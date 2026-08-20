# @dodomain/node

Server-side SDK for [DoDomain](https://dodomain.io). A thin, typed client over the DoDomain
REST API — the integrator's backend uses it to mint **connect sessions**, which the browser
[`@dodomain/connect`](../connect) widget then drives.

> Uses your **secret key** (`dd_sk_…`). Keep it on the server. Never ship it to the browser.

📖 **Guide with runnable examples: [dodomain.io/docs/node-sdk](https://dodomain.io/docs/node-sdk)**
· all docs: [dodomain.io/docs](https://dodomain.io/docs).

## Install

```sh
npm install @dodomain/node
# or: pnpm add @dodomain/node · yarn add @dodomain/node
```

Zero runtime dependencies — the build inlines everything (dual ESM+CJS + self-contained
`.d.ts`). Node 20+.

## Usage

```ts
import { DoDomain } from "@dodomain/node";

const dodomain = new DoDomain({ secretKey: process.env.DODOMAIN_SECRET_KEY! });

const session = await dodomain.sessions.create({
  domain: "app.customer.com",
  records: [
    { type: "CNAME", host: "app", value: "cname.sendly.io" },
    { type: "TXT", host: "_verify", value: "sendly-domain-abc123" },
  ],
  returnUrl: "https://dashboard.sendly.io/domains",
});

// session.token   → hand to @dodomain/connect in the browser
// session.connectUrl → or redirect the user to the hosted flow directly
```

### Managing connections

```ts
// One page of live connections, newest first.
const { connections, nextCursor } = await dodomain.connections.list({ limit: 50 });

// Walk every page (nextCursor is null on the last one).
let cursor: string | undefined;
do {
  const page = await dodomain.connections.list({ cursor, limit: 100 });
  cursor = page.nextCursor ?? undefined;
} while (cursor);

// Read ONE — the id every connection.* webhook payload carries.
const connection = await dodomain.connections.get(connectionId);
connection.status; // "active" | "broken"

// Queue an on-demand DNS recheck; the verdict arrives as a webhook.
await dodomain.connections.reverify(connectionId);

// The customer removed their domain from your product — stop the monitoring
// (idempotent; a repeat reports alreadyDisconnected).
const { disconnectedAt, alreadyDisconnected } = await dodomain.connections.delete(connectionId);
```

### Reading a session back

```ts
// Sessions are addressable by the id every webhook payload carries — the token
// never appears in one. This is how a session.abandoned receiver asks what
// actually happened.
const session = await dodomain.sessions.get(event.data.sessionId as string);

session.expired; // derived at read — do NOT infer expiry from session.status
session.connectionId; // non-null once the session finalized
session.records; // the composed fqdns DoDomain verifies, not the raw echo
```

### Pre-flighting a domain

```ts
// Which provider, which zone, which connect flow — without creating a session.
const check = await dodomain.domains.check({ domain: "app.customer.com" });
check.tier; // 1 = Cloudflare one-click · 2 = Domain Connect · 3 = manual
check.guide.steps; // what to tell the user if it comes to manual records
```

### Managing webhook endpoints

```ts
// Register a delivery target. The secret is returned ONCE — store it here.
const endpoint = await dodomain.webhookEndpoints.create({
  url: "https://hooks.sendly.io/dodomain",
});
await saveWebhookSecret(endpoint.secret); // whsec_… — feed to verifyWebhook

const { endpoints } = await dodomain.webhookEndpoints.list(); // never carries secrets
await dodomain.webhookEndpoints.update(endpoint.id, { url: "https://hooks2.sendly.io/dodomain" });

// Rotation cuts over IMMEDIATELY — deploy the new secret before you rotate.
const rekeyed = await dodomain.webhookEndpoints.rotateSecret(endpoint.id);
await dodomain.webhookEndpoints.delete(endpoint.id);
```

### Rotating your secret key

```ts
// The calling key replaces itself. By DEFAULT there is NO overlap window: the
// old key stops working the instant this returns, and this is the only copy of
// the new one — persist it before doing anything else.
const rotated = await dodomain.keys.rotate();
await saveSecretKey(rotated.secretKey); // dd_sk_…
const next = new DoDomain({ secretKey: rotated.secretKey }); // this client still holds the old key

// Opt-in zero-downtime rotation: both keys work until previousKeyExpiresAt
// (1 or 24 hours). Exactly ONE previous key is kept — rotating again replaces
// it (killing key n-1 instantly), and rotating with the default overlapHours: 0
// ends a live window early: for a leaked key, rotation IS the revoke.
const overlapped = await dodomain.keys.rotate({ overlapHours: 1 });
await saveSecretKey(overlapped.secretKey);
console.log(`old key dies at ${overlapped.previousKeyExpiresAt}`);
```

### Verifying webhooks

```ts
import { verifyWebhook } from "@dodomain/node";
import type { WebhookEvent } from "@dodomain/node";

// req.headers["x-dodomain-signature"] is `t=<unixMs>,v1=<hex hmac>`
const ok = verifyWebhook(process.env.DODOMAIN_WEBHOOK_SECRET!, rawBody, signatureHeader);
if (!ok) return new Response("bad signature", { status: 400 });

const event = JSON.parse(rawBody) as WebhookEvent; // { id, type, occurredAt, data }
// Dedupe on event.id (retries reuse it); branch on event.type.
```

This is the only package an integrator needs: it covers the whole `/api/v1` integrator surface —
sessions, connections, apps, the domain pre-flight, webhook-endpoint lifecycle and key rotation —
plus webhook signature verification.

> The remaining `/api/v1` routes (`detect`, `verify`, and the Cloudflare / Domain Connect
> one-click entry points) are **browser** surfaces: they are authenticated by the session token in
> the URL rather than by your secret key, and the hosted flow and `@dodomain/connect` widget drive
> them. They are deliberately absent from this server SDK.

## API

### `new DoDomain(options)`

| Option      | Type           | Notes                                                                                           |
| ----------- | -------------- | ----------------------------------------------------------------------------------------------- |
| `secretKey` | `string`       | Required. Must start with `dd_sk_`.                                                             |
| `baseUrl`   | `string`       | API base. Defaults to `https://app.dodomain.io` (self-hosted/custom deployments override this). |
| `fetchImpl` | `typeof fetch` | Override the fetch used (tests, custom agents).                                                 |

### `dodomain.sessions.create(input) → Promise<Session>`

`input`: `{ domain, records, returnUrl?, recipe? }` — `domain` (two or more DNS labels, no
scheme/port/trailing dot) and `records` are both required; `returnUrl` must be http(s).
`recipe` is accepted for wire compatibility but is consumed by nothing today and does not
substitute for `records`. Returns `{ id, token, expiresAt, connectUrl }`.

Errors throw `DoDomainError` with `.status` and `.body`. A malformed (non-JSON) or
schema-invalid response also throws `DoDomainError` — never a raw platform error.

### `dodomain.connections.list(filters?) → Promise<ListConnectionsResult>`

`filters`: `{ appId?, domain?, limit?, cursor?, includeDisconnected? }` — all optional, and only
the ones you pass go on the wire (the server owns the defaults: `limit` 50, max 100;
disconnected connections hidden). Returns `{ connections, nextCursor }`, newest first; pass
`nextCursor` back as `cursor` for the next page, and stop when it is `null`.

### `dodomain.connections.get(connectionId) → Promise<Connection>`

Reads one connection — including one you already disconnected. Same object shape as an element
of `list`. Unknown and not-yours both throw `DoDomainError` with `.status === 404`.

### `dodomain.connections.delete(connectionId) → Promise<DisconnectConnectionResult>`

Disconnects: archives the connection and stops its DNS monitoring, so a domain your customer
removed stops firing drift webhooks. Idempotent — a repeat returns the original
`disconnectedAt` with `alreadyDisconnected: true` and emits no second webhook.

### `dodomain.connections.reverify(connectionId) → Promise<ReverifyConnectionResult>`

Queues an on-demand DNS recheck. Resolves once the job is **accepted** (HTTP 202); the verdict
arrives as a `connection.verified` / `connection.failed` webhook. A connection checked within
the last 10 minutes throws `DoDomainError` with `.status === 429`.

### `dodomain.sessions.get(sessionId) → Promise<IntegratorSession>`

Reads a session **by id** — the `sessionId` every webhook payload carries (the token appears in
none of them). Unlike the public token route it returns an **expired** session rather than
refusing it: read the `expired` flag, which is derived at read time and is therefore already true
before the reaper rewrites `status`. Passing a `dd_sess_…` token throws `DoDomainError` with
`.status === 0` — that token addresses the same path's public arm, which answers with a different
shape. Unknown and not-yours both throw `.status === 404`.

### `dodomain.apps.list() → Promise<ListAppsResult>`

The apps this credential can see. A secret key sees exactly its own app; an OAuth token with
`apps:read` sees the whole team. Only the publishable `pk_*` key is ever returned.

### `dodomain.domains.check(input) → Promise<CheckDomainResult>`

`input`: `{ domain }`. Stateless pre-flight — provider, owning zone, connect tier and flow, and
the manual guide — without creating a session. Nothing is persisted; available on every plan.

### `dodomain.webhookEndpoints.list() → Promise<ListWebhookEndpointsResult>`

This app's delivery targets. **Never** returns `secret` — no read surface does.

### `dodomain.webhookEndpoints.create(input) → Promise<WebhookEndpointWithSecret>`

`input`: `{ url }` (https, not a localhost/private address, not a duplicate — each refusal throws
`.status === 400` with the reason in `.body.message`; the plan cap throws `.status === 402`).
**The returned `secret` is shown once** and appears in no read surface again — persist it in this
same code path.

### `dodomain.webhookEndpoints.update(endpointId, input) → Promise<WebhookEndpoint>`

Repoints an endpoint at a new `url`. The signing secret is deliberately untouched, so moving
hosts never forces your receiver to re-key.

### `dodomain.webhookEndpoints.delete(endpointId) → Promise<DeleteWebhookEndpointResult>`

Stops delivering to the endpoint. Past delivery rows survive as evidence, but a failed delivery
to a deleted endpoint can no longer be redriven.

### `dodomain.webhookEndpoints.rotateSecret(endpointId) → Promise<WebhookEndpointWithSecret>`

Mints a new signing secret and returns it **once**. **Immediate cutover, no dual-secret window** —
the worker reads the secret live at delivery time, so signatures switch at once, retries of older
deliveries included. Deploy the new secret to your receiver promptly.

### `dodomain.keys.rotate() → Promise<RotateSecretKeyResult>`

The calling app's secret key rotates itself — the automatable half of credential rotation.
**No grace window:** the old key stops authenticating the instant this returns, and the returned
`secretKey` is the only copy of the new one. Persist it, then build a new `DoDomain` with it — the
client you called this on still holds the old key. `publicKey` is echoed unchanged so a CI job can
assert it rewrote the right app. There is deliberately no create/list/revoke of other keys.

### `verifyWebhook(secret, body, header, toleranceMs?, nowMs?) → boolean`

Verifies the `t=<unixMs>,v1=<hex hmac>` signature DoDomain sends with every webhook delivery.

## Types

`DnsRecordType` = `"A" | "AAAA" | "CNAME" | "TXT" | "MX"`.
`DnsRecord` = `{ type, host, value, priority?, ttl? }`.
`Connection` = `{ id, appId, sessionId, domain, fqdn, recordFqdns, status, verifiedAt, lastCheckedAt, brokenAt, disconnectedAt, createdAt }`.
`IntegratorSession` = `{ id, appId, domain, records, recipe, status, tier, detectedProvider, connectionId, createdAt, expiresAt, expired }`.
`WebhookEndpoint` = `{ id, appId, url, createdAt }`; `WebhookEndpointWithSecret` adds the
show-once `secret`.
`RotateSecretKeyResult` = `{ appId, publicKey, secretKey, rotatedAt }`.
`WebhookEvent` = `{ id, type, occurredAt, data }` — the envelope DoDomain delivers.
`WebhookEventWire` = `WebhookEvent` plus the deprecated `event` alias of `type`, for receivers
written against the pre-2026-08-06 body.

See [`src/index.ts`](src/index.ts) for the full surface.
