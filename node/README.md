# @dodomain/node

Custom domains for SaaS, from your server: the official Node/TypeScript SDK for
[DoDomain](https://dodomain.io). A thin, typed client over the DoDomain REST API — mint
**connect sessions** that walk your customer through a one-click Cloudflare OAuth apply, a
signed [Domain Connect](https://www.domainconnect.org/) apply where their DNS provider supports
it, or guided records everywhere else; then verify the signed webhooks DoDomain sends once the
records are live at the authoritative nameservers. The browser [`@dodomain/connect`](../connect)
widget drives the session on the front end.

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
  domain: "customer.com",
  records: [
    { type: "CNAME", host: "app", value: "cname.sendly.io" },
    // Ownership TXT: keep this name and the dodomain-verify= prefix so GoDaddy and the
    // other one-click (Domain Connect) providers can apply it; any other name falls back
    // to guided manual setup there.
    { type: "TXT", host: "_dodomain-challenge", value: "dodomain-verify=abc123" },
  ],
  returnUrl: "https://dashboard.sendly.io/domains",
});

// session.token   → hand to @dodomain/connect in the browser
// session.connectUrl → or redirect the user to the hosted flow directly
```

### Try it with no account (keyless mode)

Keyless mode is new in `@dodomain/node` 0.9.0: with an older version, use the plain-`fetch`
script in [Keyless start](https://dodomain.io/docs/getting-started#keyless-start) instead.

No account and no key yet? A keyless client gets **10 test connections** for its keyless app.
Claiming the app with a free account gives it its own secret key and moves it into your Free
allowance of **50 verified connections a month**, shared with your other Free teams; paid plans
raise that again ([pricing](https://dodomain.io/pricing)).

```ts
import { DoDomain } from "@dodomain/node";

// Reuse the same keyless app across runs: its dd_ks_ key lives in your secret store or env.
const dodomain = new DoDomain({ keyless: true, keylessKey: process.env.DODOMAIN_KEYLESS_KEY });

const session = await dodomain.sessions.create({
  // Change this to a domain whose DNS you control: a keyless call refuses a placeholder or
  // reserved domain (customer.com, YOUR-DOMAIN.example) with 400 KEYLESS_PLACEHOLDER_DOMAIN.
  domain: "YOUR-DOMAIN.example",
  records: [{ type: "CNAME", host: "app", value: "edge.yourproduct.com" }],
});
// session.connectUrl: open it, add the records, watch it verify.
// session.keyless.allowance: { limit, used, open, remaining }.

if (process.env.DODOMAIN_KEYLESS_KEY === undefined && dodomain.keylessKey !== null) {
  // Returned once. Store it like a password (your secret manager, platform env vars or a
  // gitignored .env); never log it, commit it or paste it anywhere public.
  await saveSecret("DODOMAIN_KEYLESS_KEY", dodomain.keylessKey); // your own secret store
}
```

Pass `appName` on the first `sessions.create` to name the test app: DoDomain's hosted connect
page shows it next to a "Test app" chip, and it is never sent to a DNS provider until the app is
claimed (until then the app is "DoDomain test app" everywhere else).

#### Sandbox domains (no domain needed)

No domain to test with yet? Use one of the reserved **sandbox** names. A sandbox session is
simulated end to end: no DNS query, no provider call, and it is **never counted** against your
keyless allowance or any plan (it has its own rate limit). The response says `mode: "sandbox"`,
and its webhooks carry `sandbox: true`. Sandbox names work with a keyless client and with a
secret key (`@dodomain/node` 0.10.0 or later):

| Domain              | What happens                                                              |
| ------------------- | ------------------------------------------------------------------------- |
| `verified.test`     | verifies on the first check                                               |
| `pending.test`      | never verifies (stays pending until the session expires)                  |
| `slow.test`         | verifies about 20 seconds after the session was created                   |
| `wrong-record.test` | every check finds the record with a wrong value                           |
| `unsupported.test`  | detection finds no supported provider (manual records); verifies on check |

```ts
const sandbox = await dodomain.sessions.create({
  domain: "verified.test",
  records: [{ type: "CNAME", host: "app", value: "edge.yourproduct.com" }],
});
// sandbox.mode === "sandbox"
```

Only these exact lowercase names are sandbox names. Any other `.test` name is refused with
`KEYLESS_PLACEHOLDER_DOMAIN` on a keyless client, and a lookalike (`verified.test.example.com`,
`Verified.Test`) is a normal domain.

`session.keyless.claimUrl` carries the key after its `#`. Hand it only to the person who will
claim the app (your own UI or a direct message), never in a log, a commit, an issue or a public
channel. `DoDomainError` bodies and `details` redact any `dd_ks_` key to `dd_ks_…`, so logging a
caught error does not leak it.

The first `sessions.create` calls `POST /api/v1/keyless/sessions` with no key, gets the API's
`428` proof-of-work challenge, solves it with `node:crypto` (about 1 to 3 seconds at the usual
20 bits; the API never asks for more than 24) and retries with the proof. If that retry is
refused because the network now needs a harder proof or the challenge expired while solving, it
solves the fresh challenge once more, never more. The client then keeps the returned `dd_ks_`
key, so later calls need no proof. To keep using the same keyless app
from another process, pass the key back: `new DoDomain({ keyless: true, keylessKey })`.

Keyless mode is an explicit opt-in: `new DoDomain({ secretKey: undefined })` still throws, so an
unset environment variable never turns a production client into a test app. A keyless client
can only create sessions and read `dodomain.keyless.status()`; every other call throws
`DoDomainKeylessError` with `code: "KEYLESS_MODE"` until you claim the app and switch to its
`dd_sk_` key. Keyless refusals from the API (`KEYLESS_LIMIT_REACHED`, `KEYLESS_START_RATE_LIMITED`,
`KEYLESS_CAPACITY_REACHED`, `KEYLESS_PLACEHOLDER_DOMAIN`, …) throw `DoDomainKeylessError` too, with the refusal's `details`
(the limit and the link that unlocks more). Full rules:
[dodomain.io/docs/getting-started#keyless-start](https://dodomain.io/docs/getting-started#keyless-start).

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
check.oneClickAvailable; // false on tier 2 when the provider serves none of our templates (e.g. IONOS); true for Porkbun at tier 3
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

| Option           | Type           | Notes                                                                                                         |
| ---------------- | -------------- | ------------------------------------------------------------------------------------------------------------- |
| `secretKey`      | `string`       | Required unless `keyless: true`. Must start with `dd_sk_`.                                                    |
| `keyless`        | `true`         | Keyless mode: no account, no key ([above](#try-it-with-no-account-keyless-mode)).                             |
| `keylessKey`     | `string`       | Keyless mode only: a `dd_ks_` key from an earlier keyless start, to reuse that app.                           |
| `proofTimeoutMs` | `number`       | Keyless mode only: the most one proof-of-work solve may take, above 0 and at most `300000`. Default `120000`. |
| `baseUrl`        | `string`       | API base. Defaults to `https://app.dodomain.io` (self-hosted/custom deployments override this).               |
| `fetchImpl`      | `typeof fetch` | Override the fetch used (tests, custom agents).                                                               |

### `dodomain.sessions.create(input) → Promise<ConnectSessionSummary>`

`input`: `{ domain, records, returnUrl?, recipe? }` — `domain` (two or more DNS labels, no
scheme/port/trailing dot) and `records` are both required; `returnUrl` must be http(s).
`recipe` is accepted for wire compatibility but is consumed by nothing today and does not
substitute for `records`. Returns `{ id, token, expiresAt, connectUrl, records, warnings? }`.
The return type was named `Session` before 0.5.0; that alias is still exported, marked
`@deprecated`, and will be removed in the next major — import `ConnectSessionSummary`.

Errors throw `DoDomainError` with `.status` and `.body`. A malformed (non-JSON) or
schema-invalid response also throws `DoDomainError` — never a raw platform error. An API
refusal's `.message` is its machine error followed by the API's own explanation (since 0.9.2),
and `.error` / `.code` carry the machine values, so branch on those, not on the message:

```ts
import { DoDomainError, DoDomainKeylessError } from "@dodomain/node";

try {
  await dodomain.sessions.create({ domain: "customer.com", records });
} catch (e) {
  if (e instanceof DoDomainKeylessError) {
    // e.message: 'invalid_request: "customer.com" is a placeholder or reserved name, ...'
    // e.code: "KEYLESS_PLACEHOLDER_DOMAIN"; on a 402, e.details?.retryAt says when to retry.
    console.error(e.message, e.code, e.details?.retryAt);
  } else if (e instanceof DoDomainError) {
    console.error(e.message, e.error, e.code, e.status);
  }
}
```

On a keyless client the same call goes to `POST /api/v1/keyless/sessions` (no `appId`: the
keyless key is its app), and the result also carries `keyless: { key?, appId, allowance,
claimUrl, unlock, docs }`. An optional second argument `{ signal }` aborts the request and, in
keyless mode, the proof-of-work search.

### `dodomain.keyless.status() → Promise<KeylessStatus>`

Keyless mode only: `GET /api/v1/keyless`, the keyless app's `{ appId, allowance, claimUrl,
unlock, docs, createdAt, lastUsedAt }`. Throws `DoDomainKeylessError` with
`code: "KEYLESS_KEY_MISSING"` (and `status: 0`) before the client holds a `dd_ks_` key.

### `solveKeylessProof(challenge, difficultyBits, { signal?, timeoutMs? }) → Promise<string>`

The solver keyless mode uses, exported for callers that drive the REST API themselves. Resolves
with the full header value `<challenge>:<nonce>` for the `DoDomain-Keyless-Proof` header.
Rejects with `DoDomainKeylessError` (`KEYLESS_PROOF_UNSUPPORTED` above 24 bits,
`KEYLESS_PROOF_ABORTED`, `KEYLESS_PROOF_TIMEOUT`).

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

`input`: `{ domain }`. Stateless pre-flight — provider, owning zone, connect tier and flow, whether one-click is
actually available there (`oneClickAvailable`: `tier: 2` alone only means the provider speaks
Domain Connect), and the manual guide — without creating a session. Nothing is persisted; available on every plan.

### `dodomain.webhookEndpoints.list() → Promise<ListWebhookEndpointsResult>`

This app's delivery targets. **Never** returns `secret` — no read surface does.

### `dodomain.webhookEndpoints.create(input) → Promise<WebhookEndpointWithSecret>`

`input`: `{ url }` (https, not a localhost/private address, not a duplicate — each refusal throws
`.status === 400` with the reason in `.body.message`; the plan cap throws `.status === 402`).
**The returned `secret` is shown once** and appears in no read surface again — persist it in this
same code path.

### `dodomain.webhookEndpoints.update(endpointId, input) → Promise<WebhookEndpoint>`

Repoints an endpoint at a new `url`. The signing secret is deliberately untouched, so moving
hosts never forces your receiver to re-key. A `url` that actually changes also resumes an
auto-paused endpoint.

### `dodomain.webhookEndpoints.resume(endpointId) → Promise<WebhookEndpoint>`

Resumes an endpoint DoDomain paused automatically — one that had no successful delivery for 7 days
and at least 5 dead-lettered deliveries in that span (`pausedAt` is set while it is paused). Clears
`pausedAt` and restarts the 7-day clock; idempotent on an endpoint that is not paused. Events that
happened while it was paused were recorded as skipped deliveries and are not resent by this call —
redrive them from the dashboard.

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

`DnsRecordType` = `"A" | "AAAA" | "CNAME" | "TXT" | "MX" | "SRV" | "CAA" | "NS"` (NS below the zone apex only).
`DnsRecord` = `{ type, host, value, priority?, ttl?, weight?, port?, flags?, tag? }`: MX needs `priority`; SRV needs `priority`, `weight`, `port` (its `value` is the target host); CAA needs `flags` and `tag` (`issue` | `issuewild` | `iodef`; its `value` is the property value).
`Connection` = `{ id, appId, sessionId, domain, fqdn, recordFqdns, status, verifiedAt, lastCheckedAt, brokenAt, disconnectedAt, createdAt }`.
`IntegratorSession` = `{ id, appId, domain, records, recipe, status, tier, detectedProvider, connectionId, createdAt, expiresAt, expired }`.
`WebhookEndpoint` = `{ id, appId, url, createdAt, pausedAt }`; `WebhookEndpointWithSecret` adds the
show-once `secret`.
`RotateSecretKeyResult` = `{ appId, publicKey, secretKey, rotatedAt }`.
`WebhookEvent` = `{ id, type, occurredAt, data }` — the envelope DoDomain delivers.
`WebhookEventWire` = `WebhookEvent` plus the deprecated `event` alias of `type`, for receivers
written against the pre-2026-08-06 body.

See [`src/index.ts`](src/index.ts) for the full surface.
