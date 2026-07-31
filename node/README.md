# @dodomain/node

Server-side SDK for [DoDomain](https://dodomain.io). A thin, typed client over the DoDomain
REST API — the integrator's backend uses it to mint **connect sessions**, which the browser
[`@dodomain/connect`](../connect) widget then drives.

> Uses your **secret key** (`dd_sk_…`). Keep it on the server. Never ship it to the browser.

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

### Verifying webhooks

```ts
import { verifyWebhook } from "@dodomain/node";

// req.headers["x-dodomain-signature"] is `t=<unixMs>,v1=<hex hmac>`
const ok = verifyWebhook(process.env.DODOMAIN_WEBHOOK_SECRET!, rawBody, signatureHeader);
```

This is the only package an integrator needs for both minting sessions and verifying
webhooks.

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

### `verifyWebhook(secret, body, header, toleranceMs?, nowMs?) → boolean`

Verifies the `t=<unixMs>,v1=<hex hmac>` signature DoDomain sends with every webhook delivery.

## Types

`DnsRecordType` = `"A" | "AAAA" | "CNAME" | "TXT" | "MX"`.
`DnsRecord` = `{ type, host, value, priority?, ttl? }`.

See [`src/index.ts`](src/index.ts) for the full surface.
