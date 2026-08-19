# @dodomain/core

The DoDomain protocol engine — ported from the proven POC (see
`docs/archive/2026-06-plan-v1/domain-connect-poc.md` (in the private DoDomain monorepo);
original POC code preserved in git history at commit `d70302b`).
Internal package (consumed by `apps/web`); not published on its own.

## What's in here

| Module                    | Responsibility                                                                                                                              |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `detect.ts`               | Provider detection — NS-pattern map + Domain Connect discovery → `ProviderMatch { provider, label, tier, method, confidence, nameServers }` |
| `discovery.ts`            | Domain Connect discovery → settings → template-support probe                                                                                |
| `applyUrl.ts` / `sign.ts` | Build + sign the Domain Connect apply URL (synced/async flows)                                                                              |
| `cloudflare/`             | Cloudflare OAuth (Tier 1): PKCE authorize → token exchange → DNS write → verify → delete                                                    |
| `verify.ts`               | Verify a record against the domain's **authoritative** nameservers (A/AAAA/CNAME/TXT/MX)                                                    |
| `guides.ts`               | Per-provider guided-manual instructions — DNS deep link, host format, steps (top-5 + generic)                                               |
| `records.ts`              | `fqdnFor`, `toExpectedRecords`, session record shapes (client-safe subpath)                                                                 |
| `webhook.ts`              | `signWebhook` / `verifyWebhook` — HMAC-SHA256, Stripe-style `t=<ms>,v1=<hex>`, replay-tolerant                                              |

## Subpath exports

`.` pulls in `node:` builtins (dns, crypto) — server only. Client code imports the
node-free subpaths instead:

```ts
import { toExpectedRecords, fqdnFor } from "@dodomain/core/records";
import { verifyWebhook } from "@dodomain/core/webhook";
import { cloudflareConfig } from "@dodomain/core/cloudflare";
```

## Test

```bash
pnpm --filter @dodomain/core test   # node --experimental-strip-types --test
```

The three-tier model (Cloudflare OAuth → Domain Connect → guided-manual) and the verification
approach are documented in `PLAN.md` (in the private DoDomain monorepo).
