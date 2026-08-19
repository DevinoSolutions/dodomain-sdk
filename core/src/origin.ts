// The single canonical public origin for the DoDomain hosted app (F-010) —
// the production home for BOTH the REST API (`/api/v1/*`) and the hosted
// connect flow (`/connect/:token`). See root README.md's "Origins" section
// for the topology: `api.dodomain.io` / `connect.dodomain.io` are cosmetic
// subdomain names for this same apps/web deployment, not separate hosts,
// until ops splits them onto distinct deployments.
//
// Zero imports, framework-free — the one literal both the node SDK
// (packages/node) and the embeddable widget (packages/connect) default to,
// so a shipped SDK and a shipped widget can never re-diverge on the prod
// origin the way they did before this fix (node defaulted to the unregistered
// `api.dodomain.io`; connect defaulted to the unregistered `connect.dodomain.io`
// — neither actually resolves, so the widget's iframe would 404 with zero
// error surface). apps/web's own `env.ts` `APP_ORIGIN` stays a REQUIRED,
// no-default env var by design (F-015, fail-closed) — this constant is a
// client-facing SDK/widget default only, never an env fallback.
export const DODOMAIN_DEFAULT_ORIGIN = "https://app.dodomain.io";
