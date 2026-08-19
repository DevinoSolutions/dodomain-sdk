// @dodomain/core — the protocol engine (ported from the proven POC).
// Domain Connect: discovery → template-support → signed apply-URL → verify.
// Cloudflare OAuth: PKCE authorize → token exchange → DNS write → verify → delete.

export * from "./types.ts";
export * from "./discovery.ts";
export * from "./applyUrl.ts";
export * from "./sign.ts";
export * from "./recipes.ts";
export { verifyRecord, verifyRecords } from "./verify.ts";
export * from "./detect.ts";
// The ONE apex/eTLD+1 util (F-011). check-apex-bans.sh guards re-DECLARATIONS,
// not this re-export. NOTE: "which zone owns these records" is NOT this — it is
// `nearestZoneCut` below, which merely FLOORS at the apex. Reaching for apexOf
// to pick nameservers, a discovery target, or a template's zone is the bug
// fixed three times over in 2026-08 (detect, the apply pre-flight, verify).
export { apexOf } from "./apex.ts";
// Which zone OWNS a host's records (the nearest delegation cut, floored at the
// apex). Exported because apps/web must know the zone BEFORE it discovers on
// it — the pre-flight recipe gate runs in between (zone-walk.ts's header).
export { nearestZoneCut, type ZoneCut, type ZoneWalkDeps } from "./zone-walk.ts";
export * from "./guides.ts";
export * from "./records.ts";
export * from "./webhook.ts";
// F-008: the session-payload/webhook-event schemas (schemas.ts) and the
// widget<->hosted-flow postMessage contract (messages.ts) — the two new
// boundary-schema homes this fix adds alongside records.ts.
export * from "./schemas.ts";
export * from "./messages.ts";
// Integrator branding: the brand-color contrast clamp for end-user surfaces
// (branding.ts is zero-import/zod-free — also exposed as
// "@dodomain/core/branding" for bundle-sensitive consumers).
export * from "./branding.ts";

// Cloudflare OAuth connector (Tier 1)
export * as cloudflareConfig from "./cloudflare/config.ts";
export * from "./cloudflare/oauth.ts";
export * from "./cloudflare/dns.ts";
// F-002: the DI apply orchestrator (write-then-verify every requested record —
// no WRITABLE subset filter). Capability symbols already flow via ./records.ts.
export * from "./cloudflare/apply.ts";
