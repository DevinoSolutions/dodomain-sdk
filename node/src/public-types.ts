// The SDK's PUBLISHED type surface — plain TypeScript, zero imports.
//
// Why this file exists (the F-010 "revisit AT publish time" item, discharged
// at publish 2026-07-31): tsup's rollup-dts pass keeps bare
// `from "@dodomain/core/..."` / `from "zod"` imports in dist/index.d.ts
// (noExternal only governs the esbuild JS bundle; dts.resolve corrupts zod's
// types — full history in tsup.config.ts). An external `npm install
// @dodomain/node` consumer cannot resolve those, so the public API is typed
// against THIS import-free module instead and the emitted d.ts is
// self-contained.
//
// F-008 (no hand-typed drift) still holds: these shapes are pinned against
// the core zod schemas by compile-time mutual-assignability assertions in
// schema-parity.check.ts — covered by `pnpm typecheck`, which prepublishOnly
// runs, so a schema change that drifts from this file fails the publish.

/** DNS record types a connect session can carry. */
export type DnsRecordType = "A" | "AAAA" | "CNAME" | "TXT" | "MX";

/** One DNS record for the end user to create (pin: core zRecord). */
export interface DnsRecord {
  type: DnsRecordType;
  host: string;
  value: string;
  /** Required by the API for MX records. */
  priority?: number;
  ttl?: number;
}

/** Body for sessions.create (pin: core zCreateSessionInput). */
export interface CreateSessionInput {
  /**
   * OAuth-token (team-scoped) callers pass this to pick the app the session
   * belongs to. Secret-key callers omit it — the key already implies the app.
   */
  appId?: string;
  domain: string;
  /** Accepted and stored for wire-compat; consumed by nothing server-side. */
  recipe?: string;
  records: DnsRecord[];
  /** Where the hosted flow offers to send the user back (http/https only). */
  returnUrl?: string;
}

/** A minted connect session (pin: core zCreateSessionResponse). */
export interface Session {
  id: string;
  token: string;
  /** ISO 8601 datetime. */
  expiresAt: string;
  connectUrl: string;
}

/**
 * Verifies a DoDomain webhook signature header over the RAW request body.
 * (pin: core verifyWebhook)
 */
export type VerifyWebhook = (
  secret: string,
  body: string,
  header: string,
  toleranceMs?: number,
  nowMs?: number,
) => boolean;
