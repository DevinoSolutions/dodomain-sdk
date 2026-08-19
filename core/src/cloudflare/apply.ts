// The tier-1 apply orchestrator (F-002 — the Critical fix).
//
// Write-then-verify every record a connect session requested, via the user's
// Cloudflare OAuth grant. Extracted out of the cf/callback route so it is
// unit-testable OFFLINE (the route runs under a live-server test harness that
// cannot mock Cloudflare's network calls in-process, and the happy path needs a
// real OAuth grant) — mirrors the DI convention `detectProvider` establishes in
// packages/core/src/detect.ts: the network-touching calls default to the real
// implementations and can be overridden so this is exercised deterministically
// with fake deps in tests.
//
// NO WRITABLE-subset filter: this iterates the ACTUAL requested records, so
// `allLive` is computed over all of them — a session containing a type
// Cloudflare can't write can never silently finalize as "connected" (the exact
// false-success class F-002 removed; see the named regression in
// test/apply.test.ts: "A live + MX/AAAA absent ⇒ allLive is false").
//
// D-001 hardened the gate further: `allLive` now requires every record's VALUE
// to MATCH (verifyRecordViaApi's `.match`, normalized via record-capabilities.ts
// recordValueMatches), not merely to be PRESENT. Presence-only finalize let a
// pre-existing record with the WRONG value read as "connected" — a money-path
// defect. Writes stay non-destructive (an existing record is never overwritten):
// for singleton-valued types (CNAME/A/AAAA/MX) a wrong-valued pre-existing
// record is left in place AND blocks finalize; for TXT — a bag of independent
// tokens by design (record-capabilities.ts allowsCoexistingValues) — our record
// is created BESIDE pre-existing unrelated ones, and the read-back matches ANY
// record's value, so an apex's SPF/site-verification records never block an
// ownership token. See the "D-001" and "TXT coexistence" regressions in
// test/apply.test.ts.

import { fqdnFor, type SessionRecord } from "../records.ts";
import {
  allowsCoexistingValues,
  isTier1Writable,
  recordValueMatches,
  type RecordType,
} from "../record-capabilities.ts";
import { listRecords, createRecord, verifyRecordViaApi, type DnsRecordInput } from "./dns.ts";

export interface ApplyContext {
  /** Cloudflare OAuth access token from the completed grant. */
  token: string;
  zoneId: string;
  domain: string;
}

export interface RecordApplyResult {
  type: RecordType;
  fqdn: string;
  /** False only for a type outside TIER1_WRITABLE_TYPES — defense-in-depth; the
   * session-creation guard (sessions/route.ts) should already have rejected it. */
  writable: boolean;
  /** verifyRecordViaApi's `.present` — the record EXISTS on Cloudflare (source-of-
   * truth read-back), regardless of value. TELEMETRY only: it distinguishes an
   * ABSENT record from a WRONG-VALUE one on the !allLive path (cf/callback emits
   * WRITTEN vs CONFLICT off this). It does NOT gate finalize — that is `match`. */
  present: boolean;
  /** verifyRecordViaApi's `.match` — the record exists AND its value matches what
   * the session requested (normalized per record-capabilities.ts). D-001: THIS is
   * the finalize gate; finalizing on `.present` let a pre-existing wrong-valued
   * record read as "connected". */
  match: boolean;
  /** The value Cloudflare read back when present (null when absent) — surfaced so
   * cf/callback's CONFLICT notice can name the fqdns whose live value disagrees. */
  actual: string | null;
}

export interface ApplySessionRecordsResult {
  /** True only when there is at least one requested record AND every one of them
   * VALUE-MATCHES (verifyRecordViaApi's `.match`, not merely `.present`) — an
   * empty request can never vacuously finalize, and a present-but-wrong-valued
   * record blocks finalize (D-001). */
  allLive: boolean;
  results: RecordApplyResult[];
}

/** Injectable for tests, mirroring DetectDeps (packages/core/src/detect.ts) —
 * the live Cloudflare API calls can't run in CI (no creds), so tests inject
 * fakes instead of mocking the network. */
export interface ApplySessionRecordsDeps {
  listRecords?: typeof listRecords;
  createRecord?: typeof createRecord;
  verifyRecordViaApi?: typeof verifyRecordViaApi;
}

export async function applySessionRecords(
  records: SessionRecord[],
  ctx: ApplyContext,
  deps: ApplySessionRecordsDeps = {},
): Promise<ApplySessionRecordsResult> {
  const listRecordsFn = deps.listRecords ?? listRecords;
  const createRecordFn = deps.createRecord ?? createRecord;
  const verifyRecordViaApiFn = deps.verifyRecordViaApi ?? verifyRecordViaApi;

  const results: RecordApplyResult[] = [];

  for (const rec of records) {
    const fqdn = fqdnFor(rec.host, ctx.domain);

    if (!isTier1Writable(rec.type)) {
      // Defense-in-depth only: sessions/route.ts already rejects non-writable
      // types at creation (F-002 step 6). If one somehow reaches here, mark it
      // loudly not-live instead of silently dropping it from `results` — the
      // exact bug class this fix removes.
      results.push({
        type: rec.type,
        fqdn,
        writable: false,
        present: false,
        match: false,
        actual: null,
      });
      continue;
    }

    // Idempotent AND non-destructive (D-001): an existing record is NEVER
    // overwritten. The create decision is VALUE-AWARE over the FULL record list
    // (was: `findRecordId` — presence of ANY record at type+name suppressed the
    // create, which made an apex TXT verification token unwritable whenever the
    // apex already held unrelated TXT records like SPF):
    //   - a record with OUR value already exists ⇒ nothing to create;
    //   - none matches and the name is EMPTY for this type ⇒ create;
    //   - none matches but records exist ⇒ create only for a coexistence type
    //     (TXT — a bag of independent tokens by design). For CNAME/A/AAAA/MX a
    //     differing pre-existing record is left in place and the read-back below
    //     reports match:false, which blocks finalize via the `.match` gate.
    //     (Update-on-mismatch is a deliberate NON-goal here — a pending product
    //     decision, not an adjacent-task call.)
    const existing = await listRecordsFn(ctx.token, ctx.zoneId, rec.type, fqdn);
    const alreadyMatching = existing.some((r) =>
      recordValueMatches(rec.type, rec.value, r.content, {
        expectedPriority: rec.priority,
        actualPriority: r.priority,
      }),
    );
    if (!alreadyMatching && (existing.length === 0 || allowsCoexistingValues(rec.type))) {
      const input: DnsRecordInput = {
        type: rec.type,
        name: fqdn,
        content: rec.value,
        proxied: false,
      };
      if (rec.priority !== undefined) input.priority = rec.priority;
      await createRecordFn(ctx.token, ctx.zoneId, input);
    }

    // Read back from Cloudflare (source of truth) and compare presence AND value.
    // `rec.priority` is threaded so MX matches on preference too (verifyRecordViaApi
    // computes `.match` via record-capabilities.ts recordValueMatches).
    const v = await verifyRecordViaApiFn(
      ctx.token,
      ctx.zoneId,
      rec.type,
      fqdn,
      rec.value,
      rec.priority,
    );
    results.push({
      type: rec.type,
      fqdn,
      writable: true,
      present: v.present,
      match: v.match,
      actual: v.value,
    });
  }

  // D-001: gate on `.match` (value-verified), not `.present` (mere existence).
  const allLive = results.length > 0 && results.every((r) => r.match);

  return { allLive, results };
}
