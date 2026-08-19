// The ONE record-type home (F-002). Every record-type gate — the toExpectedRecords
// verify filter (records.ts), the Cloudflare tier-1 write path
// (cloudflare/dns.ts via cloudflare/apply.ts), the session-creation capability
// guard (apps/web sessions/route.ts), and later F-008's zod enum + F-014's tier
// router — imports from this file. No second hardcoded DNS record-type list may
// exist outside this file (enforced by scripts/check-record-capabilities-bans.sh,
// riding U3's CI-grep backbone).
//
// Before this file, three independently-hardcoded type lists had drifted: the
// session zod schema accepted 5 types, the verify-side filter accepted the same
// 5, but the Cloudflare write path only wrote 3 — so a session containing MX/AAAA
// could finalize as "connected" while those records were never written (F-002).
// Collapsing the lists into one source makes that drift structurally impossible:
// accepted === writable === verifiable by construction.
//
// Pure data: no `node:` imports — client-safe, so it flows through the
// `@dodomain/core/records` subpath into client components.

/** Every DNS record type a DoDomain connect session may request. */
export const RECORD_TYPES = ["A", "AAAA", "CNAME", "TXT", "MX"] as const;

export type RecordType = (typeof RECORD_TYPES)[number];

/** True when `type` is one of the accepted DoDomain record types. */
export function isRecordType(type: string): type is RecordType {
  return (RECORD_TYPES as readonly string[]).includes(type);
}

/**
 * Record types the Cloudflare-OAuth tier-1 connector can write. F-002 (R8):
 * tier-1 writable is the full accepted set — Cloudflare's DNS API writes all
 * five; the prior {CNAME,TXT,A} subset was the defect, not a Cloudflare limit.
 * accepted === writable today (both derive from RECORD_TYPES); kept as its own
 * binding (not a re-export of RECORD_TYPES) because the two concepts may
 * diverge once F-014 adds tier-2/guided types to the accepted set.
 */
export const TIER1_WRITABLE_TYPES: readonly RecordType[] = [...RECORD_TYPES];

/** True when `type` is writable by the tier-1 (Cloudflare OAuth) connector. */
export function isTier1Writable(type: string): type is RecordType {
  return (TIER1_WRITABLE_TYPES as readonly string[]).includes(type);
}

/** MX is the only type that carries an RFC 5321-required numeric preference. */
export function requiresPriority(type: RecordType): boolean {
  return type === "MX";
}

/**
 * True when a name may hold MULTIPLE records of this type with UNRELATED values,
 * such that DoDomain adding its own record beside pre-existing ones is the
 * correct, non-destructive behavior.
 *
 * Only TXT qualifies: a TXT name is a bag of independent tokens (SPF,
 * google-site-verification, ownership proofs like ours) that coexist by design —
 * an apex almost always ALREADY has TXT records, so "a different-valued record
 * exists ⇒ don't write ours" (the pre-fix apply gate) made apex verification
 * tokens permanently unwritable. The others stay conflict-and-report:
 *   - CNAME: singleton by RFC — a second CNAME at a name is illegal.
 *   - A/AAAA: additive records mean round-robin — traffic would split between
 *     the pre-existing value and ours, which is never what a connect intends.
 *   - MX: an additional exchange changes live mail routing.
 *
 * Consumed by the tier-1 apply orchestrator (cloudflare/apply.ts) to decide
 * whether a present-but-value-mismatched name still gets our record created.
 */
export function allowsCoexistingValues(type: string): boolean {
  return type === "TXT";
}

/**
 * True when a record's ACTUAL value equals its EXPECTED value, under the ONE set
 * of normalization rules DoDomain uses everywhere a record value is compared.
 * The DNS verifier (verify.ts `matches`) and the tier-1 Cloudflare apply path
 * (cloudflare/dns.ts `verifyRecordViaApi`) both call this, so the two can never
 * drift — D-001: tier-1 apply used to finalize on record PRESENCE, ignoring the
 * value, so a pre-existing record with the wrong value read as "connected".
 *
 * Semantics (ported verbatim from verify.ts's pre-D-001 `matches`):
 *   - TXT: exact, case-sensitive, no normalization — a DoDomain TXT record is a
 *     verification token (e.g. "dodomain-verify=…") where case is significant; a
 *     case-folded or substring match would weaken the ownership proof.
 *   - MX: the mail exchange is host-like (see below), AND — when the caller knows
 *     the expected preference — the numeric priority must also match (a record
 *     applied with the wrong preference must not "match"). With no expected
 *     priority (legacy sessions predating the F-002 creation guard) the exchange
 *     alone is compared.
 *   - A / AAAA / CNAME (and any other type): host-like — trailing dot stripped
 *     and lower-cased on both sides, then compared exactly. (Harmless on IPs: no
 *     trailing dot; IPv6 hex is correctly case-folded.)
 *
 * Pure/framework-free (no `node:` imports) — client-safe, like the rest of this
 * file. `actual`/`expected` are the record's value only (for MX, the exchange);
 * the MX preference travels in `opts`, never embedded in the value string.
 */
export function recordValueMatches(
  type: string,
  expected: string,
  actual: string,
  opts: { expectedPriority?: number; actualPriority?: number } = {},
): boolean {
  // TXT is a verification token: exact, case-sensitive, no normalization.
  if (type === "TXT") return actual === expected;

  const norm = (s: string) => s.replace(/\.$/, "").toLowerCase();
  const valueMatches = norm(actual) === norm(expected);

  if (type === "MX") {
    // No expected preference known → compare the exchange alone (legacy).
    if (opts.expectedPriority === undefined) return valueMatches;
    return valueMatches && opts.actualPriority === opts.expectedPriority;
  }

  return valueMatches;
}
