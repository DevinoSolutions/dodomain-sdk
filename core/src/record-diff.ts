// The ONE "why didn't this record match?" classifier.
//
// verify.ts already answers WHETHER an expected record is present, and already
// carries the raw answers it saw in VerificationResult.authoritativeFound /
// publicFound — but every surface threw those away, so a user who pasted the
// value into the wrong field, kept the provider's auto-appended trailing dot, or
// typed the right MX exchange at the wrong preference was told only "not found
// yet". They then waited for propagation that was never coming. This file turns
// the answers verify already has into the reason the match failed.
//
// It is a PURE classifier over data verify already returned: it performs no DNS
// lookup and never changes what counts as verified. `reason: "match"` is exactly
// the case verify would call present, by construction — every comparison here
// goes through record-capabilities.ts's `recordAnswerMatches`, the same matcher
// verify.ts's own `matches` uses, so this file can never claim a mismatch the
// verifier would have accepted (or the reverse).
//
// Pure/framework-free (no `node:` imports) like record-capabilities.ts, so it
// flows through the `@dodomain/core/records` client-safe subpath into the
// connect flow's client components.

import { emailPolicyKindOf } from "./email-records.ts";
import {
  allowsCoexistingValues,
  parseMxAnswer,
  recordAnswerMatches,
  recordValueMatches,
} from "./record-capabilities.ts";
import type { ExpectedRecord } from "./verify-types.ts";

/**
 * Why an expected record did not match what DNS actually returned.
 *
 * The four "near miss" reasons are the ones worth naming to a user, because each
 * has a different fix and none of them is "wait longer":
 *   - `whitespace_differs`   — the value matches once both sides are trimmed. No
 *     comparison in the product trims (see `recordValueMatches`), so a stray
 *     leading/trailing space genuinely breaks verification on EVERY type.
 *   - `trailing_dot_differs` — matches once a trailing dot is stripped. Only
 *     reachable on TXT: the host-like types already normalize the dot away, so
 *     for them this is folded into `match` before it can be reported.
 *   - `case_differs`         — matches once both sides are lower-cased. Also TXT
 *     only, and the highest-value hint of the four: TXT is compared
 *     case-sensitively on purpose (it carries ownership tokens), so a provider
 *     UI that helpfully lower-cased the value produces a record that looks
 *     correct to the human eye and never verifies.
 *   - `mx_priority_differs`  — the mail exchange is right, the preference isn't.
 *
 * `spf_terms_missing` is the email-authentication verdict: the zone ALREADY has
 * an SPF record and it lacks the mechanism the session asked for. Named apart
 * from `different_value` because its fix is the opposite of the usual one — the
 * user must edit the existing record, never add ours beside it (a second
 * `v=spf1` TXT is a PermError that fails every sender, RFC 7208 §3.2), and
 * "waiting" would never merge it.
 *
 * `different_value` is the honest fallback: something IS published at this name
 * and it is simply not what we asked for. It is unreachable for types that allow
 * coexisting values (see `diffExpectedRecord`), because for those "something
 * else is here" carries no information — with ONE exception: a DKIM key or
 * DMARC policy TXT, where a published record of the SAME policy kind is exactly
 * a different value (one `_dmarc` policy per name, one key per selector).
 *
 * `nothing_published` means OUR record isn't there — the ordinary "hasn't been
 * added yet" case, kept distinct because it is the ONLY reason for which waiting
 * is in fact the right advice. It does not promise the name is empty; on a
 * coexisting type it is also the verdict when unrelated records are present.
 */
export type RecordDiffReason =
  | "match"
  | "nothing_published"
  | "whitespace_differs"
  | "trailing_dot_differs"
  | "case_differs"
  | "mx_priority_differs"
  | "spf_terms_missing"
  | "different_value";

export interface RecordDiff {
  reason: RecordDiffReason;
  /**
   * Every answer DNS returned for this name+type, verbatim as the resolver gave
   * it (MX entries stay `"${priority} ${exchange}"` — see `parseMxAnswer`).
   * Verbatim on purpose: the whole point is to show the user the bytes that are
   * actually published, and a prettified copy would hide the stray space or the
   * trailing dot that is the entire reason the record didn't match.
   */
  published: string[];
  /**
   * The published answer this verdict is ABOUT — the near miss when there is
   * one, otherwise the first published answer.
   *
   * Absent on exactly the reasons with no answer worth pointing at: `match`
   * (nothing to explain) and `nothing_published` (our record isn't there).
   * Note that `nothing_published` does NOT imply an empty `published`: on a type
   * that allows coexisting values it also covers "other, unrelated records live
   * at this name and ours is not among them", so `published` may list an SPF
   * record while `closest` is absent — pointing at one would invite the UI to
   * render somebody else's TXT as though it were our failed record.
   */
  closest?: string;
}

/**
 * The near-miss ladder, in MINIMAL-FIRST order.
 *
 * Each rung's normalization is a superset of the one above it, so the first rung
 * that matches is the smallest relaxation that explains the failure, and its
 * label names the thing that rung ADDED. Cumulative rather than one-at-a-time
 * because real answers arrive with more than one defect at once: a value that is
 * both padded with spaces and lower-cased is not explained by trimming alone nor
 * by case-folding alone, and reporting such an answer as `different_value` —
 * "something unrelated is published" — would be actively misleading when it is
 * the user's own value with two small blemishes.
 *
 * The consequence to be aware of when reading a verdict: `case_differs` on an
 * answer that ALSO has a trailing dot names only the case, because case is the
 * rung that finally made it match. That is the intended bias — case is the
 * substantive, invisible-to-the-eye problem, and re-entering the value fixes the
 * dot along the way.
 */
const NEAR_MISS_LADDER = [
  { reason: "whitespace_differs", relax: (s: string) => s.trim() },
  { reason: "trailing_dot_differs", relax: (s: string) => s.trim().replace(/\.$/, "") },
  {
    reason: "case_differs",
    relax: (s: string) => s.trim().replace(/\.$/, "").toLowerCase(),
  },
] as const satisfies readonly { reason: RecordDiffReason; relax: (s: string) => string }[];

/**
 * Every near-miss reason, in the order `diffExpectedRecord` reports them across
 * a multi-answer name. The MX preference check leads because it is the only rung
 * that is not a string relaxation: it asks a different question ("right host,
 * wrong number?") and a wrong-preference answer would otherwise fall through the
 * whole ladder to `different_value`.
 */
const NEAR_MISS_REASONS = [
  "mx_priority_differs",
  ...NEAR_MISS_LADDER.map((rung) => rung.reason),
] as const satisfies readonly RecordDiffReason[];

type NearMissReason = (typeof NEAR_MISS_REASONS)[number];

/**
 * The smallest relaxation under which `answer` becomes a match for `rec`, or
 * null when none does.
 *
 * Every rung re-runs the REAL matcher, so a hint is only ever produced when that
 * relaxation is genuinely what stands between the published answer and a pass. A
 * relaxation the matcher already performs (trailing dot / case, on the host-like
 * types) can't produce a hint here, because the unrelaxed comparison in
 * `diffExpectedRecord` would already have returned `match`.
 */
function nearMissReasonFor(rec: ExpectedRecord, answer: string): NearMissReason | null {
  if (rec.type === "MX" && rec.priority !== undefined) {
    const { priority, exchange } = parseMxAnswer(answer);
    // Exchange-only comparison (no expectedPriority) — the question this branch
    // asks is precisely "is the host right and the number wrong?".
    if (recordValueMatches("MX", rec.expect, exchange) && priority !== rec.priority) {
      return "mx_priority_differs";
    }
  }

  for (const { reason, relax } of NEAR_MISS_LADDER) {
    if (recordAnswerMatches(rec.type, relax(rec.expect), relax(answer), rec.priority)) {
      return reason;
    }
  }
  return null;
}

/**
 * Classify what DNS returned for one expected record.
 *
 * `found` is a VerificationResult's `authoritativeFound` (or `publicFound`) — the
 * raw answers for this record's name and type. Pass the authoritative set: it is
 * the one `present` is decided from, so a diff built on the public set could
 * disagree with the verdict the user is looking at.
 *
 * Callers that hold an INDETERMINATE result must not call this. `found` is empty
 * both when the nameservers said "nothing here" and when the lookup itself
 * failed, and only the first of those means `nothing_published` — the outcome
 * discriminates them (see VerificationResult.outcome) and this function
 * deliberately cannot.
 */
export function diffExpectedRecord(rec: ExpectedRecord, found: readonly string[]): RecordDiff {
  const published = [...found];
  if (published.some((f) => recordAnswerMatches(rec.type, rec.expect, f, rec.priority))) {
    return { reason: "match", published };
  }
  if (published.length === 0) {
    return { reason: "nothing_published", published };
  }

  // Scan in NEAR_MISS_REASONS order rather than answer order: with several
  // records published at one name, the most specific explanation available
  // across ALL of them is the one worth showing, regardless of which answer the
  // resolver happened to list first.
  for (const reason of NEAR_MISS_REASONS) {
    const hit = published.find((f) => nearMissReasonFor(rec, f) === reason);
    if (hit !== undefined) return { reason, published, closest: hit };
  }

  // COEXISTING TYPES NEVER REACH `different_value`.
  //
  // For a type where unrelated values legitimately share a name — TXT, and only
  // TXT (`allowsCoexistingValues`) — "something else is published here" is not
  // evidence of anything. An apex TXT almost always ALREADY holds an SPF record
  // and other vendors' ownership proofs; ours is simply meant to join them. Left
  // to fall through, that most-common-of-all apex layouts reported
  // `different_value`, and the flow then told the user "waiting won't change
  // this" while pointing at somebody else's SPF record — inverting the whole
  // purpose of this classifier on the case it will meet most often.
  //
  // The near-miss rungs above deliberately run FIRST and still apply: a TXT
  // answer that is our token with the wrong case or a stray space is a real,
  // actionable defect, and saying so is the single most valuable hint here.
  // Only the "nothing recognisable" fallback is suppressed.
  if (allowsCoexistingValues(rec.type)) {
    // The policy exception: a published record of the SAME email-policy kind
    // as the expected one is not "somebody else's TXT" — it is THE record the
    // session is about, holding a different policy. SPF gets its own verdict
    // (edit the existing record — never add a second one); a DKIM key or DMARC
    // policy that disagrees is a plain different_value, since a name holds
    // one of each.
    const policy = emailPolicyKindOf(rec.expect);
    if (policy !== null) {
      const sibling = published.find((f) => emailPolicyKindOf(f) === policy);
      if (sibling !== undefined) {
        return {
          reason: policy === "spf" ? "spf_terms_missing" : "different_value",
          published,
          closest: sibling,
        };
      }
    }
    return { reason: "nothing_published", published };
  }

  return { reason: "different_value", published, closest: published[0]! };
}
