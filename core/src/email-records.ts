// Email-authentication TXT semantics — SPF, DKIM, DMARC — the ONE place a
// policy-shaped TXT value is parsed and compared.
//
// A verification token is a string: it either is or is not published, byte
// for byte. An SPF, DKIM or DMARC record is a POLICY, and a byte comparison is
// the wrong question for it in two ways that matter to a connect session:
//
//   - SPF is MERGED. A zone may hold only one `v=spf1` record (RFC 7208 §3.2 —
//     two of them is a PermError that fails every sender), so the correct
//     outcome of "add include:_spf.integrator.com" is an EXISTING record that
//     now contains that mechanism, and Domain Connect's SPFM type exists to do
//     exactly that. Verifying it byte-exactly would fail the healthy result and
//     pass only a broken one (a second, standalone SPF record).
//   - DKIM and DMARC are tag lists (RFC 6376 §3.2, RFC 7489 §6.4): providers
//     re-space them, some drop the optional `v=DKIM1`, and DKIM keys are split
//     across TXT strings and re-joined with whitespace. All of those are the
//     same record.
//
// The rule everywhere below is "the published record SATISFIES the expected
// one": every term or tag the session asked for is present with the same
// value, extras are the zone owner's business. It never widens what counts as
// the same value — a different `p=` policy, a different key, a missing include
// are all still mismatches — and it never applies to a TXT that is not a
// policy (`emailPolicyKindOf` returns null and the exact rule stays in force).
//
// Pure/framework-free (no `node:` imports), like record-capabilities.ts — it
// rides the `@dodomain/core/records` client-safe subpath into the connect
// flow, and recipes.ts uses `parseSpfRecord` to compile the SPFM variable.

export type EmailPolicyKind = "spf" | "dkim" | "dmarc";

/**
 * Which email policy a TXT value is, judged by its version tag — or null for
 * any other TXT (ownership tokens, site verification, arbitrary text). DKIM
 * is recognised only when it spells its RECOMMENDED `v=DKIM1` tag: a bare
 * `k=rsa; p=…` is valid DKIM (RFC 6376 §3.6.1) but indistinguishable from
 * arbitrary text without it, and "unknown" must never be read as "no".
 */
export function emailPolicyKindOf(txt: string): EmailPolicyKind | null {
  const value = txt.trim();
  if (/^v=spf1(?:\s|$)/i.test(value)) return "spf";
  if (/^v=DMARC1\s*(?:;|$)/i.test(value)) return "dmarc";
  if (/^v=DKIM1\s*(?:;|$)/i.test(value)) return "dkim";
  return null;
}

// ── SPF ────────────────────────────────────────────────────────────────────

export interface SpfRecord {
  /** Every mechanism/modifier between `v=spf1` and the `all` term, verbatim. */
  terms: string[];
  /** The terminal `all` term as published (`~all`, `-all`, …), or null. */
  all: string | null;
}

/** True for the terminal `all` term in any qualifier spelling (`~all`, `-all`,
 * `all`) — the ONE place that shape is recognised, so the parser and the merge
 * below cannot disagree about where a record ends. */
function isSpfAllTerm(token: string): boolean {
  return /^[+\-~?]?all$/i.test(token);
}

/** Parse an SPF record's terms, or null when the value is not `v=spf1 …`. */
export function parseSpfRecord(txt: string): SpfRecord | null {
  const tokens = txt.trim().split(/\s+/);
  if (!/^v=spf1$/i.test(tokens[0] ?? "")) return null;
  const terms: string[] = [];
  let all: string | null = null;
  for (const token of tokens.slice(1)) {
    if (isSpfAllTerm(token)) {
      // Terms after `all` are never evaluated (RFC 7208 §5.1) — the record ends here.
      all = token;
      break;
    }
    terms.push(token);
  }
  return { terms, all };
}

/** Mechanism names and domain-specs are case-insensitive (RFC 7208 §4.6.1);
 * a leading `+` is the default qualifier and means nothing on its own. */
function normalizeSpfTerm(term: string): string {
  return term.replace(/^\+/, "").toLowerCase();
}

/**
 * The `include:` host of an SPF record that carries EXACTLY that one
 * mechanism and nothing else — the shape DoDomain's `email-authentication`
 * template merges via `SPFM` (`spfRules: "include:%spfInclude%"`). Any other
 * SPF record (extra mechanisms, no include, two includes) returns null: it can
 * still be entered by hand, it just isn't a shape the template can express.
 */
export function spfSoleIncludeHost(txt: string): string | null {
  const record = parseSpfRecord(txt);
  if (record === null || record.terms.length !== 1) return null;
  const match = /^\+?include:([^\s/]+)$/i.exec(record.terms[0]!);
  return match?.[1] ?? null;
}

/**
 * True when the PUBLISHED SPF record carries every term the EXPECTED one asks
 * for. The `all` qualifier is deliberately not compared: after an SPFM merge
 * the provider keeps the zone's existing terminal, and a session cannot know
 * which one the domain owner runs.
 */
export function spfRecordSatisfies(expected: string, actual: string): boolean {
  const want = parseSpfRecord(expected);
  const have = parseSpfRecord(actual);
  if (want === null || have === null) return false;
  const published = new Set(have.terms.map(normalizeSpfTerm));
  return want.terms.every((term) => published.has(normalizeSpfTerm(term)));
}

/**
 * The PUBLISHED SPF record rewritten so it also carries every term the EXPECTED
 * one asks for — the merge Domain Connect performs for us at tier 2 (the `SPFM`
 * pseudo-type, domain-connect-templates.ts), done by hand on the tier-1
 * Cloudflare write path where we hold the zone ourselves. Returns null when
 * either side is not an SPF record, and the published record UNCHANGED when it
 * already satisfies the expected one (so a caller writes nothing).
 *
 * A zone may hold only ONE `v=spf1` record (RFC 7208 §3.2 — two of them is a
 * PermError that fails every sender), so creating a second one beside an
 * existing record is never the right outcome: the missing terms go INTO the
 * published record instead, inserted before its terminal `all` so they are
 * actually evaluated (§5.1: nothing after `all` ever is).
 *
 * The rewrite is deliberately minimal — token surgery on the published string,
 * not a re-render of the parse. The zone's own terminal qualifier, its other
 * mechanisms, their order, its `v=spf1` casing and any (unevaluated) tail after
 * `all` all survive verbatim; only inter-token whitespace is normalised to
 * single spaces. What we add is exactly the expected record's missing terms —
 * never its `all`, which belongs to the domain owner (`spfRecordSatisfies`
 * ignores it for the same reason).
 */
export function mergeSpfRecordTerms(expected: string, actual: string): string | null {
  const want = parseSpfRecord(expected);
  const have = parseSpfRecord(actual);
  if (want === null || have === null) return null;
  const published = new Set(have.terms.map(normalizeSpfTerm));
  const missing = want.terms.filter((term) => !published.has(normalizeSpfTerm(term)));
  if (missing.length === 0) return actual;
  const tokens = actual.trim().split(/\s+/);
  const allIndex = tokens.findIndex((token) => isSpfAllTerm(token));
  tokens.splice(allIndex === -1 ? tokens.length : allIndex, 0, ...missing);
  return tokens.join(" ");
}

/** RFC 7208 §4.6.4: the evaluation limit on DNS-querying terms. */
export const SPF_MAX_DNS_LOOKUPS = 10;

/**
 * How many of a record's OWN terms cost a DNS lookup (`include`, `a`, `mx`,
 * `ptr`, `exists`, `redirect=`). This counts the record as written, not the
 * lookups its includes go on to make, so it is a floor: a record at or over
 * the limit on its own terms is certainly broken, one under it may still be.
 * Consumers surface it as a WARNING beside a verified record, never as a
 * verification failure — the record the session asked for is present.
 */
export function spfDnsLookupTermCount(txt: string): number {
  const record = parseSpfRecord(txt);
  if (record === null) return 0;
  return record.terms.filter((term) =>
    /^[+\-~?]?(?:include:|a$|a[:/]|mx$|mx[:/]|ptr$|ptr:|exists:)|^redirect=/i.test(term),
  ).length;
}

// ── tag lists (DKIM, DMARC) ────────────────────────────────────────────────

/** `tag=value; tag=value` → a map keyed by lower-cased tag, values trimmed.
 * A malformed segment (no `=`) is skipped rather than failing the parse. */
export function parseTagValueList(txt: string): Map<string, string> {
  const tags = new Map<string, string>();
  for (const segment of txt.split(";")) {
    const eq = segment.indexOf("=");
    if (eq === -1) continue;
    const tag = segment.slice(0, eq).trim().toLowerCase();
    if (tag === "") continue;
    tags.set(tag, segment.slice(eq + 1).trim());
  }
  return tags;
}

/** RFC 6376 §3.6.1 defaults for the tags a key record may omit. */
const DKIM_TAG_DEFAULTS: Readonly<Record<string, string>> = { v: "DKIM1", k: "rsa" };

/**
 * True when the published DKIM key record carries every tag the expected one
 * does, with the same value. `p=` (the key) is compared with whitespace
 * removed — resolvers hand back a long key as several strings that verify.ts
 * re-joins, and RFC 6376 §3.6.1 ignores whitespace inside it. `v` and `k` fall
 * back to their RFC defaults when the published record omits them.
 */
export function dkimRecordSatisfies(expected: string, actual: string): boolean {
  const want = parseTagValueList(expected);
  const have = parseTagValueList(actual);
  if (!want.has("p")) return false;
  for (const [tag, wantValue] of want) {
    const haveValue = have.get(tag) ?? DKIM_TAG_DEFAULTS[tag];
    if (haveValue === undefined) return false;
    if (tag === "p") {
      if (haveValue.replace(/\s+/g, "") !== wantValue.replace(/\s+/g, "")) return false;
    } else if (haveValue.toLowerCase() !== wantValue.toLowerCase()) {
      return false;
    }
  }
  return true;
}

/** `rua`/`ruf` are comma-separated URI lists; order and case carry no meaning. */
function dmarcUriSet(value: string): string {
  return value
    .split(",")
    .map((uri) => uri.trim().toLowerCase())
    .filter((uri) => uri !== "")
    .sort()
    .join(",");
}

/**
 * True when the published DMARC record is `v=DMARC1` and carries every tag the
 * expected one does with the same value (policies and keywords compared
 * case-insensitively, report URIs as sets). Extra published tags are the zone
 * owner's choice, not a mismatch.
 */
export function dmarcRecordSatisfies(expected: string, actual: string): boolean {
  const want = parseTagValueList(expected);
  const have = parseTagValueList(actual);
  if (have.get("v")?.toUpperCase() !== "DMARC1") return false;
  for (const [tag, wantValue] of want) {
    const haveValue = have.get(tag);
    if (haveValue === undefined) return false;
    const same =
      tag === "rua" || tag === "ruf"
        ? dmarcUriSet(haveValue) === dmarcUriSet(wantValue)
        : haveValue.toLowerCase() === wantValue.toLowerCase();
    if (!same) return false;
  }
  return true;
}

/**
 * The policy-aware TXT comparison, or null when `expected` is not an email
 * policy at all (the caller then applies its exact rule). record-capabilities.ts
 * `recordValueMatches` is the ONE caller; everything that compares a TXT —
 * the verifier, the tier-1 read-back, the mismatch classifier — reaches this
 * through it, so none of them can disagree about what a satisfied policy is.
 */
export function emailPolicyTxtMatches(expected: string, actual: string): boolean | null {
  const kind = emailPolicyKindOf(expected);
  if (kind === null) return null;
  if (kind === "spf") return spfRecordSatisfies(expected, actual);
  if (kind === "dkim") return dkimRecordSatisfies(expected, actual);
  return dmarcRecordSatisfies(expected, actual);
}
