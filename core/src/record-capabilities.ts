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
// Collapsing the lists into one source makes that drift structurally impossible.
//
// Accepted vs writable (2026-10-29, SRV/CAA/NS): the accepted set is now wider
// than what EVERY tier can write, exactly as this file used to anticipate.
// ACCEPTED (RECORD_TYPES) means "a session may request it, and the guided manual
// tier plus DNS verification handle it". WRITABLE is per tier
// (TIER_WRITABLE_TYPES): a one-click tier is offered for a session only when it
// writes EVERY requested type, so a session is never "connected" by a tier that
// skipped a record (the F-002 invariant, now enforced per tier instead of by
// keeping the accepted set small). VERIFIABLE still equals ACCEPTED: every type
// here has a lookup branch in verify.ts and a matcher below.
//
// Pure data: no `node:` imports — client-safe, so it flows through the
// `@dodomain/core/records` subpath into client components.

import { emailPolicyTxtMatches } from "./email-records.ts";

/**
 * Every DNS record type a DoDomain connect session may request.
 *
 * NS is accepted BELOW the zone apex only (a subdomain delegation): an apex NS
 * set is the domain's own nameserver delegation, which no connect flow may
 * touch. The apex rule needs the PSL, so it lives in apex.ts (`isNsAtZoneApex`)
 * and is applied at session creation and again by every writer.
 *
 * ALIAS is deliberately absent: it has no DNS wire type (a provider answers it
 * as A/AAAA), so verification could only compare address sets, which a plain A
 * record also passes and a CDN target's rotating answers fail.
 */
export const RECORD_TYPES = ["A", "AAAA", "CNAME", "TXT", "MX", "SRV", "CAA", "NS"] as const;

export type RecordType = (typeof RECORD_TYPES)[number];

/** Read-only DNS tools read every accepted type. Kept as its own binding: a
 * lookup-only type (one the resolver reads but no session may request) would
 * be added here, never to RECORD_TYPES. */
export const LOOKUP_RECORD_TYPES = [...RECORD_TYPES] as const;
export type LookupRecordType = (typeof LOOKUP_RECORD_TYPES)[number];

/** Address lookups are the resolver operations that expose per-record TTL. */
export type AddressRecordType = Extract<RecordType, "A" | "AAAA">;

/** Canonical equality for complete DNS answer sets, without weakening TXT
 * token comparisons or lower-casing case-sensitive CAA property values. */
export function canonicalDnsAnswer(type: LookupRecordType, value: string): string {
  return type === "TXT" || type === "CAA" ? value : value.replace(/\.$/, "").toLowerCase();
}

/** True when `type` is one of the accepted DoDomain record types. */
export function isRecordType(type: string): type is RecordType {
  return (RECORD_TYPES as readonly string[]).includes(type);
}

/** The record types a Domain Connect template shape may carry
 * (domain-connect-templates.ts types `sessionType` with this). A template can
 * write only what a PUBLISHED template contains, and every DoDomain template
 * record is one of these five; widening this means publishing a template first. */
export const DOMAIN_CONNECT_TEMPLATE_TYPES = [
  "A",
  "AAAA",
  "CNAME",
  "TXT",
  "MX",
] as const satisfies readonly RecordType[];
export type DomainConnectSessionRecordType = (typeof DOMAIN_CONNECT_TEMPLATE_TYPES)[number];

/** Every connect mechanism, spelled as the database's `ConnectTier` enum
 * (apps/web lib/one-click-records.ts indexes TIER_WRITABLE_TYPES with that
 * enum, so a new tier fails to compile until its row exists here). */
export type ConnectWriteTier =
  | "cloudflare_oauth"
  | "porkbun_dns_connect"
  | "digitalocean_oauth"
  | "hostinger_oauth"
  | "spaceship_api_key"
  | "ovh_consent"
  | "dynadot_oauth"
  | "domain_connect"
  | "manual";

/**
 * THE type x tier matrix: which accepted types each connect mechanism writes.
 *   - cloudflare_oauth: Cloudflare's DNS API writes every accepted type (SRV and
 *     CAA as its structured `data` object, cloudflare/dns.ts).
 *   - porkbun_dns_connect: Porkbun DNS Connect documents every accepted type
 *     (NS below the root only, which is our acceptance rule anyway).
 *   - hostinger_oauth: the five types our Hostinger zone writer handles (core
 *     hostinger.ts). An explicit list, so widening RECORD_TYPES never silently
 *     widens this adapter; SRV, CAA and NS stay on the guided tier.
 *   - digitalocean_oauth: the same five types as Hostinger; structured SRV,
 *     CAA and NS stay guided until this adapter explicitly supports them.
 *   - spaceship_api_key: the five types the Spaceship adapter writes; other
 *     accepted types stay on guided setup.
 *   - ovh_consent: the five types the OVHcloud adapter (core ovh.ts) maps to
 *     OVH's `{fieldType, subDomain, target}` body. OVH also takes SRV and CAA,
 *     but their packed `target` strings are unproven, so they stay guided
 *     until the adapter explicitly supports them.
 *   - dynadot_oauth: the five types the Dynadot adapter (core dynadot.ts) maps to
 *     `set_domain_records` rows (`record_value2` = MX priority). Anything else
 *     stays guided.
 *   - domain_connect: only what a published template contains. Membership is
 *     necessary, not sufficient: recipes.ts must still match a template.
 *   - manual: the user adds the records by hand, so every accepted type.
 */
export const TIER_WRITABLE_TYPES: Readonly<Record<ConnectWriteTier, readonly RecordType[]>> = {
  cloudflare_oauth: RECORD_TYPES,
  porkbun_dns_connect: RECORD_TYPES,
  hostinger_oauth: ["A", "AAAA", "CNAME", "TXT", "MX"],
  digitalocean_oauth: ["A", "AAAA", "CNAME", "TXT", "MX"],
  spaceship_api_key: ["A", "AAAA", "CNAME", "TXT", "MX"],
  ovh_consent: ["A", "AAAA", "CNAME", "TXT", "MX"],
  dynadot_oauth: ["A", "AAAA", "CNAME", "TXT", "MX"],
  domain_connect: DOMAIN_CONNECT_TEMPLATE_TYPES,
  manual: RECORD_TYPES,
};

/** True when `tier` can write a record of `type`. */
export function tierCanWrite(tier: ConnectWriteTier, type: string): boolean {
  return (TIER_WRITABLE_TYPES[tier] as readonly string[]).includes(type);
}

/** The requested types `tier` cannot write, deduplicated, in request order.
 * Empty means the tier may be offered for these records. Every one-click offer
 * and start route asks this before handing a session to a provider. */
export function typesTierCannotWrite(
  tier: ConnectWriteTier,
  records: readonly { type: string }[],
): string[] {
  return [...new Set(records.map((r) => r.type).filter((type) => !tierCanWrite(tier, type)))];
}

/** Record types the Cloudflare-OAuth tier-1 connector can write: the
 * cloudflare_oauth row of TIER_WRITABLE_TYPES (apply.ts's defense-in-depth
 * check reads it). F-002 (R8): the prior {CNAME,TXT,A} subset was the defect,
 * not a Cloudflare limit. */
export const TIER1_WRITABLE_TYPES: readonly RecordType[] = TIER_WRITABLE_TYPES.cloudflare_oauth;

/** True when `type` is writable by the Hostinger one-click writer: the
 * hostinger_oauth row of TIER_WRITABLE_TYPES. */
export function isHostingerWritable(type: string): type is RecordType {
  return tierCanWrite("hostinger_oauth", type);
}

/** True when `type` is writable by the Spaceship API-key connect. */
export function isSpaceshipWritable(type: string): type is RecordType {
  return tierCanWrite("spaceship_api_key", type);
}

/** True when `type` is writable by the OVHcloud consent connect (core ovh.ts). */
export function isOvhWritable(type: string): type is RecordType {
  return tierCanWrite("ovh_consent", type);
}

/** True when `type` is writable by the tier-1 (Cloudflare OAuth) connector. */
export function isTier1Writable(type: string): type is RecordType {
  return tierCanWrite("cloudflare_oauth", type);
}

/** MX (RFC 5321 preference) and SRV (RFC 2782 priority) carry a required
 * numeric priority in `priority`. */
export function requiresPriority(type: RecordType): boolean {
  return type === "MX" || type === "SRV";
}

/** The CAA property tags a session may request: the three RFC 8659 defines.
 * Other tags are CA-specific and node:dns drops tags it does not know, so they
 * could never be verified. */
export const CAA_TAGS = ["issue", "issuewild", "iodef"] as const;
export type CaaTag = (typeof CAA_TAGS)[number];

/** The fields a record carries beyond type/host. For SRV, `value` is the target
 * host; for CAA, `value` is the property value (e.g. "letsencrypt.org"). */
export interface RecordFields {
  type: string;
  value: string;
  priority?: number;
  weight?: number;
  port?: number;
  flags?: number;
  tag?: string;
}

/** Why a record of an accepted type is missing a field its type requires. */
export interface RecordFieldProblem {
  reason: "missing_mx_priority" | "missing_srv_fields" | "missing_caa_fields";
  message: string;
  fields: string[];
}

/**
 * The per-type required fields: MX needs `priority`; SRV needs `priority`,
 * `weight` and `port` (its target is `value`); CAA needs `flags` and `tag` (its
 * property value is `value`). Null when the record is complete.
 *
 * One rule, two callers: zCreateSessionInput refuses an incomplete SRV/CAA at
 * the schema (so REST, the MCP tool and the node SDK refuse the same body), and
 * the create route keeps its long-standing `missing_mx_priority` refusal for MX.
 * MX stays out of the schema rule because zRecords also parses STORED rows, and
 * legacy MX rows predating the F-002 guard carry no priority.
 */
export function missingRecordFields(rec: RecordFields): RecordFieldProblem | null {
  const missing = (names: (keyof RecordFields)[]) => names.filter((n) => rec[n] === undefined);
  if (rec.type === "MX") {
    if (rec.priority !== undefined) return null;
    return {
      reason: "missing_mx_priority",
      message: "MX records require a numeric priority",
      fields: ["priority"],
    };
  }
  if (rec.type === "SRV") {
    const fields = missing(["priority", "weight", "port"]);
    if (!fields.length) return null;
    return {
      reason: "missing_srv_fields",
      message: `SRV records require priority, weight and port (missing: ${fields.join(", ")}); value is the target host`,
      fields,
    };
  }
  if (rec.type === "CAA") {
    const fields = missing(["flags", "tag"]);
    if (!fields.length) return null;
    return {
      reason: "missing_caa_fields",
      message: `CAA records require flags and tag (missing: ${fields.join(", ")}); value is the property value`,
      fields,
    };
  }
  return null;
}

/** An SRV answer in presentation order, "priority weight port target": the ONE
 * spelling verify.ts's lookup emits and every SRV comparison parses. */
export function srvAnswer(srv: {
  priority: number;
  weight: number;
  port: number;
  target: string;
}): string {
  return `${srv.priority} ${srv.weight} ${srv.port} ${srv.target}`;
}

/** A CAA answer as verify.ts's lookup emits it, `flags tag "value"` with the
 * value JSON-quoted: the ONE spelling every CAA comparison parses. */
export function caaAnswer(caa: { flags: number; tag: string; value: string }): string {
  return `${caa.flags} ${caa.tag} ${JSON.stringify(caa.value)}`;
}

/** Split an SRV answer; null when it is not four whitespace-separated fields. */
export function parseSrvAnswer(
  answer: string,
): { priority: number; weight: number; port: number; target: string } | null {
  const m = /^(\d+)\s+(\d+)\s+(\d+)\s+(\S+)$/.exec(answer.trim());
  if (!m) return null;
  return { priority: Number(m[1]), weight: Number(m[2]), port: Number(m[3]), target: m[4]! };
}

/** Split a CAA answer; null when it is not `flags tag "value"`. */
export function parseCaaAnswer(
  answer: string,
): { flags: number; tag: string; value: string } | null {
  const m = /^(\d+)\s+([A-Za-z0-9]+)\s+(".*")$/.exec(answer.trim());
  if (!m) return null;
  let value: unknown;
  try {
    value = JSON.parse(m[3]!);
  } catch {
    // Not a JSON-quoted value: not an answer in our spelling, so no match.
    return null;
  }
  return typeof value === "string" ? { flags: Number(m[1]), tag: m[2]!, value } : null;
}

/**
 * The value a record is VERIFIED against: the composite answer for the types
 * whose answer carries more than `value` (SRV, CAA), `value` itself otherwise.
 * MX keeps its exchange-only `value` with the preference beside it
 * (ExpectedRecord.priority), as it always has.
 */
export function expectedAnswerFor(rec: RecordFields): string {
  if (
    rec.type === "SRV" &&
    rec.priority !== undefined &&
    rec.weight !== undefined &&
    rec.port !== undefined
  ) {
    return srvAnswer({
      priority: rec.priority,
      weight: rec.weight,
      port: rec.port,
      target: rec.value,
    });
  }
  if (rec.type === "CAA" && rec.flags !== undefined && rec.tag !== undefined) {
    return caaAnswer({ flags: rec.flags, tag: rec.tag, value: rec.value });
  }
  return rec.value;
}

/**
 * True when a CDN/proxy in front of the zone (Cloudflare's orange cloud being
 * the one users actually hit) can REPLACE this record's published value with
 * its own edge address.
 *
 * Only the address-type records that carry web traffic qualify — A, AAAA and
 * CNAME. Proxying one of them means the authoritative answer for that name is
 * the proxy's IP, not the value the user entered, so our verification sees
 * either a different value or, when the proxy flattens a CNAME into address
 * records, nothing of the expected type at all. Both are the same root cause and
 * neither is a propagation delay.
 *
 * TXT and MX are never proxied — they carry no traffic — so a proxy hint on
 * those would be noise pointing at an innocent setting.
 *
 * Consumed by the connect flow's mismatch note to attach a "set it to DNS only"
 * hint to evidence, rather than warning every Cloudflare user unconditionally.
 */
export function isProxyableRecordType(type: string): boolean {
  if (type === "CNAME") return true;
  if (type === "A") return true;
  return type === "AAAA";
}

/**
 * True when a session record of this type hands the name's WEB TRAFFIC to the
 * integrator, so the integrator will go on to issue a TLS certificate for it —
 * the records the post-verify TLS-issuance advisories
 * (tls-issuance-advisories.ts) are computed for.
 *
 * The same address-type set as `isProxyableRecordType` (A, AAAA, CNAME) — both
 * derive from "which records carry web traffic" — kept as its own predicate
 * because the two questions differ: a proxy REPLACES a published value, while
 * issuance is what happens once the value is live. A TXT or MX record never
 * terminates TLS, so no advisory is ever computed for one — a CAA set is
 * irrelevant to a verification token.
 */
export function isTlsTerminatingRecordType(type: string): boolean {
  return isProxyableRecordType(type);
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
 *   - SRV: an additional target changes live service routing, the MX argument.
 *   - NS: a second nameserver set at a delegation mixes two zones' answers.
 *
 * CAA also qualifies (2026-10-29): a CAA RRset is a UNION of authorizations
 * (RFC 8659 §4), so adding `issue "letsencrypt.org"` beside an existing
 * `issue "digicert.com"` authorizes both, which is exactly what an integrator
 * asking for its CA intends; refusing to write it would block certificate
 * issuance on every zone that already pins a CA.
 *
 * Consumed by the tier-1 apply orchestrator (cloudflare/apply.ts) to decide
 * whether a present-but-value-mismatched name still gets our record created.
 */
export function allowsCoexistingValues(type: string): boolean {
  return type === "TXT" || type === "CAA";
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
 *   - SRV: both sides are the composite answer "priority weight port target"
 *     (`srvAnswer`); the three numbers must be equal and the target is
 *     host-like. Either side failing to parse is no match.
 *   - CAA: both sides are `flags tag "value"` (`caaAnswer`); flags equal, tag
 *     case-insensitive (RFC 8659 §4.1), value EXACT and case-sensitive, the same
 *     rule `canonicalDnsAnswer` keeps for CAA.
 *   - A / AAAA / CNAME / NS (and any other type): host-like — trailing dot
 *     stripped and lower-cased on both sides, then compared exactly. (Harmless on
 *     IPs: no trailing dot; IPv6 hex is correctly case-folded.)
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
  if (type === "SRV") {
    const want = parseSrvAnswer(expected);
    const got = parseSrvAnswer(actual);
    if (want === null || got === null) return false;
    return (
      want.priority === got.priority &&
      want.weight === got.weight &&
      want.port === got.port &&
      want.target.replace(/\.$/, "").toLowerCase() === got.target.replace(/\.$/, "").toLowerCase()
    );
  }
  if (type === "CAA") {
    const want = parseCaaAnswer(expected);
    const got = parseCaaAnswer(actual);
    if (want === null || got === null) return false;
    return (
      want.flags === got.flags &&
      want.tag.toLowerCase() === got.tag.toLowerCase() &&
      want.value === got.value
    );
  }
  if (type === "TXT") {
    // An SPF/DKIM/DMARC record is a POLICY, not a token: the published record
    // SATISFIES the expected one when every term/tag asked for is present with
    // the same value (email-records.ts — SPF is merged into the zone's one
    // v=spf1 record, DKIM keys are re-joined across strings, DMARC is a tag
    // list). Any other TXT stays a verification token: exact, case-sensitive.
    const policy = emailPolicyTxtMatches(expected, actual);
    return policy ?? actual === expected;
  }

  const norm = (s: string) => s.replace(/\.$/, "").toLowerCase();
  const valueMatches = norm(actual) === norm(expected);

  if (type === "MX") {
    // No expected preference known → compare the exchange alone (legacy).
    if (opts.expectedPriority === undefined) return valueMatches;
    return valueMatches && opts.actualPriority === opts.expectedPriority;
  }

  return valueMatches;
}

/**
 * Split ONE resolver MX answer back into its parts.
 *
 * MX answers travel between the DNS layer and every comparison as the single
 * string `"${priority} ${exchange}"` (verify.ts's `lookup` builds them that way
 * so a resolver's per-record preference survives into
 * VerificationResult.authoritativeFound/publicFound). This is the ONE place that
 * wire shape is taken apart again — it used to be an inline regex inside
 * verify.ts's `matches`, which made the encoding a second, undocumented home the
 * moment anything else needed to read a found MX value.
 *
 * An answer that doesn't carry a leading numeric preference yields the whole
 * string as the exchange and NO priority, which is exactly how the pre-F-002
 * legacy path behaved (`recordValueMatches` then compares the exchange alone).
 */
export function parseMxAnswer(answer: string): { priority?: number; exchange: string } {
  const m = /^(\d+)\s+(.*)$/.exec(answer);
  if (!m) return { exchange: answer };
  return { priority: Number(m[1]), exchange: m[2]! };
}

/**
 * True when ONE raw resolver answer satisfies an expected record — the
 * answer-level matcher, sitting one layer above value-level `recordValueMatches`.
 *
 * The difference is the MX wire encoding: `answer` is what a resolver actually
 * returned (for MX, `"10 mx.example.com"`), whereas `recordValueMatches` takes
 * the exchange and the preference as separate arguments. Callers holding raw
 * answers — verify.ts's `matches` over authoritative/public lookups, and
 * record-diff.ts's mismatch classifier — go through here so neither has to know
 * how an MX answer is spelled.
 */
export function recordAnswerMatches(
  type: string,
  expected: string,
  answer: string,
  expectedPriority?: number,
): boolean {
  if (type === "MX") {
    const { priority, exchange } = parseMxAnswer(answer);
    return recordValueMatches("MX", expected, exchange, {
      expectedPriority,
      actualPriority: priority,
    });
  }
  return recordValueMatches(type, expected, answer);
}
