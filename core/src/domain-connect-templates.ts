// THE Domain Connect template registry — the ONE home for "which record sets
// can DoDomain apply over Domain Connect, and what does each template write".
//
// Domain Connect providers apply PRE-APPROVED templates, never arbitrary
// records[] (spec v2.3 §4 — docs/domain-connect-findings.md §4/§5). Every entry
// below is the in-code twin of one JSON file in docs/domain-connect/templates/
// (`dodomain.io.<serviceId>.json`, the Domain-Connect/Templates repo shape), and
// the two are kept in LOCKSTEP by test/domain-connect-templates.test.ts, which
// renders each entry's `records` through `renderTemplateRecords` and compares
// them byte-for-byte with the committed JSON. Change a serviceId, a variable
// name, a host or a groupId here and the test fails until the JSON moves too —
// that is the drift check the templates README asks for, because a provider
// that receives a variable its copy of the template doesn't define rejects the
// apply, and nothing on our side would otherwise notice.
//
// recipes.ts (`compileToRecipe`) is the MATCHER over this data: it finds the
// one template whose shape list the session's record set fills. This file holds
// no matching logic — only shapes, in the order the matcher tries them.
//
// Pure data, no `node:` imports, no env (scripts/check-core-config-bans.sh).

import type { RecordType } from "./record-capabilities.ts";

/** The record types the JSON templates are written in: the session record
 * types, SPF as `SPFM` — the merge pseudo-type a provider folds into the zone's
 * existing `v=spf1` TXT (spec §"SPFM"), never as a second SPF TXT — and the
 * three types only the `dns-records` slots declare (SRV, NS, CAA), which no
 * session record can carry yet (see `sessionType: null` below). */
export type DomainConnectTemplateRecordType = RecordType | "SPFM" | "SRV" | "NS" | "CAA";

/**
 * How a session record's VALUE becomes the template's variable(s).
 *
 *   - `whole`     the entire value is the variable (a CNAME target, an address).
 *   - `prefixed`  the value MUST start with `prefix`; the remainder is the
 *                 variable. The prefix is byte-exact on purpose: the provider
 *                 writes `prefix + variable`, and verification compares TXT
 *                 values exactly, so a session whose value spells the prefix
 *                 differently ("v=DKIM1;k=…" with no space) could be applied but
 *                 would never verify — it is refused here instead. An optional
 *                 `suffix` closes the value the same way (CAA's closing quote).
 *   - `spf-include` the value is a complete SPF record carrying exactly ONE
 *                 `include:` mechanism and nothing else (`v=spf1 include:<host>
 *                 <q>all`); `<host>` is the variable. v1 constraint, so a
 *                 provider's template review sees a bounded merge rule, and so
 *                 the merged result stays verifiable (email-records.ts).
 *   - `spf-terms` the value is a complete SPF record; EVERY term between
 *                 `v=spf1` and the terminal `all` is the variable (the SPFM
 *                 `spfRules`). The `dns-records` slots use it; a record with a
 *                 `redirect=`/`exp=` modifier is refused, because merging a
 *                 modifier into someone else's SPF record changes its meaning.
 *                 Verification is term-aware (`spfRecordSatisfies`), so the
 *                 merged result verifies whatever else the zone's SPF carries.
 *                 GoDaddy publishes the merge one hop away (apex
 *                 `include:<id>._spfm.<zone>`, terms at that name; live
 *                 2026-11-04), which verify.ts follows exactly once, same zone.
 */
export type TemplateValueRule =
  | { kind: "whole"; variable: string }
  | { kind: "prefixed"; prefix: string; variable: string; suffix?: string }
  | { kind: "spf-include"; variable: string }
  | { kind: "spf-terms"; variable: string };

/**
 * Which TXT records a `dns-records` TXT slot takes. The two kinds are DISJOINT
 * by construction (`isSingletonTxtRecord` in recipes.ts), so a TXT record has
 * exactly one kind of slot it can land in:
 *
 *   - `add`     — conflict mode None: the provider ADDS the record beside any
 *                 TXT already at that name and never removes one. Verification
 *                 tokens and other "one more TXT" records.
 *   - `replace` — conflict mode All: the record REPLACES every TXT at its name.
 *                 Only records a name may hold ONE of by their own standard:
 *                 DMARC (RFC 7489 §6.6.3 — two records means no policy at
 *                 all), DKIM keys (one key per selector), MTA-STS and TLS-RPT.
 *                 Adding a second one beside the old would break the domain's
 *                 mail, which is why these never go to an `add` slot.
 *   - `dkim-key` — a whole-value group at a selector name that REPLACES (conflict
 *                 mode All), so it takes only a real DKIM key record
 *                 (`isDkimKeyRecord`, the same classifier `replace` is built
 *                 on); any other TXT at that name is not its to delete.
 */
export type TxtSlotRole = "add" | "replace" | "dkim-key";

/** The SRV fields beyond host (`name`) and value (`target`), as variable names. */
export interface SrvSlotVariables {
  service: string;
  protocol: string;
  priority: string;
  weight: string;
  port: string;
}

export interface DomainConnectTemplateRecordShape {
  /**
   * The type the SESSION record carries (what the verifier checks). `null` for
   * a slot no session record can fill: the SRV / NS / CAA slots of
   * `dns-records`. They are declared so the template GoDaddy and the registry
   * approve is complete once, and become fillable the day the session record
   * model carries those types (DESIGN.md "Feature 1"). TODO(scope): sessions
   * accept only A/AAAA/CNAME/TXT/MX (record-capabilities.ts), so these slots
   * are never applied yet.
   */
  sessionType: RecordType | null;
  /** The type written in the template JSON — differs from `sessionType` only
   * for SPF (`SPFM`) and the unfillable SRV / NS / CAA slots. */
  templateType: DomainConnectTemplateRecordType;
  /** Domain Connect record group. Optional shapes are left out of the apply's
   * `groupId` list when the session doesn't carry them (spec: "If no group is
   * specified, all groups are applied"). */
  groupId: string;
  /**
   * Host relative to the template ROOT. `"@"` is the root itself. The root is
   * the zone for `hostRequired:false` templates and `<host>.<zone>` for
   * `hostRequired:true` ones (spec: record hosts are "relative to the applied
   * host and domain"). May start with exactly one `%variable%` label
   * (`%dkimSelector%._domainkey`) — the fixed remainder is what the matcher
   * anchors on; the leading label becomes the variable. May also be ONE whole
   * `%variable%` (the `dns-records` slots): the record's root-relative name is
   * the variable, `"@"` for the root itself (spec: an empty or `@` host after
   * substitution is the root). For SRV this is the record's `name`.
   */
  host: string;
  /**
   * Whole-variable hosts only: the name must be a SUBDOMAIN, never the root,
   * and no label of it a wildcard (`*`) or an underscore name (`_dmarc`,
   * `bounce._domainkey` — see `isSubdomainHost` in recipes.ts). `email-sending`'s
   * MAIL FROM pair sets it, so its MX can never land at the root, where it
   * would take over the domain's inbound mail.
   */
  subdomainHost?: true;
  value: TemplateValueRule;
  /** A shape the session may omit; omitted ⇒ its groupId is not applied. */
  optional?: boolean;
  /** MX only: the preference as a variable (the session record's `priority`).
   * Its name holds no digit — see `slotNumberWord`. */
  priority?: { variable: string };
  /** SRV only: the remaining fields as variables. */
  srv?: SrvSlotVariables;
  /** `dns-records` TXT slots and a whole-value DKIM group — see `TxtSlotRole`. */
  txtRole?: TxtSlotRole;
  /** TXT-only conflict handling, exactly as the template JSON carries it. */
  txtConflictMatchingMode?: "None" | "All" | "Prefix";
  txtConflictMatchingPrefix?: string;
  /**
   * Conflict-detection lifetime (spec, record attributes): `Always` — the
   * DEFAULT, left implicit — means the record "MUST be applied and kept with
   * the template", so a provider reads its later removal as the whole template
   * being broken; `OnApply` means it "MUST be applied but can be later removed
   * without dropping the whole template".
   *
   * Only ever `OnApply`, and only on a record the domain owner legitimately
   * re-tunes afterwards — DMARC (the Templates-repo quality checklist names it
   * as the example), a CAA policy, and the `dns-records` replace slots. Every
   * other record DoDomain writes IS the service: removing it is disconnecting,
   * so the implicit `Always` is correct and stays absent from the JSON.
   */
  essential?: "OnApply";
}

export interface DomainConnectTemplate {
  serviceId: string;
  /** `true` ⇒ the apply carries `host=` and every record host is relative to
   * `<host>.<zone>`. The template MUST be true when a CNAME sits at `@`. */
  hostRequired: boolean;
  /**
   * `true` ⇒ re-applying the template on the same domain/host MUST NOT remove
   * the previous instance (spec §"Apply, Re-apply, and Multi-Instance"). Set on
   * every template whose applies are per INTEGRATION rather than per domain:
   * `dns-records` (its record hosts are variables), `email-sending` (a MAIL
   * FROM host and DKIM selectors that differ per sender) and
   * `site-verification` (one token per vendor account). The apply carries no
   * `host=`, so without it a provider that keeps template state (GoDaddy
   * does) would delete one integrator's records when the next one applies the
   * same template on the same domain. Conflict mode does not help: it governs
   * records already in the zone, not the previous template instance.
   */
  multiInstance?: boolean;
  /**
   * `true` ⇒ the matcher may also root a `hostRequired: false` template at a
   * subdomain, passing the apply's `host=` (the spec allows `host` on any
   * template; every record host is then relative to `<host>.<zone>`). Root
   * `"@"` is always tried first, so a record set at the zone root never
   * carries a host.
   */
  appliesUnderHost?: boolean;
  /**
   * `true` ⇒ the JSON sets `sharedProviderName` (and the deprecated `shared`,
   * which the spec recommends beside it for v2.1 providers), so an apply MAY
   * pass `providerName=` and the consent screen can read "<integrator> via
   * DoDomain". TODO(scope): applyUrl.ts does not send `providerName` yet, so
   * the screen still names DoDomain alone — docs/domain-connect/templates/README.md.
   */
  sharedProviderName?: boolean;
  /**
   * `true` ⇒ prepared here but not yet submitted to Domain-Connect/Templates,
   * so no provider serves it. The matcher still compiles to it (an unserved
   * template probes 404 and the flow degrades to manual, like any other), but
   * every surface that judges a provider's coverage leaves it out — see
   * `PREPARED_SERVICE_IDS`.
   */
  prepared?: boolean;
  records: readonly DomainConnectTemplateRecordShape[];
}

/** TTL every template record carries — one value, so the JSON and the
 * rendered twin can't disagree. */
export const DOMAIN_CONNECT_TEMPLATE_TTL = 3600;

/** The fixed prefix of every DoDomain ownership token. Shared with recipes.ts's
 * exported `VERIFY_PREFIX` (same bytes — that export is the public name). */
const VERIFY_TOKEN_PREFIX = "dodomain-verify=";
/** The fixed host of the ownership TXT (recipes.ts `VERIFY_TXT_HOST`). */
const VERIFY_TOKEN_HOST = "_dodomain-challenge";

const VERIFICATION_TXT_SHAPE: DomainConnectTemplateRecordShape = {
  sessionType: "TXT",
  templateType: "TXT",
  groupId: "verify",
  host: VERIFY_TOKEN_HOST,
  value: { kind: "prefixed", prefix: VERIFY_TOKEN_PREFIX, variable: "token" },
  txtConflictMatchingMode: "Prefix",
  txtConflictMatchingPrefix: VERIFY_TOKEN_PREFIX,
};

/**
 * The vendor ownership-token prefixes `site-verification` declares, as
 * [groupId, fixed prefix]. Part of the published template: adding one is a
 * new template `version`. The variable is `<groupId>Token`.
 */
const SITE_VERIFICATION_PREFIXES: readonly (readonly [string, string])[] = [
  ["google", "google-site-verification="],
  ["facebook", "facebook-domain-verification="],
  ["microsoft", "MS="],
  ["apple", "apple-domain-verification="],
  ["atlassian", "atlassian-domain-verification="],
  ["docusign", "docusign="],
  ["adobe", "adobe-idp-site-verification="],
  ["globalsign", "globalsign-domain-verification="],
  ["openai", "openai-domain-verification="],
  ["pinterest", "pinterest-site-verification="],
];

/**
 * How many slots of each kind `dns-records` declares. Part of the published
 * template: changing a count is a new template `version`, re-reviewed by every
 * provider, so these are deliberately generous (an Amazon SES setup is 1 MX +
 * 1 SPF + 3 DKIM CNAMEs + 1 DMARC; a site with four A records + www is 5).
 */
export const DNS_RECORDS_SLOT_COUNTS = {
  spf: 2,
  txtr: 4,
  txt: 8,
  a: 8,
  aaaa: 4,
  cname: 16,
  mx: 5,
  srv: 4,
  ns: 4,
  caa: 2,
} as const;

/** `count` numbered slot names: `slotNames("a", 3)` → `["a1", "a2", "a3"]`. */
function slotNames(prefix: string, count: number): string[] {
  return Array.from({ length: count }, (_, i) => `${prefix}${i + 1}`);
}

/**
 * A slot's number as a word (`mx2` → `two`), for the variables that fill a
 * NUMERIC field (MX/SRV priority, SRV weight and port). The Domain Connect
 * Online Editor's validator accepts such a field as `oneOf` [a `%variable%`
 * string, a string matching an UNANCHORED `\d`], so a variable whose name
 * holds a digit (`%mx1priority%`) matches both branches and the whole template
 * is rejected (found 2026-10-27). The TTL is fixed for the same reason: a
 * variable TTL per slot would need 55 more such names.
 */
const SLOT_NUMBER_WORDS = ["one", "two", "three", "four", "five", "six", "seven", "eight"];
function slotNumberWord(name: string): string {
  const word = SLOT_NUMBER_WORDS[Number(/\d+$/.exec(name)?.[0]) - 1];
  if (word === undefined) throw new Error(`dns-records slot ${name} has no number word`);
  return word;
}

/** One `dns-records` slot: its own group and a whole-variable host and value,
 * `<slot>host` and `<slot>value` (`<slot>rules` for SPF), written at
 * `DOMAIN_CONNECT_TEMPLATE_TTL`. A session record type is written as itself;
 * SPF (session TXT → SPFM) and the types no session carries
 * (`sessionType: null`) name both sides through `extra`. */
function slot(
  name: string,
  type: RecordType | null,
  extra: Partial<DomainConnectTemplateRecordShape> = {},
): DomainConnectTemplateRecordShape {
  const templateType = extra.templateType ?? type;
  if (templateType === null) {
    throw new Error(`dns-records slot ${name} names no template record type`);
  }
  return {
    sessionType: type,
    templateType,
    groupId: name,
    host: `%${name}host%`,
    value: { kind: "whole", variable: `${name}value` },
    optional: true,
    ...extra,
  };
}

/**
 * The `dns-records` slots, in the order the matcher fills them. Specific slots
 * come first (SPF, then the replace-only TXT kinds), but the TXT kinds are
 * disjoint anyway, so a greedy fill can never strand a record a later slot
 * would have taken.
 */
const DNS_RECORDS_SLOTS: readonly DomainConnectTemplateRecordShape[] = [
  ...slotNames("spf", DNS_RECORDS_SLOT_COUNTS.spf).map((n) =>
    slot(n, "TXT", { templateType: "SPFM", value: { kind: "spf-terms", variable: `${n}rules` } }),
  ),
  ...slotNames("txtr", DNS_RECORDS_SLOT_COUNTS.txtr).map((n) =>
    slot(n, "TXT", {
      txtRole: "replace",
      txtConflictMatchingMode: "All",
      // DMARC policies, MTA-STS ids and DKIM keys get re-tuned or rotated by
      // the owner; that must not read as the whole instance being broken.
      essential: "OnApply",
    }),
  ),
  ...slotNames("txt", DNS_RECORDS_SLOT_COUNTS.txt).map((n) =>
    slot(n, "TXT", { txtRole: "add", txtConflictMatchingMode: "None" }),
  ),
  ...slotNames("a", DNS_RECORDS_SLOT_COUNTS.a).map((n) => slot(n, "A")),
  ...slotNames("aaaa", DNS_RECORDS_SLOT_COUNTS.aaaa).map((n) => slot(n, "AAAA")),
  ...slotNames("cname", DNS_RECORDS_SLOT_COUNTS.cname).map((n) => slot(n, "CNAME")),
  ...slotNames("mx", DNS_RECORDS_SLOT_COUNTS.mx).map((n) =>
    slot(n, "MX", { priority: { variable: `mx${slotNumberWord(n)}priority` } }),
  ),
  ...slotNames("srv", DNS_RECORDS_SLOT_COUNTS.srv).map((n) =>
    slot(n, null, {
      templateType: "SRV",
      srv: {
        service: `${n}service`,
        protocol: `${n}protocol`,
        priority: `srv${slotNumberWord(n)}priority`,
        weight: `srv${slotNumberWord(n)}weight`,
        port: `srv${slotNumberWord(n)}port`,
      },
    }),
  ),
  ...slotNames("ns", DNS_RECORDS_SLOT_COUNTS.ns).map((n) => slot(n, null, { templateType: "NS" })),
  ...slotNames("caa", DNS_RECORDS_SLOT_COUNTS.caa).map((n) =>
    // A CAA policy is the owner's to tighten later (OnApply), like DMARC.
    slot(n, null, { templateType: "CAA", essential: "OnApply" }),
  ),
];

/**
 * The templates DoDomain publishes, in the order `compileToRecipe` tries them.
 *
 * ORDER IS LOAD-BEARING where two templates could both accept a record set:
 * `email-authentication` sits before `custom-subdomain-cname` because a CNAME at
 * `<selector>._domainkey` is a DKIM record by definition (RFC 6376 §3.6.2.1),
 * and the DKIM template is the one whose merged SPF / conflict rules a provider
 * reviewed for that shape. The purpose-scoped family and `dns-records` come
 * after the five merged templates on purpose: they accept supersets of what
 * those take (a lone DMARC fills `email-sending` too), and a record set a
 * merged, provider-served template already takes must keep going there. The
 * registry test proves each template's canonical record set compiles to
 * itself.
 *
 * The two ORIGINAL templates (`custom-subdomain-cname`, `domain-verification`)
 * are merged upstream (Domain-Connect/Templates#1436) and served by several
 * providers (the live, probed list is docs/domain-connect/provider-watch.json):
 * their serviceIds, hosts and variable names are frozen — see the rules in
 * .claude/rules/domain-connect-tier2.md.
 */
export const DOMAIN_CONNECT_TEMPLATES = [
  // ── email authentication: SPF merge + one DKIM selector + DMARC, no MX ────
  // FIRST on purpose (see the order note above): a lone CNAME at
  // `<selector>._domainkey` must land here, not on custom-subdomain-cname.
  // MX is deliberately NOT here (v1): a wrong MX write black-holes a domain's
  // mail, and nothing in a connect session lets DoDomain know the domain's
  // current mail routing well enough to touch it. Templates README explains.
  {
    serviceId: "email-authentication",
    hostRequired: false,
    records: [
      {
        sessionType: "TXT",
        templateType: "SPFM",
        groupId: "spf",
        host: "@",
        value: { kind: "spf-include", variable: "spfInclude" },
        optional: true,
      },
      {
        sessionType: "CNAME",
        templateType: "CNAME",
        groupId: "dkim-cname",
        host: "%dkimSelector%._domainkey",
        value: { kind: "whole", variable: "dkimTarget" },
        optional: true,
      },
      {
        sessionType: "TXT",
        templateType: "TXT",
        groupId: "dkim-txt",
        host: "%dkimSelector%._domainkey",
        value: { kind: "prefixed", prefix: "v=DKIM1; ", variable: "dkimTxt" },
        optional: true,
        txtConflictMatchingMode: "All",
      },
      {
        sessionType: "TXT",
        templateType: "TXT",
        groupId: "dmarc",
        host: "_dmarc",
        value: { kind: "prefixed", prefix: "v=DMARC1; ", variable: "dmarcTxt" },
        optional: true,
        txtConflictMatchingMode: "All",
        // The one record here the owner tunes afterwards (p=none → p=quarantine
        // → p=reject, rua=, pct=), and SPF + DKIM keep authorising mail without
        // it. Under the implicit `Always` a provider could read that ordinary
        // hardening as the template having been broken.
        essential: "OnApply",
      },
    ],
  },
  // ── one non-apex CNAME (frozen; live on Domain Chief / Glauca / Cloudflare) ──
  {
    serviceId: "custom-subdomain-cname",
    hostRequired: true,
    records: [
      {
        sessionType: "CNAME",
        templateType: "CNAME",
        groupId: "connect",
        host: "@",
        value: { kind: "whole", variable: "target" },
      },
    ],
  },
  // ── one ownership TXT at the fixed host (frozen; live on the same three) ──
  {
    serviceId: "domain-verification",
    hostRequired: false,
    records: [VERIFICATION_TXT_SHAPE],
  },
  // ── the production pattern: one non-apex CNAME + the ownership TXT UNDER it ──
  // hostRequired, so BOTH records hang off `<host>.<zone>`: the CNAME at the
  // host itself and the TXT at `_dodomain-challenge.<host>.<zone>` (a session
  // on `status.example.com` with TXT host `_dodomain-challenge`). The
  // apex-level ownership TXT stays `domain-verification`'s job.
  {
    serviceId: "custom-subdomain-cname-with-verification",
    hostRequired: true,
    records: [
      {
        sessionType: "CNAME",
        templateType: "CNAME",
        groupId: "connect",
        host: "@",
        value: { kind: "whole", variable: "target" },
      },
      VERIFICATION_TXT_SHAPE,
    ],
  },
  // ── apex: A (+ optional AAAA) at the zone root + the ownership TXT ─────────
  // Never a CNAME at the apex (RFC 1034 §3.6.2; Cloudflare's Domain Connect
  // additionally refuses APEXCNAME outright — docs/apex-domains). Tier 1 (the
  // Cloudflare OAuth connector) writes apex records directly and stays the more
  // capable path for Cloudflare zones.
  {
    serviceId: "apex-a-with-verification",
    hostRequired: false,
    records: [
      {
        sessionType: "A",
        templateType: "A",
        groupId: "apex-a",
        host: "@",
        value: { kind: "whole", variable: "ipv4" },
      },
      {
        sessionType: "AAAA",
        templateType: "AAAA",
        groupId: "apex-aaaa",
        host: "@",
        value: { kind: "whole", variable: "ipv6" },
        optional: true,
      },
      VERIFICATION_TXT_SHAPE,
    ],
  },
  // ── the purpose-scoped family (2026-10-29) ────────────────────────────────
  // Domain-Connect/Templates rejected `dns-records` as a "god template"
  // (#2645, 2026-10-29), so the record sets it carried for most integrators
  // get templates with FIXED hosts here; only the values are variables. All
  // four sit after the five merged templates (which keep every record set
  // they already take) and before `dns-records`.
  //
  // Email sending, the whole set in ONE apply: SPF, up to three DKIM CNAMEs
  // (Amazon SES style) or one DKIM key TXT, DMARC, and the MAIL FROM (bounce)
  // subdomain's MX + SPF. That MX is the only MX a shaped template writes:
  // `subdomainHost` keeps it off the root, so it never touches inbound mail,
  // and the MX and the SPF share one host variable, so they always land on the
  // same name (precedents: resend.com.mail-send-and-receive-forge,
  // mailbluster.com.sender-verification-ses).
  {
    serviceId: "email-sending",
    hostRequired: false,
    // Two integrations (a bounce subdomain and selectors each) are two
    // instances on one domain; neither apply may remove the other's records.
    multiInstance: true,
    sharedProviderName: true,
    prepared: true,
    records: [
      {
        sessionType: "TXT",
        templateType: "SPFM",
        groupId: "spf",
        host: "@",
        value: { kind: "spf-include", variable: "spfInclude" },
        optional: true,
      },
      ...(["1", "2", "3"] as const).map((n): DomainConnectTemplateRecordShape => ({
        sessionType: "CNAME",
        templateType: "CNAME",
        groupId: `dkim-cname-${n}`,
        host: `%dkimSelector${n}%._domainkey`,
        value: { kind: "whole", variable: `dkimTarget${n}` },
        optional: true,
      })),
      {
        sessionType: "TXT",
        templateType: "TXT",
        groupId: "dkim-txt",
        host: "%dkimTxtSelector%._domainkey",
        value: { kind: "whole", variable: "dkimTxt" },
        optional: true,
        // Conflict mode All deletes whatever TXT sits at the selector, so only
        // a real DKIM key may fill it; a site-verification token there falls
        // through to an additive slot instead of replacing the owner's key.
        txtRole: "dkim-key",
        txtConflictMatchingMode: "All",
      },
      {
        sessionType: "TXT",
        templateType: "TXT",
        groupId: "dmarc",
        host: "_dmarc",
        value: { kind: "prefixed", prefix: "v=DMARC1; ", variable: "dmarcTxt" },
        optional: true,
        txtConflictMatchingMode: "Prefix",
        txtConflictMatchingPrefix: "v=DMARC1",
        essential: "OnApply",
      },
      {
        sessionType: "MX",
        templateType: "MX",
        groupId: "mail-from-mx",
        host: "%mailFromHost%",
        subdomainHost: true,
        value: { kind: "whole", variable: "mailFromMx" },
        priority: { variable: "mailFromPriority" },
        optional: true,
      },
      {
        sessionType: "TXT",
        templateType: "SPFM",
        groupId: "mail-from-spf",
        host: "%mailFromHost%",
        subdomainHost: true,
        value: { kind: "spf-include", variable: "mailFromSpfInclude" },
        optional: true,
      },
    ],
  },
  // A website: up to four A and two AAAA at the root, `www`, a wildcard, the
  // `_acme-challenge` CNAME a host uses to issue the site's certificate, and
  // the ownership TXT. `appliesUnderHost`, so the same set works for a site
  // on `shop.<zone>`. The wildcard and the ACME CNAME live here, not in
  // templates of their own: alone, either is one CNAME that
  // `custom-subdomain-cname` already applies at that host.
  {
    serviceId: "website",
    hostRequired: false,
    appliesUnderHost: true,
    sharedProviderName: true,
    prepared: true,
    records: [
      ...(["a", "b", "c", "d"] as const).map((n): DomainConnectTemplateRecordShape => ({
        sessionType: "A",
        templateType: "A",
        groupId: `a-${n}`,
        host: "@",
        value: { kind: "whole", variable: `ipv4${n}` },
        optional: true,
      })),
      ...(["a", "b"] as const).map((n): DomainConnectTemplateRecordShape => ({
        sessionType: "AAAA",
        templateType: "AAAA",
        groupId: `aaaa-${n}`,
        host: "@",
        value: { kind: "whole", variable: `ipv6${n}` },
        optional: true,
      })),
      {
        sessionType: "CNAME",
        templateType: "CNAME",
        groupId: "www",
        host: "www",
        value: { kind: "whole", variable: "wwwTarget" },
        optional: true,
      },
      {
        sessionType: "CNAME",
        templateType: "CNAME",
        groupId: "wildcard",
        host: "*",
        value: { kind: "whole", variable: "wildcardTarget" },
        optional: true,
      },
      {
        sessionType: "CNAME",
        templateType: "CNAME",
        groupId: "acme-challenge",
        host: "_acme-challenge",
        value: { kind: "whole", variable: "acmeTarget" },
        optional: true,
      },
      { ...VERIFICATION_TXT_SHAPE, optional: true },
    ],
  },
  // Third-party ownership tokens at the root, one group per FIXED vendor
  // prefix. Conflict mode None: a domain often carries several tokens of one
  // vendor (two Search Console owners), and replacing one would un-verify
  // someone else.
  {
    serviceId: "site-verification",
    hostRequired: false,
    // Successive ownership tokens are separate instances, not a re-apply of
    // the first.
    multiInstance: true,
    sharedProviderName: true,
    prepared: true,
    records: SITE_VERIFICATION_PREFIXES.map(
      ([groupId, prefix]): DomainConnectTemplateRecordShape => ({
        sessionType: "TXT",
        templateType: "TXT",
        groupId,
        host: "@",
        value: { kind: "prefixed", prefix, variable: `${groupId}Token` },
        optional: true,
        txtConflictMatchingMode: "None",
      }),
    ),
  },
  // Which certificate authority may issue for the domain.
  // TODO(scope): no session record carries CAA yet (record-capabilities.ts),
  // so the matcher never compiles to this template; it is declared so it can
  // be reviewed and onboarded once — docs/domain-connect/templates/README.md.
  {
    serviceId: "caa",
    hostRequired: false,
    sharedProviderName: true,
    prepared: true,
    records: (["issue", "issuewild"] as const).map((tag): DomainConnectTemplateRecordShape => ({
      sessionType: null,
      templateType: "CAA",
      groupId: tag,
      host: "@",
      value: { kind: "prefixed", prefix: `0 ${tag} "`, variable: "caDomain", suffix: '"' },
      optional: true,
      // A CAA policy is the owner's to tighten later, like DMARC.
      essential: "OnApply",
    })),
  },
  // ── any record set: typed slots, each its own group, host + value variable ──
  // LAST on purpose: every record set one of the shaped templates above
  // expresses still compiles to that template, whose narrower review those
  // providers already gave; this one takes only what nothing above can say
  // (several subdomains, inbound MX, ...).
  // Record TYPES stay fixed per slot (the spec forbids a variable type).
  {
    serviceId: "dns-records",
    hostRequired: false,
    multiInstance: true,
    // DIRECT ONBOARDING ONLY, for good: Domain-Connect/Templates closed #2645
    // on 2026-10-29 (the registry takes no "god templates"), so a provider
    // serves it only when onboarded by hand (GoDaddy has the file). It stays
    // `prepared`, out of the provider watch and the public verdicts.
    prepared: true,
    records: DNS_RECORDS_SLOTS,
  },
] as const satisfies readonly DomainConnectTemplate[];

/** Every serviceId in the registry, as a type DERIVED from the data above —
 * `CompiledRecipe.serviceId` and apps/web's preflight matrix are keyed on it,
 * so adding a template fails every consumer that has not caught up. */
export type DomainConnectServiceId = (typeof DOMAIN_CONNECT_TEMPLATES)[number]["serviceId"];

/**
 * The serviceIds marked `prepared` (not yet submitted, served nowhere). The
 * provider watch, the public provider verdicts and the preflight's one-click
 * coverage judge only the OTHER templates: counting a template no provider can
 * serve yet would read as every provider losing coverage the day it was added.
 */
export const PREPARED_SERVICE_IDS: ReadonlySet<string> = new Set(
  (DOMAIN_CONNECT_TEMPLATES as readonly DomainConnectTemplate[])
    .filter((template) => template.prepared === true)
    .map((template) => template.serviceId),
);

/** The registry entry for a serviceId. Throws on an unknown id — every caller
 * holds a `DomainConnectServiceId`, so a miss is a programming error. */
export function domainConnectTemplate(serviceId: DomainConnectServiceId): DomainConnectTemplate {
  const template = DOMAIN_CONNECT_TEMPLATES.find((t) => t.serviceId === serviceId);
  if (!template) throw new Error(`unknown Domain Connect template "${serviceId}"`);
  return template;
}

// ── DNS-provider variants: the same template, a variable renamed ───────────
//
// GoDaddy's Domain Connect signature check RESERVES the query parameter name
// `token`, so it refuses every apply of the three templates that carry the
// ownership TXT `dodomain-verify=%token%` (refused live on 2026-11-03/04/06;
// `custom-subdomain-cname` and `email-authentication`, which carry no
// `token`, were proven there on 2026-11-04 and 2026-11-06). GoDaddy (VJ,
// 2026-11-09) confirmed `verification` is NOT reserved.
//
// The five originals are live at Cloudflare, Glauca, Vercel, Domain Chief,
// NameSilo, Simply.com and Danego DNS and stay byte-for-byte unchanged (owner
// ruling, T-15462). Instead each `token` template gets a `-v2` SIBLING, its
// own serviceId at `version: 1` (the Templates-repo convention for a sibling:
// canva.com.website-v2, domainconnect.org.dynamicdns-v2), identical to the
// original except that `token` is named `verification`. A sibling is not in
// DOMAIN_CONNECT_TEMPLATES on purpose: the matcher compiles to the ORIGINAL,
// every API surface keys on the original's serviceId, and only the hop that
// talks to a DNS provider (`templateServiceIdForDnsProvider` for the support
// probe, `templateApplyForDnsProvider` for the apply URL) swaps in the sibling
// for a provider listed in TEMPLATE_VARIANTS_BY_DNS_PROVIDER below. The
// JSON-twin lockstep test covers the siblings too, and proves each one differs
// from its original ONLY in that variable's name.

/** A sibling of a registry template that differs only in variable NAMES. */
export interface DomainConnectTemplateVariant extends DomainConnectTemplate {
  /** The registry template it is a sibling of. */
  variantOf: DomainConnectServiceId;
  /** Original variable name → the name this sibling uses for it. */
  renamedVariables: Readonly<Record<string, string>>;
}

/** The original with every `renamedVariables` key renamed in its records.
 * Only a record VALUE (or MX priority) variable may be renamed: a host or SRV
 * variable is part of how the matcher reads a session record, and no sibling
 * needs one renamed, so asking for it throws. */
function templateVariant(
  variantOf: DomainConnectServiceId,
  serviceId: string,
  renamedVariables: Readonly<Record<string, string>>,
): DomainConnectTemplateVariant {
  const original = domainConnectTemplate(variantOf);
  const rename = (name: string): string => renamedVariables[name] ?? name;
  for (const from of Object.keys(renamedVariables)) {
    if (!templateVariableNames(original).includes(from)) {
      throw new Error(`template ${variantOf} has no variable "${from}" to rename`);
    }
    for (const shape of original.records) {
      if (hostVariableOf(shape.host) === from || shape.srv !== undefined) {
        throw new Error(`template ${variantOf}: only value variables can be renamed ("${from}")`);
      }
    }
  }
  return {
    ...original,
    serviceId,
    variantOf,
    renamedVariables,
    records: original.records.map((shape) => ({
      ...shape,
      value: { ...shape.value, variable: rename(shape.value.variable) },
      ...(shape.priority !== undefined
        ? { priority: { variable: rename(shape.priority.variable) } }
        : {}),
    })),
  };
}

/** GoDaddy reserves `token` (see the section header). */
const TOKEN_TO_VERIFICATION: Readonly<Record<string, string>> = { token: "verification" };

/** Every DNS-provider sibling, each the in-code twin of its own JSON file in
 * docs/domain-connect/templates/ (never submitted to Domain-Connect/Templates:
 * a sibling is onboarded directly by the provider that needs it). */
export const DOMAIN_CONNECT_TEMPLATE_VARIANTS: readonly DomainConnectTemplateVariant[] = [
  templateVariant("domain-verification", "domain-verification-v2", TOKEN_TO_VERIFICATION),
  templateVariant(
    "custom-subdomain-cname-with-verification",
    "custom-subdomain-cname-with-verification-v2",
    TOKEN_TO_VERIFICATION,
  ),
  templateVariant("apex-a-with-verification", "apex-a-with-verification-v2", TOKEN_TO_VERIFICATION),
];

/**
 * THE one home for "which template does THIS DNS provider get instead of the
 * one the matcher compiled to". Keyed by the `providerId` in the provider's OWN
 * settings JSON (discovery.ts `parseSettings`), like applyUrl.ts's emission
 * order and discovery.ts's refusal table; values are sibling serviceIds from
 * DOMAIN_CONNECT_TEMPLATE_VARIANTS. A provider not listed gets the originals.
 *
 * TODO(scope): GoDaddy's reseller platform (domainconnect.api.secureserver.net)
 * runs the same software but publishes its own settings `providerId`, which we
 * have not read (no reseller-hosted zone), so a reseller zone still gets the
 * `token` originals. Add its providerId here once known (discovery.ts carries
 * the same caveat for the refusal table).
 */
const TEMPLATE_VARIANTS_BY_DNS_PROVIDER: Readonly<Record<string, readonly string[]>> = {
  "godaddy.com": [
    "domain-verification-v2",
    "custom-subdomain-cname-with-verification-v2",
    "apex-a-with-verification-v2",
  ],
};

/** The sibling this DNS provider gets for a registry template, or undefined
 * when it gets the original. Pure lookup, no env, no I/O. */
export function templateVariantForDnsProvider(
  dnsProviderId: string,
  serviceId: string,
): DomainConnectTemplateVariant | undefined {
  const variantIds = TEMPLATE_VARIANTS_BY_DNS_PROVIDER[dnsProviderId.trim().toLowerCase()];
  if (variantIds === undefined) return undefined;
  return DOMAIN_CONNECT_TEMPLATE_VARIANTS.find(
    (variant) => variant.variantOf === serviceId && variantIds.includes(variant.serviceId),
  );
}

/** The serviceId to PROBE and APPLY at this DNS provider for a registry
 * template: its sibling's when it has one, the template's own otherwise. */
export function templateServiceIdForDnsProvider(dnsProviderId: string, serviceId: string): string {
  return templateVariantForDnsProvider(dnsProviderId, serviceId)?.serviceId ?? serviceId;
}

/**
 * A compiled recipe's serviceId and variables as THIS DNS provider must
 * receive them. Variable ORDER is kept (it is the signed payload's order; the
 * signature itself always covers whatever names are sent), only names move.
 * Throws when the recipe lacks a variable the sibling renames, or already
 * carries the new name: either is a recipe that no longer fits the sibling.
 */
export function templateApplyForDnsProvider(
  dnsProviderId: string,
  recipe: { serviceId: string; variables: Readonly<Record<string, string>> },
): { serviceId: string; variables: Record<string, string> } {
  const variant = templateVariantForDnsProvider(dnsProviderId, recipe.serviceId);
  if (variant === undefined)
    return { serviceId: recipe.serviceId, variables: { ...recipe.variables } };
  for (const [from, to] of Object.entries(variant.renamedVariables)) {
    if (!(from in recipe.variables)) {
      throw new Error(`${recipe.serviceId} recipe has no "${from}" for ${variant.serviceId}`);
    }
    if (to in recipe.variables) {
      throw new Error(`${recipe.serviceId} recipe already carries "${to}" (${variant.serviceId})`);
    }
  }
  return {
    serviceId: variant.serviceId,
    variables: Object.fromEntries(
      Object.entries(recipe.variables).map(([name, value]) => [
        variant.renamedVariables[name] ?? name,
        value,
      ]),
    ),
  };
}

/** The session record types a template can write (deduplicated, registry order). */
export function templateSessionRecordTypes(template: DomainConnectTemplate): RecordType[] {
  return [
    ...new Set(
      template.records
        .map((r) => r.sessionType)
        .filter((type): type is RecordType => type !== null),
    ),
  ];
}

/** The variable a shape's host carries, when it carries one: a leading label
 * (`%dkimSelector%._domainkey`) or the whole host (`%a1host%`). */
export function hostVariableOf(host: string): string | undefined {
  return /^%([A-Za-z0-9]+)%(?:\.|$)/.exec(host)?.[1];
}

/** Every variable name a template declares (registry order, deduplicated —
 * the two DKIM shapes share `dkimSelector`). */
export function templateVariableNames(template: DomainConnectTemplate): string[] {
  const names: string[] = [];
  const add = (name: string | undefined) => {
    if (name !== undefined && !names.includes(name)) names.push(name);
  };
  for (const shape of template.records) {
    add(hostVariableOf(shape.host));
    if (shape.srv !== undefined) {
      add(shape.srv.service);
      add(shape.srv.protocol);
      add(shape.srv.priority);
      add(shape.srv.weight);
      add(shape.srv.port);
    }
    add(shape.value.variable);
    add(shape.priority?.variable);
  }
  return names;
}

/** One record as the Domain-Connect/Templates JSON spells it. Keys follow the
 * registry's own field order (type, groupId, host, value, ttl, conflict). */
export type RenderedTemplateRecord = Record<string, string | number>;

/**
 * The `records` array of a template's JSON file, rendered FROM the registry.
 * test/domain-connect-templates.test.ts asserts this equals the committed file,
 * so the JSON can never carry a host, variable or group the matcher does not
 * know about (or the reverse).
 */
export function renderTemplateRecords(template: DomainConnectTemplate): RenderedTemplateRecord[] {
  return template.records.map((shape) => {
    const rendered: RenderedTemplateRecord = { type: shape.templateType, groupId: shape.groupId };
    const variable = `%${shape.value.variable}%`;
    if (shape.templateType === "SRV") {
      // SRV spells its host `name` and its value `target`; the provider builds
      // the owner name `_<service>._<protocol>.<name>` from the fields.
      if (shape.srv === undefined) throw new Error(`SRV shape ${shape.groupId} has no srv fields`);
      rendered.name = shape.host;
      rendered.service = `%${shape.srv.service}%`;
      rendered.protocol = `%${shape.srv.protocol}%`;
      rendered.priority = `%${shape.srv.priority}%`;
      rendered.weight = `%${shape.srv.weight}%`;
      rendered.port = `%${shape.srv.port}%`;
      rendered.target = variable;
      rendered.ttl = DOMAIN_CONNECT_TEMPLATE_TTL;
      return rendered;
    }
    rendered.host = shape.host;
    if (shape.templateType === "SPFM") {
      // spfRules = "everything but the leading v=spf1 and the trailing all"
      // (spec) — one include mechanism for email-authentication, every term
      // for the dns-records slots.
      rendered.spfRules = shape.value.kind === "spf-include" ? `include:${variable}` : variable;
      return rendered; // SPFM carries no ttl: the provider owns the merged TXT
    }
    if (shape.templateType === "TXT" || shape.templateType === "CAA") {
      rendered.data =
        shape.value.kind === "prefixed"
          ? `${shape.value.prefix}${variable}${shape.value.suffix ?? ""}`
          : variable;
    } else {
      rendered.pointsTo = variable;
    }
    if (shape.priority !== undefined) rendered.priority = `%${shape.priority.variable}%`;
    rendered.ttl = DOMAIN_CONNECT_TEMPLATE_TTL;
    if (shape.txtConflictMatchingMode !== undefined) {
      rendered.txtConflictMatchingMode = shape.txtConflictMatchingMode;
    }
    if (shape.txtConflictMatchingPrefix !== undefined) {
      rendered.txtConflictMatchingPrefix = shape.txtConflictMatchingPrefix;
    }
    if (shape.essential !== undefined) {
      rendered.essential = shape.essential;
    }
    return rendered;
  });
}
