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

/** The record types the JSON templates are written in. Identical to the session
 * record types except for SPF, which Domain Connect expresses as `SPFM` — the
 * merge pseudo-type a provider folds into the zone's existing `v=spf1` TXT
 * (spec §"SPFM"), never as a second SPF TXT. */
export type DomainConnectTemplateRecordType = RecordType | "SPFM";

/**
 * How a session record's VALUE becomes the template's variable(s).
 *
 *   - `whole`     the entire value is the variable (a CNAME target, an address).
 *   - `prefixed`  the value MUST start with `prefix`; the remainder is the
 *                 variable. The prefix is byte-exact on purpose: the provider
 *                 writes `prefix + variable`, and verification compares TXT
 *                 values exactly, so a session whose value spells the prefix
 *                 differently ("v=DKIM1;k=…" with no space) could be applied but
 *                 would never verify — it is refused here instead.
 *   - `spf-include` the value is a complete SPF record carrying exactly ONE
 *                 `include:` mechanism and nothing else (`v=spf1 include:<host>
 *                 <q>all`); `<host>` is the variable. v1 constraint, so a
 *                 provider's template review sees a bounded merge rule, and so
 *                 the merged result stays verifiable (email-records.ts).
 */
export type TemplateValueRule =
  | { kind: "whole"; variable: string }
  | { kind: "prefixed"; prefix: string; variable: string }
  | { kind: "spf-include"; variable: string };

export interface DomainConnectTemplateRecordShape {
  /** The type the SESSION record carries (what the verifier checks). */
  sessionType: RecordType;
  /** The type written in the template JSON — differs from `sessionType` only
   * for SPF (`SPFM`). */
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
   * anchors on; the leading label becomes the variable.
   */
  host: string;
  value: TemplateValueRule;
  /** A shape the session may omit; omitted ⇒ its groupId is not applied. */
  optional?: boolean;
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
   * re-tunes afterwards — today that is DMARC alone (the Templates-repo quality
   * checklist names it as the example). Every other record DoDomain writes IS
   * the service: removing it is disconnecting, so the implicit `Always` is
   * correct and stays absent from the JSON.
   */
  essential?: "OnApply";
}

export interface DomainConnectTemplate {
  serviceId: string;
  /** `true` ⇒ the apply carries `host=` and every record host is relative to
   * `<host>.<zone>`. The template MUST be true when a CNAME sits at `@`. */
  hostRequired: boolean;
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
 * The templates DoDomain publishes, in the order `compileToRecipe` tries them.
 *
 * ORDER IS LOAD-BEARING where two templates could both accept a record set:
 * `email-authentication` sits before `custom-subdomain-cname` because a CNAME at
 * `<selector>._domainkey` is a DKIM record by definition (RFC 6376 §3.6.2.1),
 * and the DKIM template is the one whose merged SPF / conflict rules a provider
 * reviewed for that shape. Every other pair is disjoint by construction (the
 * registry test proves each template's canonical record set matches exactly
 * one entry).
 *
 * The two ORIGINAL templates (`custom-subdomain-cname`, `domain-verification`)
 * are merged upstream (Domain-Connect/Templates#1436) and live on three
 * providers: their serviceIds, hosts and variable names are frozen — see the
 * rules in .claude/rules/domain-connect-tier2.md.
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
] as const satisfies readonly DomainConnectTemplate[];

/** Every serviceId in the registry, as a type DERIVED from the data above —
 * `CompiledRecipe.serviceId` and apps/web's preflight matrix are keyed on it,
 * so adding a template fails every consumer that has not caught up. */
export type DomainConnectServiceId = (typeof DOMAIN_CONNECT_TEMPLATES)[number]["serviceId"];

/** The registry entry for a serviceId. Throws on an unknown id — every caller
 * holds a `DomainConnectServiceId`, so a miss is a programming error. */
export function domainConnectTemplate(serviceId: DomainConnectServiceId): DomainConnectTemplate {
  const template = DOMAIN_CONNECT_TEMPLATES.find((t) => t.serviceId === serviceId);
  if (!template) throw new Error(`unknown Domain Connect template "${serviceId}"`);
  return template;
}

/** The session record types a template can write (deduplicated, registry order). */
export function templateSessionRecordTypes(template: DomainConnectTemplate): RecordType[] {
  return [...new Set(template.records.map((r) => r.sessionType))];
}

/** Every variable name a template declares (registry order, deduplicated —
 * the two DKIM shapes share `dkimSelector`). */
export function templateVariableNames(template: DomainConnectTemplate): string[] {
  const names: string[] = [];
  for (const shape of template.records) {
    const hostVariable = /^%([A-Za-z0-9]+)%\./.exec(shape.host)?.[1];
    if (hostVariable !== undefined && !names.includes(hostVariable)) names.push(hostVariable);
    if (!names.includes(shape.value.variable)) names.push(shape.value.variable);
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
    rendered.host = shape.host;
    const variable = `%${shape.value.variable}%`;
    if (shape.templateType === "SPFM") {
      // spfRules = "everything but the leading v=spf1 and the trailing all"
      // (spec) — for DoDomain, exactly one include mechanism.
      rendered.spfRules = `include:${variable}`;
      return rendered; // SPFM carries no ttl: the provider owns the merged TXT
    }
    if (shape.templateType === "TXT") {
      rendered.data =
        shape.value.kind === "prefixed" ? `${shape.value.prefix}${variable}` : variable;
    } else {
      rendered.pointsTo = variable;
    }
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
