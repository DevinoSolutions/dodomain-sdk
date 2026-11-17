// Compile a session's DNS records into ONE of DoDomain's approved Domain
// Connect templates. Domain Connect connectors do NOT accept arbitrary
// records[]: the general session API may accept records[], but for the Domain
// Connect path it must be compiled into a narrow, pre-approved template +
// variables (docs/domain-connect-findings.md §4/§5).
//
// THE MATCHER over the registry in domain-connect-templates.ts. Templates are
// DATA there (serviceId, hostRequired, the record shapes with host rules +
// variable extraction); this file finds the one template whose shape list the
// session's record set fills — order-independent, every record consumed, every
// non-optional shape filled, every variable extracted exactly once — and throws
// RecipeError for anything else, so the caller degrades to the manual / OAuth
// path. Before Stage 9 (2026-09) this was a hand-rolled two-branch function
// that accepted exactly one record; the registry is what made multi-record
// sessions (CNAME + ownership TXT, apex A/AAAA + TXT, SPF/DKIM/DMARC)
// expressible without a second matcher per template.
//
// WIRED (tier-2 build, 2026-07-11 — Amin ruled BUILD): the product callers are
// apps/web's `/api/v1/sessions/:token/domain-connect/start` route and the
// detect route's `domainConnectReady` probe (via apps/web/src/lib/domain-connect-config.ts),
// both gated behind the DODOMAIN_DOMAIN_CONNECT_ENABLED flag. `providerId` is
// an ARGUMENT: the composition root (apps/web/src/env.ts → lib/domain-connect.ts)
// validates DODOMAIN_PROVIDER_ID and passes it in — core reads NO process.env
// (D-005 discharged; scripts/check-core-config-bans.sh has zero exceptions).

import {
  DOMAIN_CONNECT_TEMPLATES,
  type DomainConnectServiceId,
  type DomainConnectTemplate,
  type DomainConnectTemplateRecordShape,
} from "./domain-connect-templates.ts";
import { parseSpfRecord, spfSoleIncludeHost } from "./email-records.ts";
import { typesTierCannotWrite } from "./record-capabilities.ts";

export const VERIFY_PREFIX = "dodomain-verify=";

// The FIXED host of the ownership TXT every "…-with-verification" template and
// `domain-verification` write, relative to the template root (the zone, or
// `<host>.<zone>` for hostRequired templates — see
// docs/domain-connect/templates/dodomain.io.domain-verification.json, which
// pins `host` itself so no apply `host` param is ever passed for that recipe).
export const VERIFY_TXT_HOST = "_dodomain-challenge";

export interface SimpleRecord {
  type: string;
  name: string; // host relative to the ZONE, or "@"
  value: string;
  ttl?: number;
  /** MX preference — only a template with a priority variable reads it. */
  priority?: number;
}

export interface CompiledRecipe {
  providerId: string;
  serviceId: DomainConnectServiceId;
  /** The apply's `host=` — present for `hostRequired` templates, and for an
   * `appliesUnderHost` template the matcher rooted at a subdomain. */
  host?: string;
  variables: Record<string, string>;
  /**
   * The template groups to apply, present only when the session fills a
   * SUBSET of the template's optional shapes (spec: "If no group is specified,
   * all groups are applied" — so a full match sends no `groupId` at all).
   */
  groupIds?: string[];
}

export class RecipeError extends Error {}

/** A shape's host is a fixed name, a leading `%variable%` label on a fixed
 * part (the ONE label the matcher extracts), or one whole `%variable%`. */
type HostPattern =
  | { kind: "fixed"; fixed: string }
  | { kind: "label"; variable: string; fixed: string }
  | { kind: "whole"; variable: string };

function splitHostPattern(host: string): HostPattern {
  const whole = /^%([A-Za-z0-9]+)%$/.exec(host);
  if (whole) return { kind: "whole", variable: whole[1]! };
  const label = /^%([A-Za-z0-9]+)%\.(.+)$/.exec(host);
  return label
    ? { kind: "label", variable: label[1]!, fixed: label[2]! }
    : { kind: "fixed", fixed: host };
}

type TxtTag = { name: string; value: string };

/**
 * The TXT's data as DNS carries it: a zone-file presentation form is one or
 * more quoted character-strings `"a" "b"`, which DNS concatenates with
 * nothing between them. A value that does not START with a quote is the raw
 * data itself: it is never parsed or balanced, and every quote inside it is a
 * literal character (a DKIM key's `n="operations"`, `n=operations"` or
 * `n=6" rack` note). Only a value that starts with a quote can have broken
 * quoting; null for one that is not a clean run of quoted strings.
 */
function txtData(value: string): string | null {
  if (!value.trimStart().startsWith('"')) return value;
  if (!/^\s*"(?:[^"\\]|\\.)*"(?:\s*"(?:[^"\\]|\\.)*")*\s*$/s.test(value)) return null;
  return [...value.matchAll(/"((?:[^"\\]|\\.)*)"/gs)]
    .map((m) => m[1]!.replace(/\\(.)/gs, "$1"))
    .join("");
}

/**
 * The COMPLETE tag list of a "tag=value; tag=value" TXT (RFC 7489 §6.3, RFC 6376
 * §3.2): whitespace around the name, the `=` and the value is allowed, tag
 * names are case-insensitive, and an empty segment (a trailing `;`) is no tag.
 * Null when ANY segment is not a tag=value pair, or the value is a quoted
 * presentation form with broken quoting (see `txtData`): a record that is not wholly a tag list is not one of the standard records,
 * and must never be mistaken for one by the tags it happens to contain.
 */
function txtTagList(value: string): TxtTag[] | null {
  const data = txtData(value);
  if (data === null) return null;
  const tags: TxtTag[] = [];
  for (const segment of data.split(";")) {
    if (segment.trim() === "") continue;
    const m = /^\s*([A-Za-z][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/s.exec(segment);
    if (m === null) return null;
    tags.push({ name: m[1]!.toLowerCase(), value: m[2]! });
  }
  return tags;
}

/** The record's version, from a well-formed tag list whose FIRST tag is `v=`
 * (every version-tagged record here must open with it, RFC 7489 §6.3). */
function txtVersion(tags: TxtTag[] | null): string | null {
  return tags?.[0]?.name === "v" ? tags[0].value : null;
}

const SINGLETON_TXT_VERSIONS = new Set(["dmarc1", "dkim1", "stsv1", "tlsrptv1"]);

/**
 * True for a TXT record its NAME may hold only one of, by the record's own
 * standard — the records a `dns-records` `replace` slot takes and an `add` slot
 * refuses (see `TxtSlotRole`): DMARC (RFC 7489), a DKIM key (RFC 6376, one key
 * per selector), MTA-STS (RFC 8461) and TLS-RPT (RFC 8460).
 *
 * Judged by the VALUE, never by the host alone: a replace slot wipes every TXT
 * at its name, so a `google-site-verification=…` token that merely sits at
 * `_dmarc` must take an `add` slot and leave the owner's DMARC policy alone.
 * The version tag decides, with the whitespace the tag-list grammar permits
 * (`v = DMARC1`); an explicit version that is none of these (`v=APP1`) is NOT a
 * singleton whatever else it carries. Only a record with no version tag at all
 * can be a DKIM key by its `p=` tag under `_domainkey` (`v=DKIM1` is only
 * recommended, RFC 6376 §3.6.1).
 */
export function isSingletonTxtRecord(name: string, value: string): boolean {
  const tags = txtTagList(value);
  if (tags === null) return false;
  const version = txtVersion(tags);
  if (version !== null) return SINGLETON_TXT_VERSIONS.has(version.toLowerCase());
  return isDkimKeyRecord(name, value);
}

/**
 * True for a DKIM key record: `v=DKIM1`, or no version tag at all with a `p=`
 * tag at a `_domainkey` name — in both cases a record that is WHOLLY a valid tag
 * list (quoted and split strings are joined first, as DNS does; a malformed
 * segment beside `p=` disqualifies it). The ONE definition `email-sending`'s
 * `dkim-txt` group (`txtRole: "dkim-key"`) shares with `isSingletonTxtRecord`, so a
 * token that merely sits at a selector name can never land in a conflict-mode
 * `All` slot.
 */
export function isDkimKeyRecord(name: string, value: string): boolean {
  const tags = txtTagList(value);
  if (tags === null) return false;
  const version = txtVersion(tags);
  if (version !== null) return version.toLowerCase() === "dkim1";
  return (
    name.toLowerCase().split(".").includes("_domainkey") &&
    !tags.some((tag) => tag.name === "v") &&
    tags.some((tag) => tag.name === "p")
  );
}

/**
 * Why an SPF value cannot be compiled, or null when every token of it is
 * expressible. `parseSpfRecord` stops at the terminal `all` (nothing after it
 * is evaluated, RFC 7208 §5.1) — but a modifier such as `exp=` is still read
 * wherever it sits, so a tail the parser drops would be dropped from the
 * applied record too. Anything the SPFM / spf-include variable cannot carry is
 * refused instead: a `redirect=` / `exp=` modifier anywhere, and any token
 * after the terminal `all`.
 */
function spfUnexpressibleReason(value: string): string | null {
  if (parseSpfRecord(value) === null) return null;
  const tokens = value.trim().split(/\s+/).slice(1);
  const modifier = tokens.find((token) => /^(redirect|exp)=/i.test(token));
  if (modifier !== undefined) {
    return `the SPF record carries "${modifier}", a modifier the SPFM merge cannot express`;
  }
  const allIndex = tokens.findIndex((token) => /^[+\-~?]?all$/i.test(token));
  if (allIndex !== -1 && allIndex < tokens.length - 1) {
    const tail = tokens.slice(allIndex + 1).join(" ");
    return `the SPF record has "${tail}" after its terminal "${tokens[allIndex]}", which the SPFM merge would drop`;
  }
  return null;
}

/** The SPFM `spfRules` an SPF record merges as: every term between `v=spf1`
 * and the terminal `all`. Null for a non-SPF value, an SPF with no terms, or
 * one `spfUnexpressibleReason` refuses. */
function spfMergeTerms(value: string): string | null {
  const record = parseSpfRecord(value);
  if (record === null || record.terms.length === 0) return null;
  if (spfUnexpressibleReason(value) !== null) return null;
  return record.terms.join(" ");
}

/** A `subdomainHost` name: not the root, and every label an ordinary hostname
 * label — no wildcard owner, no `_` anywhere (those names belong to other
 * records: `_dmarc`, `<selector>._domainkey`, `_acme-challenge`). */
function isSubdomainHost(relative: string): boolean {
  if (relative === "@") return false;
  return relative.split(".").every((label) => label !== "" && !/[*_]/.test(label));
}

interface ShapeMatch {
  variables: Record<string, string>;
}

/**
 * Does ONE session record fill ONE shape, given the template root's
 * zone-relative name (`"@"` for the zone itself, the apply host otherwise)?
 * Returns the variables the record contributes, or null.
 */
function matchShape(
  shape: DomainConnectTemplateRecordShape,
  record: SimpleRecord,
  root: string,
): ShapeMatch | null {
  // A slot no session record type can fill (dns-records' SRV / NS / CAA).
  if (shape.sessionType === null) return null;
  if (record.type.toUpperCase() !== shape.sessionType) return null;
  const variables: Record<string, string> = {};
  const name = record.name === "" ? "@" : record.name;

  // ── rules every template obeys, whatever its shapes say ──
  // A CNAME can never sit at the zone apex (RFC 1034 §3.6.2); a whole-variable
  // host could otherwise be asked to write one.
  if (shape.sessionType === "CNAME" && name === "@") return null;
  // SPF is only ever MERGED (SPFM): a v=spf1 value written as its own TXT would
  // be a second SPF record, a PermError that fails every sender (RFC 7208
  // §3.2; Templates README rule 4).
  if (shape.templateType === "TXT" && parseSpfRecord(record.value) !== null) return null;
  // A replacing TXT slot (conflict mode All or Prefix) for a version-tagged
  // record (`v=DKIM1; `, `v=DMARC1; `) takes only a record that is wholly a valid
  // tag list — the same parse the classifier uses — so a malformed DKIM or DMARC
  // value never deletes the owner's real one, whatever prefix it opens with.
  // (A non-tag-list prefix such as `dodomain-verify=` is a token, not a policy.)
  if (
    shape.templateType === "TXT" &&
    (shape.txtConflictMatchingMode === "All" || shape.txtConflictMatchingMode === "Prefix") &&
    shape.value.kind === "prefixed" &&
    /^vs*=/i.test(shape.value.prefix) &&
    txtTagList(record.value) === null
  ) {
    return null;
  }
  if (shape.txtRole !== undefined) {
    if (shape.txtRole === "dkim-key") {
      if (!isDkimKeyRecord(name, record.value)) return null;
    } else if ((shape.txtRole === "replace") !== isSingletonTxtRecord(name, record.value)) {
      return null;
    }
  }

  // ── host ──
  const pattern = splitHostPattern(shape.host);
  if (pattern.kind === "whole") {
    // The record's name relative to the template root, "@" for the root.
    let relative: string;
    if (root === "@") relative = name;
    else if (name === root) relative = "@";
    else if (name.endsWith(`.${root}`)) relative = name.slice(0, -(root.length + 1));
    else return null;
    // A MAIL FROM-style host: a real subdomain, never the root, and no label
    // of it a wildcard or an underscore name (`*`, `_dmarc`, `bounce._domainkey`).
    if (shape.subdomainHost === true && !isSubdomainHost(relative)) return null;
    variables[pattern.variable] = relative;
  } else {
    // The shape host, re-based onto the template root.
    const { fixed } = pattern;
    const expectedFixed = fixed === "@" ? root : root === "@" ? fixed : `${fixed}.${root}`;
    if (pattern.kind === "fixed") {
      if (name !== expectedFixed) return null;
    } else {
      // `<label>.<fixed>[.<root>]` — exactly one leading label is the variable.
      const suffix = `.${expectedFixed}`;
      if (!name.endsWith(suffix)) return null;
      const label = name.slice(0, -suffix.length);
      if (label === "" || label.includes(".") || label === "@") return null;
      variables[pattern.variable] = label;
    }
  }

  // ── value ──
  const rule = shape.value;
  if (rule.kind === "whole") {
    if (record.value === "") return null;
    variables[rule.variable] = record.value;
  } else if (rule.kind === "prefixed") {
    const suffix = rule.suffix ?? "";
    if (
      !record.value.startsWith(rule.prefix) ||
      !record.value.endsWith(suffix) ||
      record.value.length <= rule.prefix.length + suffix.length
    ) {
      return null;
    }
    variables[rule.variable] = record.value.slice(
      rule.prefix.length,
      record.value.length - suffix.length,
    );
  } else if (rule.kind === "spf-include") {
    const include = spfSoleIncludeHost(record.value);
    if (include === null) return null;
    variables[rule.variable] = include;
  } else {
    const terms = spfMergeTerms(record.value);
    if (terms === null) return null;
    variables[rule.variable] = terms;
  }

  // ── MX priority, when the template carries it as a variable ──
  if (shape.priority !== undefined) {
    if (record.priority === undefined) return null;
    variables[shape.priority.variable] = String(record.priority);
  }
  return { variables };
}

/**
 * Try to fill a template with the whole record set. Every record must land on
 * exactly one shape, every non-optional shape must be filled, and a variable
 * two records both contribute (the DKIM selector) must agree.
 */
function matchTemplate(
  template: DomainConnectTemplate,
  records: SimpleRecord[],
  root: string,
): Omit<CompiledRecipe, "providerId" | "serviceId"> | null {
  const consumed = new Set<number>();
  const variables: Record<string, string> = {};
  for (const record of records) {
    let placed = false;
    for (const [i, shape] of template.records.entries()) {
      if (consumed.has(i)) continue;
      const match = matchShape(shape, record, root);
      if (match === null) continue;
      for (const [k, v] of Object.entries(match.variables)) {
        if (variables[k] !== undefined && variables[k] !== v) return null;
        variables[k] = v;
      }
      consumed.add(i);
      placed = true;
      break;
    }
    if (!placed) return null;
  }
  const unfilled = template.records.filter((_, i) => !consumed.has(i));
  if (unfilled.some((shape) => !shape.optional)) return null;
  const compiled: Omit<CompiledRecipe, "providerId" | "serviceId"> = { variables };
  if (template.hostRequired || root !== "@") compiled.host = root;
  if (unfilled.length > 0) {
    compiled.groupIds = [
      ...new Set(template.records.filter((_, i) => consumed.has(i)).map((s) => s.groupId)),
    ];
  }
  return compiled;
}

/**
 * The candidate roots for a `hostRequired` template: every record name that a
 * `"@"` shape of the right type could sit at. Never the zone apex — a
 * hostRequired template exists precisely because a CNAME cannot live there.
 */
function candidateHosts(template: DomainConnectTemplate, records: SimpleRecord[]): string[] {
  const rootTypes = new Set(
    template.records.filter((s) => s.host === "@").map((s) => s.sessionType),
  );
  const hosts = records
    .filter((r) =>
      rootTypes.has(r.type.toUpperCase() as (typeof template.records)[number]["sessionType"]),
    )
    .map((r) => r.name)
    .filter((name) => name !== "" && name !== "@");
  return [...new Set(hosts)];
}

/**
 * The roots an `appliesUnderHost` template may be applied at: the zone root
 * first, then every subdomain a fixed-host shape of the right type places a
 * record under (`www.shop` under a `www` shape ⇒ `shop`; `shop` itself under
 * an `"@"` shape). A TXT never roots the template: an ownership TXT alone at
 * `_dodomain-challenge.shop` is not a website on `shop`.
 */
function candidateSubdomainRoots(
  template: DomainConnectTemplate,
  records: SimpleRecord[],
): string[] {
  const roots = new Set<string>(["@"]);
  for (const record of records) {
    const name = record.name === "" ? "@" : record.name;
    if (name === "@") continue;
    for (const shape of template.records) {
      if (shape.sessionType === "TXT" || shape.sessionType !== record.type.toUpperCase()) continue;
      const pattern = splitHostPattern(shape.host);
      if (pattern.kind !== "fixed") continue;
      if (pattern.fixed === "@") roots.add(name);
      else if (name.startsWith(`${pattern.fixed}.`)) {
        roots.add(name.slice(pattern.fixed.length + 1));
      }
    }
  }
  return [...roots];
}

function candidateRoots(template: DomainConnectTemplate, records: SimpleRecord[]): string[] {
  if (template.hostRequired) return candidateHosts(template, records);
  if (template.appliesUnderHost === true) return candidateSubdomainRoots(template, records);
  return ["@"];
}

function describeRecords(records: SimpleRecord[]): string {
  return records
    .map((r) => `${r.type.toUpperCase()} at ${r.name === "" ? "@" : r.name}`)
    .join(", ");
}

export function compileToRecipe(records: SimpleRecord[], providerId: string): CompiledRecipe {
  if (records.length === 0) {
    throw new RecipeError(
      "Domain Connect needs at least one record to apply; this session has none.",
    );
  }
  // The tier's row of the type x tier matrix (record-capabilities.ts): a type
  // no template may carry can never match one, and is refused by name so the
  // start route and the detect probe say why one-click is not offered.
  const unwritable = typesTierCannotWrite(
    "domain_connect",
    records.map((r) => ({ type: r.type.toUpperCase() })),
  );
  if (unwritable.length > 0) {
    throw new RecipeError(
      `Domain Connect templates cannot carry ${unwritable.join(", ")} records; ` +
        `use the OAuth/API or manual fallback.`,
    );
  }

  // An SPF the SPFM merge cannot carry in full is refused by name, before any
  // template is tried: whichever template it landed in would silently drop part
  // of what the integrator asked for.
  for (const record of records) {
    const reason =
      record.type.toUpperCase() === "TXT" ? spfUnexpressibleReason(record.value) : null;
    if (reason !== null) {
      throw new RecipeError(`Domain Connect cannot apply ${record.name || "@"}: ${reason}.`);
    }
  }

  // The FIRST template that takes the record set wins, whatever the provider
  // serves. TODO(scope): a provider onboarded with `dns-records` alone (direct
  // onboarding) but not the narrower template a set compiles to gets the
  // manual flow for that set; picking per provider needs a probe per
  // candidate — docs/domain-connect/templates/README.md.
  for (const template of DOMAIN_CONNECT_TEMPLATES) {
    for (const root of candidateRoots(template, records)) {
      const match = matchTemplate(template, records, root);
      if (match !== null) {
        return { providerId, serviceId: template.serviceId, ...match };
      }
    }
  }

  // Nothing matched. Name the one refusal that has a documented cause of its
  // own (docs/apex-domains quotes this sentence); everything else gets the
  // honest general answer — the record set is not one of the published shapes.
  if (
    records.length === 1 &&
    records[0]!.type.toUpperCase() === "CNAME" &&
    (records[0]!.name === "@" || records[0]!.name === "")
  ) {
    throw new RecipeError(
      "CNAME recipe requires a non-apex host (CNAME cannot sit at the zone apex).",
    );
  }
  throw new RecipeError(
    `No Domain Connect template expresses this record set (${describeRecords(records)}). ` +
      `Domain Connect applies only DoDomain's published templates (${DOMAIN_CONNECT_TEMPLATES.map((t) => t.serviceId).join(", ")}); ` +
      `use the OAuth/API or manual fallback.`,
  );
}
