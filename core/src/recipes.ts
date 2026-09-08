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
import { spfSoleIncludeHost } from "./email-records.ts";

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
}

export interface CompiledRecipe {
  providerId: string;
  serviceId: DomainConnectServiceId;
  /** The apply's `host=` — present only for `hostRequired` templates. */
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

/** Every shape's host is anchored on a fixed part; a leading `%variable%`
 * label, when present, is the ONE label the matcher extracts. */
function splitHostPattern(host: string): { variable?: string; fixed: string } {
  const match = /^%([A-Za-z0-9]+)%\.(.+)$/.exec(host);
  return match ? { variable: match[1], fixed: match[2]! } : { fixed: host };
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
  if (record.type.toUpperCase() !== shape.sessionType) return null;
  const variables: Record<string, string> = {};

  // ── host ──
  const name = record.name === "" ? "@" : record.name;
  const { variable: hostVariable, fixed } = splitHostPattern(shape.host);
  // The shape host, re-based onto the template root.
  const expectedFixed = fixed === "@" ? root : root === "@" ? fixed : `${fixed}.${root}`;
  if (hostVariable === undefined) {
    if (name !== expectedFixed) return null;
  } else {
    // `<label>.<fixed>[.<root>]` — exactly one leading label is the variable.
    const suffix = `.${expectedFixed}`;
    if (!name.endsWith(suffix)) return null;
    const label = name.slice(0, -suffix.length);
    if (label === "" || label.includes(".") || label === "@") return null;
    variables[hostVariable] = label;
  }

  // ── value ──
  const rule = shape.value;
  if (rule.kind === "whole") {
    if (record.value === "") return null;
    variables[rule.variable] = record.value;
  } else if (rule.kind === "prefixed") {
    if (!record.value.startsWith(rule.prefix) || record.value.length === rule.prefix.length) {
      return null;
    }
    variables[rule.variable] = record.value.slice(rule.prefix.length);
  } else {
    const include = spfSoleIncludeHost(record.value);
    if (include === null) return null;
    variables[rule.variable] = include;
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
  if (template.hostRequired) compiled.host = root;
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

  for (const template of DOMAIN_CONNECT_TEMPLATES) {
    const roots = template.hostRequired ? candidateHosts(template, records) : ["@"];
    for (const root of roots) {
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
