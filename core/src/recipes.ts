// Compile a constrained set of DNS records into one of DoDomain's approved
// Domain Connect *recipes*. This is the heart of the corrected architecture:
// Domain Connect connectors do NOT accept arbitrary records[]. The general
// session API may accept records[], but for the Domain Connect path it must be
// compiled into a narrow, pre-approved template + variables.
//
// Scope: two recipes only (the two templates in docs/domain-connect/templates/).
//   - custom-subdomain-cname : exactly one non-apex CNAME
//   - domain-verification    : exactly one prefixed TXT
//
// Anything else throws — the caller should fall back to OAuth/API or manual setup.
//
// WIRED (tier-2 build, 2026-07-11 — Amin ruled BUILD; discharges the audit's
// needs_human tier-2-domain-connect decision): the product callers are
// apps/web's `/api/v1/sessions/:token/domain-connect/start` route and the
// detect route's `domainConnectReady` probe (via apps/web/src/lib/dc-config.ts),
// both gated behind the DODOMAIN_TIER2_DC_ENABLED flag. `providerId` is an
// ARGUMENT: the composition root (apps/web/src/env.ts → lib/domain-connect.ts)
// validates DODOMAIN_PROVIDER_ID and passes it in — core reads NO process.env
// (D-005 discharged; scripts/check-core-config-bans.sh now has zero exceptions).

export const VERIFY_PREFIX = "dodomain-verify=";

// The FIXED host of the domain-verification template's TXT record, relative to
// the zone apex (see docs/domain-connect/templates/dodomain.io.domain-verification.json
// — the template pins `host` itself, so no apply `host` param is ever passed
// for this recipe). Callers use this to check a session's TXT actually lands
// where the template will write it.
export const VERIFY_TXT_HOST = "_dodomain-challenge";

export interface SimpleRecord {
  type: string;
  name: string; // host, relative or "@"
  value: string;
  ttl?: number;
}

export interface CompiledRecipe {
  providerId: string;
  serviceId: "custom-subdomain-cname" | "domain-verification";
  host?: string;
  variables: Record<string, string>;
}

export class RecipeError extends Error {}

export function compileToRecipe(records: SimpleRecord[], providerId: string): CompiledRecipe {
  if (records.length !== 1) {
    throw new RecipeError(
      `Domain Connect recipes accept exactly one record; got ${records.length}. ` +
        `Multi-record sets (e.g. full email auth) need a dedicated recipe or the manual/OAuth path.`,
    );
  }
  const r = records[0]!;
  const host = r.name === "@" || r.name === "" ? undefined : r.name;

  if (r.type.toUpperCase() === "CNAME") {
    if (!host)
      throw new RecipeError(
        "CNAME recipe requires a non-apex host (CNAME cannot sit at the zone apex).",
      );
    return {
      providerId,
      serviceId: "custom-subdomain-cname",
      host,
      // The template uses %target% for the CNAME destination.
      variables: { target: r.value },
    };
  }

  if (r.type.toUpperCase() === "TXT") {
    if (!r.value.startsWith(VERIFY_PREFIX)) {
      throw new RecipeError(
        `domain-verification TXT must start with the constrained prefix "${VERIFY_PREFIX}" ` +
          `(arbitrary TXT values are not allowed in this recipe).`,
      );
    }
    return {
      providerId,
      serviceId: "domain-verification",
      // The verification template fixes the host (VERIFY_TXT_HOST) itself, so
      // no apply `host` param is passed — only the constrained token variable.
      host: undefined,
      variables: { token: r.value.slice(VERIFY_PREFIX.length) },
    };
  }

  throw new RecipeError(
    `No recipe for record type "${r.type}". Use the OAuth/API or manual fallback.`,
  );
}
