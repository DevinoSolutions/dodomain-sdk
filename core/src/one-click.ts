// Whether a domain can ACTUALLY be set up in one click, read off what the
// template-support probe found — the ONE verdict behind every surface that
// answers "is one-click available here?": the preflight headline and discovery
// row (@dodomain/ui/preflight, both the dashboard tool and the public
// provider-detector) and `oneClickAvailable` on POST /api/v1/domains/check.
//
// Why it needed a home: tier 2 means the provider SPEAKS Domain Connect, not
// that it serves DoDomain's templates. GoDaddy answers 404 for all five of them
// (never onboarded), yet on 2026-10-14 a paying integrator was told "Tier 2 —
// one-click" in green for a GoDaddy domain, three rows above five "not
// onboarded" rows. The tier is a routing fact; one-click is this verdict.
//
// Zero runtime imports (both imports are type-only and erased), so the
// browser bundles that render the preflight can ship it.

import type { Tier } from "./detect.ts";
import type { TemplateProbeOutcome } from "./schemas.ts";

/**
 * How much of DoDomain's template set the provider was found to serve.
 *
 *   "all"         — every template was probed and every one is served.
 *   "some"        — at least one template is served (the others answered 404
 *                   or were not probed): one-click exists for those setups only.
 *   "none"        — at least one template was probed and none is served: the
 *                   provider has not enabled DoDomain's one-click.
 *   "unconfirmed" — no template was probed at all (flag off, no discovery,
 *                   probe failed, not tier 2), so nothing may be claimed
 *                   either way.
 */
export type TemplateOneClickCoverage = "all" | "some" | "none" | "unconfirmed";

export function templateOneClickCoverage(
  templates: Record<string, TemplateProbeOutcome>,
): TemplateOneClickCoverage {
  const outcomes = Object.values(templates);
  const probed = outcomes.filter((outcome) => outcome.probed);
  if (probed.length === 0) return "unconfirmed";
  const served = probed.filter((outcome) => outcome.probed && outcome.supported).length;
  if (served === 0) return "none";
  return served === outcomes.length ? "all" : "some";
}

/**
 * true ⇒ this domain's provider offers DoDomain's one-click for at least one
 * typical setup: tier 1 (Cloudflare OAuth writes every record type directly),
 * or tier 2 where the provider serves at least one of our templates. Fails
 * CLOSED: an unprobed tier 2 is `false`, the same direction the connect flow's
 * own readiness probe takes, because `false` only ever means "plan for guided
 * setup", which always works.
 *
 * Provider-level only. A session also needs a plan that includes one-click
 * (`packages/plans` `oneClickConnect`), and a tier-2 setup needs its records to
 * fill one of the templates the provider serves.
 */
export function oneClickAvailableFor(result: {
  tier: Tier;
  templates: Record<string, TemplateProbeOutcome>;
}): boolean {
  if (result.tier === 1) return true;
  if (result.tier === 3) return false;
  const coverage = templateOneClickCoverage(result.templates);
  return coverage === "all" || coverage === "some";
}
