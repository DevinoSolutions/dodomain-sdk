// The preflight's HONESTY copy — the one sentence each "we did not probe this
// template" reason renders as. Zero-import and zod-free so BOTH readers of a
// DomainPreflightResponse can ship it to a browser: the dashboard's Domain
// preflight and the public provider-detector page, which since 2026-09-08 draw
// ONE matrix out of @dodomain/ui/preflight (a client-safe module).
//
// Why copy lives in core at all: the `probed:false` reasons are part of the
// wire contract (schemas.ts zTemplateProbeOutcome), and the sentence that
// explains each one IS the honesty rule — "we did not look" must never read
// as "the provider said no". Two apps each keeping their own wording of that
// rule would drift, and the drift would be invisible because the two pages
// are never on screen together — which is exactly what happened to the rows
// AROUND these sentences before they were promoted to @dodomain/ui. One map,
// keyed by the schema's own enum, so adding a reason without its sentence
// fails the build in both apps.

/** The reasons a template was NOT probed — `zTemplateProbeOutcome`'s `probed:false` branch. */
export type TemplateNotProbedReason = "not_tier_2" | "no_discovery" | "flag_off" | "probe_failed";

export const TEMPLATE_NOT_PROBED_COPY: Record<TemplateNotProbedReason, string> = {
  not_tier_2:
    "This domain does not route to the Domain Connect flow, so its provider was never asked about our templates.",
  no_discovery:
    "The zone publishes no usable `_domainconnect` record, so there is no provider endpoint to ask.",
  flag_off:
    "The Domain Connect apply path is switched off in this deployment, so no provider was contacted.",
  probe_failed:
    "The provider did not answer inside the probe's budget. That is a fact about the request, not about the provider — re-run the check.",
};
