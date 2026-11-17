import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { DOMAIN_CONNECT_TEMPLATES } from "../src/domain-connect-templates.ts";
import { oneClickAvailableFor, templateOneClickCoverage } from "../src/one-click.ts";
import type { TemplateProbeOutcome } from "../src/schemas.ts";

// The verdict behind "is one-click available here?" — the preflight headline
// and POST /api/v1/domains/check's `oneClickAvailable`. Born from a GoDaddy
// domain (tier 2, all five templates 404) being shown "one-click" in green to a
// paying integrator on 2026-10-14.

const SERVICE_IDS = DOMAIN_CONNECT_TEMPLATES.map((template) => template.serviceId);

function templates(
  outcome: TemplateProbeOutcome,
  overrides: Record<string, TemplateProbeOutcome> = {},
): Record<string, TemplateProbeOutcome> {
  const all: Record<string, TemplateProbeOutcome> = {};
  for (const id of SERVICE_IDS) all[id] = outcome;
  return { ...all, ...overrides };
}

const SERVED: TemplateProbeOutcome = { probed: true, supported: true };
const NOT_SERVED: TemplateProbeOutcome = { probed: true, supported: false };

describe("templateOneClickCoverage reads how much of the template set a provider serves", () => {
  test("a GoDaddy-like provider that answers 404 for every template covers none", () => {
    assert.equal(templateOneClickCoverage(templates(NOT_SERVED)), "none");
  });

  test("a provider that serves every template covers all", () => {
    assert.equal(templateOneClickCoverage(templates(SERVED)), "all");
  });

  test("a provider that serves two templates and 404s the rest covers some", () => {
    const mixed = templates(NOT_SERVED, {
      "domain-verification": SERVED,
      "custom-subdomain-cname": SERVED,
    });
    assert.equal(templateOneClickCoverage(mixed), "some");
  });

  test("served templates beside unprobed ones are some, never all", () => {
    const partial = templates(
      { probed: false, reason: "probe_failed" },
      { "domain-verification": SERVED },
    );
    assert.equal(templateOneClickCoverage(partial), "some");
  });

  test("404s beside unprobed ones are none — one real no is still a measured no", () => {
    const partial = templates(
      { probed: false, reason: "probe_failed" },
      { "domain-verification": NOT_SERVED },
    );
    assert.equal(templateOneClickCoverage(partial), "none");
  });

  test("nothing probed is unconfirmed, for every not-probed reason", () => {
    for (const reason of ["not_tier_2", "no_discovery", "flag_off", "probe_failed"] as const) {
      assert.equal(templateOneClickCoverage(templates({ probed: false, reason })), "unconfirmed");
    }
  });
});

describe("oneClickAvailableFor answers for typical setups, failing closed", () => {
  test("tier 1 (Cloudflare OAuth) is available whatever the template rows say", () => {
    assert.equal(
      oneClickAvailableFor({
        tier: 1,
        templates: templates({ probed: false, reason: "not_tier_2" }),
        ownApiOneClickEnabled: false,
      }),
      true,
    );
  });

  test("tier 2 on a GoDaddy-like provider that serves no template is NOT available", () => {
    assert.equal(
      oneClickAvailableFor({
        tier: 2,
        templates: templates(NOT_SERVED),
        ownApiOneClickEnabled: false,
      }),
      false,
    );
  });

  test("tier 2 on a provider that serves at least one template is available", () => {
    const mixed = templates(NOT_SERVED, { "custom-subdomain-cname": SERVED });
    assert.equal(
      oneClickAvailableFor({ tier: 2, templates: mixed, ownApiOneClickEnabled: false }),
      true,
    );
    assert.equal(
      oneClickAvailableFor({ tier: 2, templates: templates(SERVED), ownApiOneClickEnabled: false }),
      true,
    );
  });

  test("tier 2 that was never probed is NOT available — unconfirmed is not a yes", () => {
    for (const reason of ["no_discovery", "flag_off", "probe_failed"] as const) {
      assert.equal(
        oneClickAvailableFor({
          tier: 2,
          templates: templates({ probed: false, reason }),
          ownApiOneClickEnabled: false,
        }),
        false,
        reason,
      );
    }
  });

  test("tier 3 without an enabled own integration is never available, even if a stray outcome claims support", () => {
    assert.equal(
      oneClickAvailableFor({ tier: 3, templates: templates(SERVED), ownApiOneClickEnabled: false }),
      false,
    );
  });
});

describe("oneClickAvailableFor counts a provider's own one-click API integration", () => {
  // Porkbun (DNS Connect) and Hostinger (OAuth) are detected as tier 3 "guided":
  // their one-click is DoDomain's own integration, enabled per deployment, so
  // the caller says whether it is on (apps/web lib/own-api-one-click.ts).
  const NOT_PROBED = templates({ probed: false, reason: "not_tier_2" });

  test("a tier-3 provider whose own one-click integration is enabled is available", () => {
    assert.equal(
      oneClickAvailableFor({ tier: 3, templates: NOT_PROBED, ownApiOneClickEnabled: true }),
      true,
    );
  });

  test("the same tier-3 provider with its integration disabled is NOT available", () => {
    assert.equal(
      oneClickAvailableFor({ tier: 3, templates: NOT_PROBED, ownApiOneClickEnabled: false }),
      false,
    );
  });

  test("an enabled own integration wins over a tier-2 probe that found nothing served", () => {
    assert.equal(
      oneClickAvailableFor({
        tier: 2,
        templates: templates(NOT_SERVED),
        ownApiOneClickEnabled: true,
      }),
      true,
    );
  });
});
