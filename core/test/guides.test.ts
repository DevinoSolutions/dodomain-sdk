import { test } from "node:test";
import assert from "node:assert/strict";

import { guideFor, listProviderGuides, publicGuideFor } from "../src/guides.ts";
import { zProviderGuide } from "../src/schemas.ts";

test("guideFor returns the matching provider guide", () => {
  const g = guideFor("cloudflare", "acme.com");
  assert.equal(g.label, "Cloudflare");
  assert.ok(g.dashboardUrl?.includes("acme.com"), "dashboard URL is domain-substituted");
  assert.ok(g.steps.length > 0);
});

test("guideFor substitutes %domain% in steps", () => {
  const g = guideFor("godaddy", "example.org");
  assert.ok(g.steps.some((s) => s.includes("example.org")));
  assert.ok(!g.steps.some((s) => s.includes("%domain%")), "no unsubstituted tokens remain");
});

test("guideFor falls back to generic for unknown providers", () => {
  const g = guideFor("some-random-host", "x.com");
  assert.equal(g.provider, "unknown");
  assert.ok(g.steps.length > 0);
});

test("guideFor without a domain leaves %domain% tokens in place", () => {
  const g = guideFor("namecheap");
  assert.ok(g.dashboardUrl?.includes("%domain%"), "template token preserved when no domain given");
});

// —— Entri-manual-parity batch (2026-07): every provider added in this pass
// resolves to a dedicated guide (not the generic fallback), with a dashboard
// link and fully substituted steps.

const PARITY_PROVIDERS = [
  "bluehost",
  "digitalocean",
  "dnsimple",
  "dreamhost",
  "gandi",
  "hostgator",
  "hostinger",
  "ionos",
  "namecom",
  "namesilo",
  "onecom",
  "ovh",
  "porkbun",
  "strato",
  "vercel",
  "wix",
  "wordpress",
];

test("every Entri-manual-parity provider resolves to a dedicated guide", () => {
  for (const p of PARITY_PROVIDERS) {
    const g = guideFor(p, "acme.com");
    assert.equal(g.provider, p, `dedicated guide for ${p}`);
    assert.ok(g.dashboardUrl, `${p} has a dashboard URL`);
    assert.ok(g.hostFormat.length > 0, `${p} documents its host format`);
    assert.ok(g.steps.length >= 3 && g.steps.length <= 5, `${p} has 3-5 steps`);
    assert.ok(!g.steps.some((s) => s.includes("%domain%")), `${p} steps fully substituted`);
    assert.ok(!g.dashboardUrl?.includes("%domain%"), `${p} dashboardUrl fully substituted`);
  }
});

test("%domain% substitutes into the deep-linkable dashboard URLs", () => {
  assert.equal(
    guideFor("porkbun", "acme.com").dashboardUrl,
    "https://porkbun.com/account/dns/acme.com",
  );
  assert.equal(
    guideFor("namecom", "acme.com").dashboardUrl,
    "https://www.name.com/account/domain/details/acme.com/dns",
  );
  assert.equal(
    guideFor("digitalocean", "acme.com").dashboardUrl,
    "https://cloud.digitalocean.com/networking/domains/acme.com",
  );
  // wordpress.com carries the token twice (domain + site slug) — both substituted.
  assert.equal(
    guideFor("wordpress", "acme.com").dashboardUrl,
    "https://wordpress.com/domains/manage/acme.com/dns/acme.com",
  );
});

test("generic fallback still works for providers without a dedicated guide", () => {
  const g = guideFor("some-brand-new-registrar", "acme.com");
  assert.equal(g.provider, "unknown");
  assert.ok(g.steps.length > 0);
});

// —— Stage 9 WS-G batch (2026-09-05): providers whose vocabulary was re-read
// from the provider's own help page carry a dated citation; Hover is new.

test("Hover resolves to a dedicated guide with the @-for-root rule and a help citation", () => {
  const g = guideFor("hover", "acme.com");
  assert.equal(g.provider, "hover");
  assert.equal(g.apexToken, "@");
  assert.ok(g.steps.some((s) => s.includes("acme.com")));
  assert.ok(g.helpArticle?.url.startsWith("https://support.hover.com/"));
  assert.match(g.helpArticle?.checkedOn ?? "", /^\d{4}-\d{2}-\d{2}$/);
});

// T-5809 batch 1 (2026-10-22): each is read from the provider's own help page, so each
// carries the dated citation the docs page renders.
test("the T-5809 batch resolves to dedicated, cited guides", () => {
  for (const p of ["dynadot", "enom", "infomaniak", "networksolutions", "transip"]) {
    const g = guideFor(p, "acme.com");
    assert.equal(g.provider, p, `dedicated guide for ${p}`);
    assert.ok(g.steps.length >= 3 && g.steps.length <= 5, `${p} has 3-5 steps`);
    assert.ok(!g.steps.some((s) => s.includes("%domain%")), `${p} steps fully substituted`);
    assert.ok(g.helpArticle, `${p} cites the help page it was read from`);
    assert.equal(g.helpArticle?.checkedOn, "2026-10-22");
  }
});

// —— T-6545 batch (2026-10-22): Domain Chief, Glauca and Simply.com reach the
// flow by Domain Connect discovery, which reports the provider's own
// providerId — live discovery returned exactly these ids that day (abobo.nl,
// aada.cat, 000no.dk). Each must land on its dedicated guide.

test("Domain Connect providerIds resolve to their dedicated guides, not the generic one", () => {
  const cases: Array<[providerId: string, guide: string]> = [
    ["domainchief", "domainchief"],
    ["glauca.digital", "glauca"],
    ["simply.com", "simplycom"],
    ["squarespace.com", "squarespace"],
    ["namesilo.com", "namesilo"],
  ];
  for (const [providerId, guide] of cases) {
    const g = guideFor(providerId, "acme.com");
    assert.equal(g.provider, guide, `${providerId} → ${guide}`);
    assert.ok(g.helpArticle || guide === "namesilo", `${guide} carries a dated citation`);
    assert.ok(!g.steps.some((s) => s.includes("%domain%")), `${guide} steps substituted`);
    // The wire body follows the same mapping.
    assert.equal(publicGuideFor(providerId, "acme.com").provider, guide);
  }
});

test("Google Cloud DNS has its own guide: blank apex, and points ex-Google-Domains owners at Squarespace", () => {
  const g = guideFor("googleclouddns", "acme.com");
  assert.equal(g.provider, "googleclouddns");
  assert.equal(g.apexToken, "(blank)");
  assert.ok(g.steps.some((s) => s.includes("acme.com")));
  assert.ok(g.notes?.some((n) => n.includes("Squarespace")));
  assert.ok(g.helpArticle?.url.startsWith("https://cloud.google.com/dns/"));
});

test("every help-article citation carries a full ISO date and an https URL", () => {
  for (const g of listProviderGuides()) {
    if (!g.helpArticle) continue;
    assert.match(g.helpArticle.checkedOn, /^\d{4}-\d{2}-\d{2}$/, `${g.provider} checkedOn`);
    assert.ok(g.helpArticle.url.startsWith("https://"), `${g.provider} helpArticle url`);
  }
});

test("listProviderGuides returns every dedicated guide, label-sorted, without the generic fallback", () => {
  const all = listProviderGuides();
  assert.ok(all.length >= 28, `expected the full provider set, got ${all.length}`);
  assert.ok(
    !all.some((g) => g.provider === "unknown"),
    "generic fallback is not a listed provider",
  );
  const labels = all.map((g) => g.label);
  assert.deepEqual(
    labels,
    [...labels].sort((a, b) => a.localeCompare(b, "en")),
  );
  for (const g of all) {
    assert.equal(guideFor(g.provider).provider, g.provider, `${g.provider} resolves to itself`);
    assert.ok(
      g.steps.length > 0 && g.hostFormat.length > 0,
      `${g.provider} has steps + host format`,
    );
  }
});

// The docs generator headlines these two flags (apps/docs/scripts/generate-dns-provider-guides.mts):
// a flag may only sit on a guide whose own copy says what the flag claims, so the page
// never asserts something the provider entry does not.
test("discouragesApexCname is set exactly where the guide copy warns about a CNAME on the bare domain", () => {
  const flagged = listProviderGuides()
    .filter((g) => g.discouragesApexCname)
    .map((g) => g.provider);
  assert.deepEqual(flagged, ["godaddy", "hover", "namecheap"]);
  for (const g of listProviderGuides().filter((x) => x.discouragesApexCname)) {
    const copy = [g.hostFormat, ...(g.notes ?? [])].join(" ");
    assert.match(copy, /CNAME/, `${g.provider} copy names CNAME`);
    assert.match(copy, /`@`|bare domain|root domain/, `${g.provider} copy names the bare domain`);
  }
});

test("hasNoHostField is set only on a guide whose host copy says there is no host field", () => {
  const flagged = listProviderGuides().filter((g) => g.hasNoHostField);
  assert.deepEqual(
    flagged.map((g) => g.provider),
    ["strato"],
  );
  for (const g of flagged) assert.match(g.hostFormat, /^No host field/);
});

// T-2444: the wire must match the published contract. guideFor() returns the full
// record (docs-only fields included); publicGuideFor() is the ONE producer of every
// public `guide` body and may carry only zProviderGuide's keys.
const CONTRACT_KEYS = new Set(Object.keys(zProviderGuide.shape));
const DOCS_ONLY_KEYS = ["discouragesApexCname", "apexCnameNote", "hasNoHostField", "helpArticle"];

test("publicGuideFor output keys are a subset of zProviderGuide's shape, for every provider", () => {
  const providers = [...listProviderGuides().map((g) => g.provider), "definitely-not-a-provider"];
  for (const provider of providers) {
    for (const domain of [undefined, "acme.com"]) {
      const pub = publicGuideFor(provider, domain);
      for (const key of Object.keys(pub)) {
        assert.ok(
          CONTRACT_KEYS.has(key),
          `${provider}: "${key}" reached the public guide but is not in zProviderGuide`,
        );
      }
      // A valid contract body, carrying the same values the full record has.
      zProviderGuide.parse(pub);
      const full = guideFor(provider, domain);
      for (const key of Object.keys(pub) as (keyof typeof pub)[]) {
        assert.deepEqual(pub[key], full[key], `${provider}.${key} matches guideFor`);
      }
    }
  }
});

test("every zProviderGuide field defined on the full guide is present on the public guide", () => {
  // The other direction: a field added to ProviderGuide + zProviderGuide but
  // forgotten in publicGuideFor would silently vanish from the wire.
  const providers = [...listProviderGuides().map((g) => g.provider), "definitely-not-a-provider"];
  for (const provider of providers) {
    for (const domain of [undefined, "acme.com"]) {
      const pub = publicGuideFor(provider, domain) as Record<string, unknown>;
      const full = guideFor(provider, domain) as unknown as Record<string, unknown>;
      for (const key of CONTRACT_KEYS) {
        if (full[key] === undefined) continue;
        assert.ok(
          key in pub,
          `${provider}: contract field "${key}" is missing from publicGuideFor`,
        );
        assert.deepEqual(pub[key], full[key], `${provider}.${key} matches guideFor`);
      }
    }
  }
});

test("the docs-only fields exist on the full guides but never on the public guide", () => {
  const all = listProviderGuides();
  for (const key of DOCS_ONLY_KEYS) {
    assert.ok(
      all.some((g) => key in g),
      `${key} is no longer set on any guide: update DOCS_ONLY_KEYS or this pin is vacuous`,
    );
    assert.ok(!CONTRACT_KEYS.has(key), `${key} must stay out of zProviderGuide`);
  }
  for (const g of all) {
    const pub = publicGuideFor(g.provider, "acme.com");
    for (const key of DOCS_ONLY_KEYS) {
      assert.ok(!(key in pub), `${g.provider}: docs-only "${key}" leaked into the public guide`);
    }
  }
});
