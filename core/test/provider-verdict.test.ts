// The per-provider verdict behind /domain-connect/<provider> (T-5811): one-click
// is claimed ONLY where a real apply is proven, and every state the snapshot can
// carry maps to a sentence that says no more than the data does.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { templateServiceIdForDnsProvider } from "../src/domain-connect-templates.ts";
import { listProviderGuides } from "../src/guides.ts";
import { providerSlug } from "../src/provider-slug.ts";
import {
  PROVEN_APPLIES,
  WATCH_PROVIDER_DNS_PROVIDER_ID,
  WATCH_PROVIDER_GUIDE,
  providerVerdict,
  templateVerdictRows,
  watchedTemplateCell,
  zProviderWatchSnapshot,
  type ProviderWatchProvider,
} from "../src/provider-watch.ts";

const SERVICE_IDS = ["a", "b", "c"];
const SERVED = {
  state: "served",
  status: 200,
  firstSeen: "2026-10-01",
  servedVersion: 1,
  versionDrift: false,
} as const;
const MISSING = {
  state: "not_served",
  status: 404,
  firstSeen: null,
  servedVersion: null,
  versionDrift: null,
} as const;
const UNKNOWN = {
  state: "unchecked",
  status: "timeout",
  firstSeen: null,
  servedVersion: null,
  versionDrift: null,
} as const;

function provider(templates: ProviderWatchProvider["templates"]): ProviderWatchProvider {
  return {
    name: "Acme DNS",
    urlAPI: "https://dc.acme.example",
    control: { ok: true, status: 200 },
    templates,
  };
}

const PROVEN = (ids: string[]) =>
  ids.map((serviceId) => ({ provider: "Acme DNS", serviceId, date: "2026-10-02" }));

test("served and proven on every template reads one_click_all", () => {
  const v = providerVerdict(
    provider({ a: SERVED, b: SERVED, c: SERVED }),
    SERVICE_IDS,
    PROVEN(["a", "b", "c"]),
  );
  assert.equal(v.kind, "one_click_all");
  assert.equal(v.oneClick, 3);
});

test("served without a proven apply is NEVER described as one-click", () => {
  const v = providerVerdict(provider({ a: SERVED, b: SERVED, c: SERVED }), SERVICE_IDS, []);
  assert.equal(v.kind, "served_unproven");
  assert.equal(v.oneClick, 0);
  assert.equal(v.servedUnproven, 3);
  assert.doesNotMatch(v.headline, /one-click setup on/i);
  assert.match(v.headline, /does not promise it/);
});

test("a served-but-unproven template is OFFERED with a fallback, never described as manual", () => {
  const unproven = providerVerdict(
    provider({ a: SERVED, b: MISSING, c: MISSING }),
    SERVICE_IDS,
    [],
  );
  assert.match(unproven.headline, /offers the provider's one-click approval/);
  assert.match(unproven.headline, /falls back to guided manual records/);
  const mixed = providerVerdict(
    provider({ a: SERVED, b: SERVED, c: MISSING }),
    SERVICE_IDS,
    PROVEN(["a"]),
  );
  assert.match(mixed.headline, /1 more is served there/);
  assert.match(mixed.headline, /The other 1 uses guided manual records/);
});

test("a manual provider says its API answers but does not serve the templates", () => {
  const v = providerVerdict(provider({ a: MISSING, b: MISSING, c: MISSING }), SERVICE_IDS, []);
  assert.match(
    v.headline,
    /^Its Domain Connect API answers, but it does not serve DoDomain's templates/,
  );
});

test("a mix reads one_click_some and counts the manual remainder", () => {
  const v = providerVerdict(
    provider({ a: SERVED, b: SERVED, c: MISSING }),
    SERVICE_IDS,
    PROVEN(["a"]),
  );
  assert.equal(v.kind, "one_click_some");
  assert.deepEqual([v.oneClick, v.servedUnproven, v.manual], [1, 1, 1]);
});

test("not served everywhere reads manual; an all-unchecked provider has no verdict", () => {
  assert.equal(
    providerVerdict(provider({ a: MISSING, b: MISSING, c: MISSING }), SERVICE_IDS, []).kind,
    "manual",
  );
  const blind = providerVerdict(provider({ a: UNKNOWN, b: UNKNOWN, c: UNKNOWN }), SERVICE_IDS, []);
  assert.equal(blind.kind, "unchecked");
  assert.match(blind.headline, /no verdict/);
});

test("a template missing from the snapshot row is unchecked, never not_served", () => {
  const v = providerVerdict(provider({ a: SERVED }), SERVICE_IDS, []);
  assert.deepEqual(
    v.rows.map((r) => r.verdict),
    ["served_unproven", "unchecked", "unchecked"],
  );
});

test("a regressed template counts as manual, not as served", () => {
  const regressed = { ...MISSING, state: "regressed", firstSeen: "2026-09-01" } as const;
  const v = providerVerdict(
    provider({ a: regressed, b: regressed, c: regressed }),
    SERVICE_IDS,
    PROVEN(["a"]),
  );
  assert.equal(v.oneClick, 0);
  assert.equal(v.kind, "manual");
});

test("the committed snapshot: Cloudflare is one-click on all five, Domain Chief is served but unproven", () => {
  const snapshot = zProviderWatchSnapshot.parse(
    JSON.parse(
      readFileSync(
        join(
          import.meta.dirname,
          "..",
          "..",
          "..",
          "docs",
          "domain-connect",
          "provider-watch.json",
        ),
        "utf8",
      ),
    ),
  );
  const byName = (name: string) => {
    const found = snapshot.providers.find((p) => p.name === name);
    assert.ok(found, `${name} is watched`);
    return providerVerdict(found, snapshot.ourTemplates.serviceIds);
  };
  assert.equal(byName("Cloudflare").kind, "one_click_all");
  // Glauca's fifth proof (apex-a-with-verification) landed 2026-10-23.
  assert.equal(byName("Glauca").kind, "one_click_all");
  assert.equal(byName("Domain Chief").kind, "served_unproven");
  // GoDaddy: custom-subdomain-cname (2026-11-04) and email-authentication
  // (2026-11-06) proven, and the three carrying an ownership TXT proven through
  // their -v2 siblings (served and applied 2026-11-12), so one-click on all five.
  assert.equal(byName("GoDaddy").kind, "one_click_all");
  assert.equal(byName("Host Europe").kind, "manual");
});

test("every proven apply names a provider the watch measures", () => {
  const snapshot = zProviderWatchSnapshot.parse(
    JSON.parse(
      readFileSync(
        join(
          import.meta.dirname,
          "..",
          "..",
          "..",
          "docs",
          "domain-connect",
          "provider-watch.json",
        ),
        "utf8",
      ),
    ),
  );
  const names = new Set(snapshot.providers.map((p) => p.name));
  for (const proven of PROVEN_APPLIES) {
    assert.ok(
      names.has(proven.provider),
      `PROVEN_APPLIES names "${proven.provider}", which the watch does not measure`,
    );
  }
});

test("WATCH_PROVIDER_GUIDE maps only to real guides", () => {
  const ids = new Set(listProviderGuides().map((g) => g.provider));
  for (const [name, id] of Object.entries(WATCH_PROVIDER_GUIDE)) {
    assert.ok(ids.has(id), `${name} -> ${id} is not a guide`);
  }
});

test("providerSlug turns a provider name into one stable URL slug", () => {
  assert.equal(providerSlug("GoDaddy"), "godaddy");
  assert.equal(providerSlug("1&1"), "1-and-1");
  assert.equal(providerSlug("Simply.com"), "simply-com");
  assert.equal(providerSlug("Squarespace Domains"), "squarespace-domains");
  assert.equal(providerSlug("GoDaddy reseller"), "godaddy-reseller");
});

// ── GoDaddy is judged on the -v2 siblings it is actually sent (T-15462) ─────

const TOKEN_TEMPLATES = [
  "domain-verification",
  "custom-subdomain-cname-with-verification",
  "apex-a-with-verification",
];

function godaddyRow(templates: ProviderWatchProvider["templates"]): ProviderWatchProvider {
  return {
    name: "GoDaddy",
    urlAPI: "https://domainconnect.api.godaddy.com",
    control: { ok: true, status: 200 },
    templates,
  };
}

test("GoDaddy serving a token original but not its -v2 sibling is NOT served for that template", () => {
  const templates: ProviderWatchProvider["templates"] = {};
  for (const id of TOKEN_TEMPLATES) {
    templates[id] = SERVED; // GoDaddy serves the original, but refuses its applies
    templates[`${id}-v2`] = MISSING; // the sibling DoDomain sends is not loaded yet
  }
  const rows = templateVerdictRows(godaddyRow(templates), TOKEN_TEMPLATES, []);
  assert.deepEqual(
    rows.map((row) => [row.serviceId, row.verdict]),
    TOKEN_TEMPLATES.map((id) => [id, "not_served"]),
  );
  // The row stays keyed on the registry serviceId every page links by.
  assert.equal(watchedTemplateCell(godaddyRow(templates), "domain-verification"), MISSING);
});

test("GoDaddy's -v2 sibling served reads served for the registry template, and token-free ones read their own cell", () => {
  const v = providerVerdict(
    godaddyRow({
      "domain-verification": MISSING,
      "domain-verification-v2": SERVED,
      "custom-subdomain-cname": SERVED,
    }),
    ["domain-verification", "custom-subdomain-cname"],
    [{ provider: "GoDaddy", serviceId: "custom-subdomain-cname", date: "2026-11-04" }],
  );
  assert.deepEqual(
    v.rows.map((row) => [row.serviceId, row.verdict]),
    [
      ["domain-verification", "served_unproven"],
      ["custom-subdomain-cname", "one_click"],
    ],
  );
});

test("every other watched provider is judged on the original cell", () => {
  const cloudflare: ProviderWatchProvider = {
    ...godaddyRow({ "domain-verification": SERVED, "domain-verification-v2": MISSING }),
    name: "Cloudflare",
  };
  assert.equal(watchedTemplateCell(cloudflare, "domain-verification"), SERVED);
  // The reseller platform's settings providerId is unknown, so core still
  // sends it the originals; its verdict reads them too.
  assert.equal(WATCH_PROVIDER_DNS_PROVIDER_ID["GoDaddy reseller"], undefined);
});

test("the committed snapshot's GoDaddy row carries a cell for every sibling core sends GoDaddy", () => {
  const snapshot = zProviderWatchSnapshot.parse(
    JSON.parse(
      readFileSync(
        join(
          import.meta.dirname,
          "..",
          "..",
          "..",
          "docs",
          "domain-connect",
          "provider-watch.json",
        ),
        "utf8",
      ),
    ),
  );
  for (const [watchName, dnsProviderId] of Object.entries(WATCH_PROVIDER_DNS_PROVIDER_ID)) {
    const row = snapshot.providers.find((p) => p.name === watchName);
    assert.ok(row, `${watchName} is watched`);
    for (const serviceId of snapshot.ourTemplates.serviceIds) {
      const sent = templateServiceIdForDnsProvider(dnsProviderId, serviceId);
      // scripts/ci/dc-provider-watch.mjs GODADDY_TEMPLATE_VARIANTS mirrors the
      // core table; a sibling it does not probe leaves this verdict blind.
      assert.ok(row.templates[sent], `${watchName} has no snapshot cell for ${sent}`);
    }
  }
});
