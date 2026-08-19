import { test } from "node:test";
import assert from "node:assert/strict";

import { guideFor } from "../src/guides.ts";

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
