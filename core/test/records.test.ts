import { test } from "node:test";
import assert from "node:assert/strict";

import {
  composeRecords,
  fqdnFor,
  recordHostWarnings,
  toExpectedRecords,
  zoneRelativeName,
} from "../src/records.ts";

test("fqdnFor treats @ and blank and the bare domain as the apex", () => {
  assert.equal(fqdnFor("@", "acme.com"), "acme.com");
  assert.equal(fqdnFor("", "acme.com"), "acme.com");
  assert.equal(fqdnFor("acme.com", "acme.com"), "acme.com");
});

test("fqdnFor prefixes a subdomain host", () => {
  assert.equal(fqdnFor("www", "acme.com"), "www.acme.com");
  assert.equal(fqdnFor("mail", "acme.com"), "mail.acme.com");
});

test("fqdnFor does not double-append an already-qualified host", () => {
  assert.equal(fqdnFor("www.acme.com", "acme.com"), "www.acme.com");
});

test("zoneRelativeName returns @ for the zone apex itself", () => {
  assert.equal(zoneRelativeName("devino.ca", "devino.ca"), "@");
});

test("zoneRelativeName strips the zone suffix from an in-zone fqdn", () => {
  assert.equal(zoneRelativeName("status-e2e.devino.ca", "devino.ca"), "status-e2e");
  assert.equal(zoneRelativeName("a.b.devino.ca", "devino.ca"), "a.b");
});

test("zoneRelativeName leaves a fqdn outside the zone fully qualified", () => {
  assert.equal(zoneRelativeName("example.com", "devino.ca"), "example.com");
  // A same-suffix LABEL is not zone membership — "notdevino.ca" is outside.
  assert.equal(zoneRelativeName("notdevino.ca", "devino.ca"), "notdevino.ca");
});

test("zoneRelativeName tolerates a trailing dot and stray whitespace", () => {
  assert.equal(zoneRelativeName(" www.devino.ca. ", "devino.ca"), "www");
});

test("issue #41 repro: host @ on a subdomain session names the SESSION apex, never the zone apex", () => {
  // Session domain status-e2e.devino.ca, record host "@": the verifier checks
  // fqdnFor(host, SESSION domain) — the display's zone-relative name for that
  // fqdn must be "status-e2e" (in zone devino.ca), NOT "@" (the zone apex —
  // the mis-display that had users creating a root-breaking apex CNAME).
  const fqdn = fqdnFor("@", "status-e2e.devino.ca");
  assert.equal(fqdn, "status-e2e.devino.ca");
  assert.equal(zoneRelativeName(fqdn, "devino.ca"), "status-e2e");
});

test("toExpectedRecords maps Sendly's record set to fqdns", () => {
  const out = toExpectedRecords(
    [
      { type: "MX", host: "mail", value: "feedback-smtp.us-east-1.amazonses.com", priority: 10 },
      { type: "TXT", host: "usesend._domainkey", value: "p=MIGf" },
      { type: "TXT", host: "mail", value: "v=spf1 include:amazonses.com ~all" },
      { type: "TXT", host: "_dmarc", value: "v=DMARC1; p=none;" },
    ],
    "customer.com",
  );
  assert.equal(out.length, 4);
  // FIXED(F-002): MX preference now carries through (was silently dropped —
  // see git history for the pinned pre-fix assertion this replaces).
  assert.deepEqual(out[0], {
    type: "MX",
    fqdn: "mail.customer.com",
    expect: "feedback-smtp.us-east-1.amazonses.com",
    priority: 10,
  });
  assert.equal(out[3]!.fqdn, "_dmarc.customer.com");
});

test("toExpectedRecords omits priority when the source record has none (non-MX types)", () => {
  const out = toExpectedRecords(
    [{ type: "CNAME", host: "www", value: "target.example.com" }],
    "acme.com",
  );
  assert.equal(out.length, 1);
  assert.ok(!("priority" in out[0]!));
});

test("toExpectedRecords drops unsupported record types", () => {
  const out = toExpectedRecords(
    [{ type: "NS" as unknown as "TXT", host: "@", value: "x" }],
    "acme.com",
  );
  assert.equal(out.length, 0);
});

// ── Create-time composition + advisories (F3, BioFlow live E2E 2026-08-12) ───

test("composeRecords echoes the caller's host beside the fqdn verification will check", () => {
  const out = composeRecords(
    [
      { type: "CNAME", host: "app", value: "cname.sendly.io" },
      { type: "TXT", host: "@", value: "v=spf1" },
      { type: "TXT", host: "already.acme.com", value: "x" },
    ],
    "acme.com",
  );
  assert.deepEqual(out, [
    { type: "CNAME", host: "app", fqdn: "app.acme.com" },
    { type: "TXT", host: "@", fqdn: "acme.com" },
    { type: "TXT", host: "already.acme.com", fqdn: "already.acme.com" },
  ]);
});

test("composeRecords composes exactly what toExpectedRecords will verify, for the same input", () => {
  const records = [
    { type: "CNAME" as const, host: "links", value: "cname.example.com" },
    { type: "TXT" as const, host: "@", value: "v=spf1" },
  ];
  const composed = composeRecords(records, "links.acme.com");
  const expected = toExpectedRecords(records, "links.acme.com");
  assert.deepEqual(
    composed.map((r) => r.fqdn),
    expected.map((r) => r.fqdn),
    "the create-time promise and the verify-time check must be the same names",
  );
});

test("recordHostWarnings flags the doubled-hostname trap: host repeats the domain's leading label", () => {
  const warnings = recordHostWarnings(
    [{ type: "CNAME", host: "links", value: "cname.example.com" }],
    "links.acme.com",
  );
  assert.equal(warnings.length, 1);
  assert.equal(warnings[0]?.code, "duplicate_host_label");
  assert.equal(warnings[0]?.host, "links");
  assert.equal(
    warnings[0]?.fqdn,
    "links.links.acme.com",
    "the warning names the composed fqdn, so the caller sees the consequence not just the rule",
  );
});

test("recordHostWarnings compares labels case-insensitively (DNS names are)", () => {
  const warnings = recordHostWarnings(
    [{ type: "CNAME", host: "Links", value: "cname.example.com" }],
    "LINKS.acme.com",
  );
  assert.equal(warnings.length, 1);
});

test("recordHostWarnings flags a multi-label host whose LAST label doubles, since that label is the one that lands adjacent to the domain", () => {
  const warnings = recordHostWarnings(
    [{ type: "TXT", host: "_dmarc.links", value: "v=DMARC1" }],
    "links.acme.com",
  );
  assert.equal(warnings.length, 1);
  assert.equal(warnings[0]?.fqdn, "_dmarc.links.links.acme.com");
});

test("recordHostWarnings stays silent for every host that cannot double a label", () => {
  const domain = "links.acme.com";
  const quiet = [
    { type: "TXT" as const, host: "@", value: "v=spf1" },
    { type: "CNAME" as const, host: "app", value: "cname.example.com" },
    // Already fully qualified — fqdnFor returns it unchanged, no composition.
    { type: "CNAME" as const, host: "links.links.acme.com", value: "cname.example.com" },
    // The bare session domain resolves to the apex.
    { type: "TXT" as const, host: "links.acme.com", value: "x" },
    // A leading label that merely SHARES a prefix is not the same label.
    { type: "CNAME" as const, host: "linkshub", value: "cname.example.com" },
  ];
  assert.deepEqual(recordHostWarnings(quiet, domain), []);
});

test("recordHostWarnings returns one entry per offending record, not one per session", () => {
  const warnings = recordHostWarnings(
    [
      { type: "CNAME", host: "links", value: "cname.example.com" },
      { type: "TXT", host: "links", value: "v=spf1" },
      { type: "TXT", host: "@", value: "ok" },
    ],
    "links.acme.com",
  );
  assert.equal(warnings.length, 2);
});
