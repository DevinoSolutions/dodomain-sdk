// Offline tests for the SPF checker — every TXT answer is a fake shaped like a
// real zone's (Google Workspace's include chain, a Microsoft 365 record, the
// classic over-the-limit marketing stack). No network.

import assert from "node:assert/strict";
import { test } from "node:test";

import { analyzeSpf, parseSpfTerms } from "../src/spf.ts";
import { SPF_DNS_LOOKUP_LIMIT } from "../src/spf-types.ts";

function dnsError(code: string): Error {
  return Object.assign(new Error(code), { code });
}

/** name → TXT strings (each a one-part record), or an Error to throw. A missing name answers ENODATA. */
function txtFixture(table: Record<string, string[] | Error>) {
  const calls: string[] = [];
  const resolveTxt = async (host: string): Promise<string[][]> => {
    calls.push(host);
    const value = table[host];
    if (value === undefined) throw dnsError("ENODATA");
    if (value instanceof Error) throw value;
    return value.map((s) => [s]);
  };
  return { resolveTxt, calls };
}

function codes(analysis: { issues: Array<{ code: string }> }): string[] {
  return analysis.issues.map((i) => i.code);
}

test("parseSpfTerms splits mechanisms with qualifier/argument and modifiers with name/value", () => {
  const terms = parseSpfTerms(
    "v=spf1 ip4:192.0.2.0/24 include:_spf.google.com a mx/24 -all exp=explain.example.com",
  );
  assert.deepEqual(
    terms.map((t) =>
      t.kind === "mechanism" ? [t.qualifier, t.name, t.argument] : [t.kind, t.raw],
    ),
    [
      ["+", "ip4", "192.0.2.0/24"],
      ["+", "include", "_spf.google.com"],
      ["+", "a", null],
      ["+", "mx", "/24"],
      ["-", "all", null],
      ["modifier", "exp=explain.example.com"],
    ],
  );
});

test("parseSpfTerms marks a term that is neither mechanism nor modifier as unknown", () => {
  const [term] = parseSpfTerms("v=spf1 includes:_spf.example.com");
  assert.equal(term?.kind, "unknown");
});

test("a Google-Workspace-style record: the include chain is walked and every DNS-querying term is counted", async () => {
  // google.com's real chain shape (2026): _spf.google.com includes three netblock records.
  const { resolveTxt, calls } = txtFixture({
    "customer.com": ["v=spf1 include:_spf.google.com ~all"],
    "_spf.google.com": [
      "v=spf1 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com ~all",
    ],
    "_netblocks.google.com": ["v=spf1 ip4:35.190.247.0/24 ip4:64.233.160.0/19 ~all"],
    "_netblocks2.google.com": ["v=spf1 ip6:2001:4860:4000::/36 ~all"],
    "_netblocks3.google.com": ["v=spf1 ip4:172.217.0.0/19 ~all"],
  });
  const analysis = await analyzeSpf("customer.com", { resolveTxt });
  assert.equal(analysis.records.length, 1);
  assert.equal(analysis.allQualifier, "~");
  assert.equal(analysis.dnsLookups, 4);
  assert.equal(analysis.complete, true);
  assert.deepEqual(analysis.visited, [
    "_spf.google.com",
    "_netblocks.google.com",
    "_netblocks2.google.com",
    "_netblocks3.google.com",
  ]);
  assert.deepEqual(codes(analysis), []);
  assert.deepEqual(calls, [
    "customer.com",
    "_spf.google.com",
    "_netblocks.google.com",
    "_netblocks2.google.com",
    "_netblocks3.google.com",
  ]);
});

test("no v=spf1 record → no_record (other TXT strings at the name are ignored)", async () => {
  const { resolveTxt } = txtFixture({
    "customer.com": ["google-site-verification=abc", "dodomain-verify=xyz"],
  });
  const analysis = await analyzeSpf("customer.com", { resolveTxt });
  assert.deepEqual(analysis.records, []);
  assert.deepEqual(codes(analysis), ["no_record"]);
  assert.equal(analysis.issues[0]!.severity, "error");
});

test("two v=spf1 records → multiple_records (permerror at receivers), the first is still analyzed", async () => {
  const { resolveTxt } = txtFixture({
    "customer.com": ["v=spf1 ip4:192.0.2.1 -all", "v=spf1 include:_spf.other.com ~all"],
  });
  const analysis = await analyzeSpf("customer.com", { resolveTxt });
  assert.equal(analysis.records.length, 2);
  assert.ok(codes(analysis).includes("multiple_records"));
  assert.equal(analysis.allQualifier, "-");
});

test("+all is an error, ?all a warning, and a record with no all at all is warned about", async () => {
  const pass = await analyzeSpf("a.example", {
    ...txtFixture({ "a.example": ["v=spf1 ip4:192.0.2.1 +all"] }),
  });
  assert.ok(codes(pass).includes("all_pass"));
  const neutral = await analyzeSpf("b.example", {
    ...txtFixture({ "b.example": ["v=spf1 ip4:192.0.2.1 ?all"] }),
  });
  assert.ok(codes(neutral).includes("all_neutral"));
  const missing = await analyzeSpf("c.example", {
    ...txtFixture({ "c.example": ["v=spf1 ip4:192.0.2.1"] }),
  });
  assert.ok(codes(missing).includes("no_all"));
  assert.equal(missing.allQualifier, null);
});

test("the ten-lookup limit: eleven include/a/mx terms across the chain → lookup_limit_exceeded", async () => {
  const includes = Array.from({ length: 6 }, (_, i) => `include:spf${i}.vendor.example`);
  const table: Record<string, string[]> = {
    "customer.com": [`v=spf1 ${includes.join(" ")} a mx -all`],
  };
  for (let i = 0; i < 6; i++) {
    // Each vendor record costs one more `a` lookup: 6 includes + 6 a + a + mx = 14.
    table[`spf${i}.vendor.example`] = ["v=spf1 a ip4:198.51.100.0/24 -all"];
  }
  const analysis = await analyzeSpf("customer.com", txtFixture(table));
  assert.equal(analysis.dnsLookups, 14);
  assert.ok(analysis.dnsLookups > SPF_DNS_LOOKUP_LIMIT);
  assert.ok(codes(analysis).includes("lookup_limit_exceeded"));
});

test("an include whose target has no SPF record is include_target_missing; a redirect= hands the all-qualifier over", async () => {
  const { resolveTxt } = txtFixture({
    "customer.com": ["v=spf1 include:gone.vendor.example redirect=_spf.customer.com"],
    "gone.vendor.example": ["some-unrelated-txt"],
    "_spf.customer.com": ["v=spf1 ip4:203.0.113.0/24 -all"],
  });
  const analysis = await analyzeSpf("customer.com", { resolveTxt });
  assert.ok(codes(analysis).includes("include_target_missing"));
  // include (1) + redirect (1): both count.
  assert.equal(analysis.dnsLookups, 2);
  assert.equal(analysis.allQualifier, "-");
  assert.ok(!codes(analysis).includes("no_all"));
});

test("redirect= beside an all mechanism is flagged as ignored and the record's own all wins", async () => {
  const { resolveTxt, calls } = txtFixture({
    "customer.com": ["v=spf1 ip4:192.0.2.1 ~all redirect=_spf.other.example"],
  });
  const analysis = await analyzeSpf("customer.com", { resolveTxt });
  assert.ok(codes(analysis).includes("redirect_ignored"));
  assert.equal(analysis.allQualifier, "~");
  // The ignored redirect is never fetched.
  assert.deepEqual(calls, ["customer.com"]);
});

test("terms after all are reported as never evaluated; ptr is reported as deprecated", async () => {
  const { resolveTxt } = txtFixture({
    "customer.com": ["v=spf1 ptr -all include:_spf.late.example"],
  });
  const analysis = await analyzeSpf("customer.com", { resolveTxt });
  assert.ok(codes(analysis).includes("ptr_mechanism"));
  assert.ok(codes(analysis).includes("terms_after_all"));
  // The term after `all` costs no lookup and is not fetched.
  assert.equal(analysis.dnsLookups, 1);
  assert.deepEqual(analysis.visited, []);
});

test("a TXT read that FAILS mid-chain leaves complete:false and an unchecked issue — never a verdict from partial data", async () => {
  const { resolveTxt } = txtFixture({
    "customer.com": ["v=spf1 include:_spf.flaky.example include:_spf.fine.example -all"],
    "_spf.flaky.example": dnsError("ETIMEOUT"),
    "_spf.fine.example": ["v=spf1 ip4:192.0.2.0/24 -all"],
  });
  const analysis = await analyzeSpf("customer.com", { resolveTxt });
  assert.equal(analysis.complete, false);
  const unchecked = analysis.issues.find((i) => i.code === "unchecked");
  assert.equal(unchecked?.domain, "_spf.flaky.example");
  assert.match(unchecked?.note ?? "", /ETIMEOUT/);
  // The count still includes both include terms — the lower bound is honest.
  assert.equal(analysis.dnsLookups, 2);
});

test("a failed lookup of the domain itself is unchecked, not no_record", async () => {
  const { resolveTxt } = txtFixture({ "customer.com": dnsError("ESERVFAIL") });
  const analysis = await analyzeSpf("customer.com", { resolveTxt });
  assert.deepEqual(codes(analysis), ["unchecked"]);
  assert.equal(analysis.complete, false);
});

test("an include loop terminates: a domain is walked once", async () => {
  const { resolveTxt, calls } = txtFixture({
    "a.example": ["v=spf1 include:b.example -all"],
    "b.example": ["v=spf1 include:a.example -all"],
  });
  const analysis = await analyzeSpf("a.example", { resolveTxt });
  assert.deepEqual(calls, ["a.example", "b.example"]);
  assert.equal(analysis.dnsLookups, 2);
});
