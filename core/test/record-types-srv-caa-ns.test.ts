// SRV, CAA and below-root NS, end to end through core: the schema's per-type
// required fields, the composite answer each type verifies against, the DNS
// lookup, the Cloudflare writer's structured `data`, the Porkbun request JWT,
// and the type x tier matrix that decides which one-click tier may be offered.
// No network: every DNS resolver and Cloudflare fetch here is an in-memory fake.

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";

import { isNsAtZoneApex } from "../src/apex.ts";
import { applySessionRecords } from "../src/cloudflare/apply.ts";
import {
  cloudflareRecordAnswer,
  cloudflareValueFields,
  createRecord,
  verifyRecordViaApi,
} from "../src/cloudflare/dns.ts";
import {
  buildPorkbunAuthorizeUrl,
  porkbunOneClickBlocker,
  porkbunRecords,
  porkbunServiceName,
} from "../src/porkbun.ts";
import { compileToRecipe, RecipeError } from "../src/recipes.ts";
import {
  caaAnswer,
  expectedAnswerFor,
  missingRecordFields,
  parseCaaAnswer,
  parseSrvAnswer,
  RECORD_TYPES,
  recordValueMatches,
  srvAnswer,
  TIER_WRITABLE_TYPES,
  tierCanWrite,
  typesTierCannotWrite,
} from "../src/record-capabilities.ts";
import { toExpectedRecords, type SessionRecord } from "../src/records.ts";
import { zCreateSessionInput } from "../src/schemas.ts";
import { verifyRecord, type DnsResolver, type VerifyDeps } from "../src/verify.ts";
import type { ExpectedRecord } from "../src/verify-types.ts";

const SRV: SessionRecord = {
  type: "SRV",
  host: "_sip._tcp",
  value: "sip.provider.net",
  priority: 10,
  weight: 5,
  port: 5060,
};
const CAA: SessionRecord = {
  type: "CAA",
  host: "@",
  value: "letsencrypt.org",
  flags: 0,
  tag: "issue",
};
const NS: SessionRecord = { type: "NS", host: "eu", value: "ns1.provider.net" };

// ── schema ───────────────────────────────────────────────────────────────────

test("zCreateSessionInput accepts complete SRV, CAA and below-root NS records", () => {
  const parsed = zCreateSessionInput.safeParse({ domain: "customer.com", records: [SRV, CAA, NS] });
  assert.equal(parsed.success, true, JSON.stringify(parsed.error?.issues));
  assert.deepEqual(parsed.data?.records[0], SRV, "weight and port survive the parse");
  assert.deepEqual(parsed.data?.records[1], CAA, "flags and tag survive the parse");
});

test("zCreateSessionInput refuses an SRV record missing weight or port, at the missing field", () => {
  const { weight: _w, port: _p, ...partial } = SRV;
  const parsed = zCreateSessionInput.safeParse({ domain: "customer.com", records: [partial] });
  assert.equal(parsed.success, false);
  const paths = parsed.error!.issues.map((i) => i.path.join("."));
  assert.deepEqual(paths.sort(), ["records.0.port", "records.0.weight"]);
});

test("zCreateSessionInput refuses a CAA record missing flags or tag", () => {
  const { tag: _t, ...noTag } = CAA;
  const parsed = zCreateSessionInput.safeParse({ domain: "customer.com", records: [noTag] });
  assert.equal(parsed.success, false);
  assert.deepEqual(
    parsed.error!.issues.map((i) => i.path.join(".")),
    ["records.0.tag"],
  );
});

test("zCreateSessionInput refuses a CAA value carrying a quote or a newline, an unknown tag, and an out-of-range port", () => {
  const quoted = { ...CAA, value: 'letsencrypt.org"; evil' };
  const newline = { ...CAA, value: `letsencrypt.org${String.fromCharCode(10)}issue evil.ca` };
  const badTag = { ...CAA, tag: "contactemail" };
  const bigPort = { ...SRV, port: 65536 };
  for (const record of [quoted, newline, badTag, bigPort]) {
    assert.equal(
      zCreateSessionInput.safeParse({ domain: "customer.com", records: [record] }).success,
      false,
      `expected a refusal for ${JSON.stringify(record)}`,
    );
  }
});

test("missingRecordFields names exactly the fields each type is missing", () => {
  assert.equal(missingRecordFields(SRV), null);
  assert.equal(missingRecordFields(CAA), null);
  assert.equal(missingRecordFields(NS), null);
  assert.deepEqual(missingRecordFields({ type: "SRV", value: "t.example", priority: 1 }), {
    reason: "missing_srv_fields",
    message:
      "SRV records require priority, weight and port (missing: weight, port); value is the target host",
    fields: ["weight", "port"],
  });
  assert.equal(
    missingRecordFields({ type: "CAA", value: "x", tag: "issue" })?.reason,
    "missing_caa_fields",
  );
  assert.equal(
    missingRecordFields({ type: "MX", value: "mx.example" })?.reason,
    "missing_mx_priority",
  );
});

// ── the composite answer each type verifies against ──────────────────────────

test("toExpectedRecords verifies SRV and CAA against their composite answers, NS against its value", () => {
  const expected = toExpectedRecords([SRV, CAA, NS], "customer.com");
  assert.deepEqual(
    expected.map((r) => [r.type, r.fqdn, r.expect]),
    [
      ["SRV", "_sip._tcp.customer.com", "10 5 5060 sip.provider.net"],
      ["CAA", "customer.com", '0 issue "letsencrypt.org"'],
      ["NS", "eu.customer.com", "ns1.provider.net"],
    ],
  );
  assert.equal(
    expectedAnswerFor(SRV),
    srvAnswer({ priority: 10, weight: 5, port: 5060, target: "sip.provider.net" }),
  );
  assert.deepEqual(parseSrvAnswer("10 5 5060 sip.provider.net"), {
    priority: 10,
    weight: 5,
    port: 5060,
    target: "sip.provider.net",
  });
  assert.deepEqual(parseCaaAnswer(caaAnswer({ flags: 128, tag: "iodef", value: "mailto:a@b.c" })), {
    flags: 128,
    tag: "iodef",
    value: "mailto:a@b.c",
  });
});

test("SRV matches on every field; the target is host-normalized and the numbers are exact", () => {
  const want = "10 5 5060 sip.provider.net";
  assert.equal(recordValueMatches("SRV", want, "10 5 5060 SIP.Provider.net."), true);
  assert.equal(recordValueMatches("SRV", want, "20 5 5060 sip.provider.net"), false, "priority");
  assert.equal(recordValueMatches("SRV", want, "10 6 5060 sip.provider.net"), false, "weight");
  assert.equal(recordValueMatches("SRV", want, "10 5 5061 sip.provider.net"), false, "port");
  assert.equal(recordValueMatches("SRV", want, "10 5 5060 other.provider.net"), false, "target");
  assert.equal(
    recordValueMatches("SRV", want, "sip.provider.net"),
    false,
    "an unparseable answer never matches",
  );
});

test("CAA matches flags exactly, the tag case-insensitively and the value case-sensitively", () => {
  const want = '0 issue "letsencrypt.org"';
  assert.equal(recordValueMatches("CAA", want, '0 ISSUE "letsencrypt.org"'), true);
  assert.equal(recordValueMatches("CAA", want, '128 issue "letsencrypt.org"'), false, "flags");
  assert.equal(recordValueMatches("CAA", want, '0 issuewild "letsencrypt.org"'), false, "tag");
  assert.equal(recordValueMatches("CAA", want, '0 issue "LetsEncrypt.org"'), false, "value case");
  assert.equal(
    recordValueMatches("CAA", want, "0 issue letsencrypt.org"),
    false,
    "an unquoted answer never matches",
  );
});

// ── verification over DNS ────────────────────────────────────────────────────

/** A resolver where every lookup the test did not stub throws loudly. */
function fakeResolver(overrides: Partial<DnsResolver> = {}): DnsResolver {
  const notStubbed = (name: string) => async () => {
    throw new Error(`fakeResolver: ${name} not stubbed for this test`);
  };
  return {
    resolveNs: overrides.resolveNs ?? notStubbed("resolveNs"),
    resolve4: overrides.resolve4 ?? notStubbed("resolve4"),
    resolve6: overrides.resolve6 ?? notStubbed("resolve6"),
    resolveCname: overrides.resolveCname ?? notStubbed("resolveCname"),
    resolveMx: overrides.resolveMx ?? notStubbed("resolveMx"),
    resolveTxt: overrides.resolveTxt ?? notStubbed("resolveTxt"),
    resolveCaa: overrides.resolveCaa ?? notStubbed("resolveCaa"),
    ...(overrides.resolveSrv ? { resolveSrv: overrides.resolveSrv } : {}),
  };
}

/** Both the public and the authoritative side answer from the same fake. */
function sameAnswerEverywhere(resolver: DnsResolver, zone: string): VerifyDeps {
  return { resolver, zone, authoritativeResolverFor: async () => ({ kind: "resolver", resolver }) };
}

const SRV_EXPECTED: ExpectedRecord = {
  type: "SRV",
  fqdn: "_sip._tcp.customer.com",
  expect: "10 5 5060 sip.provider.net",
  priority: 10,
};

test("SRV verifies when the resolver's answer carries the same priority, weight, port and target", async () => {
  const resolver = fakeResolver({
    resolveSrv: async () => [{ priority: 10, weight: 5, port: 5060, name: "sip.provider.net" }],
  });
  const result = await verifyRecord(SRV_EXPECTED, sameAnswerEverywhere(resolver, "customer.com"));
  assert.equal(result.outcome, "verified");
  assert.deepEqual(result.authoritativeFound, ["10 5 5060 sip.provider.net"]);
});

test("SRV with the wrong port is present-but-not-verified, never a match", async () => {
  const resolver = fakeResolver({
    resolveSrv: async () => [{ priority: 10, weight: 5, port: 5061, name: "sip.provider.net" }],
  });
  const result = await verifyRecord(SRV_EXPECTED, sameAnswerEverywhere(resolver, "customer.com"));
  assert.equal(result.present, false);
  assert.equal(result.outcome, "absent");
});

test("SRV on a resolver without resolveSrv is indeterminate, never absent or verified", async () => {
  const result = await verifyRecord(
    SRV_EXPECTED,
    sameAnswerEverywhere(fakeResolver(), "customer.com"),
  );
  assert.equal(result.present, false);
  assert.equal(result.outcome, "indeterminate");
  assert.equal(result.authoritativeError, "ESRVUNSUPPORTED");
});

test("CAA verifies only when flags, tag and the exact value match", async () => {
  const expected: ExpectedRecord = {
    type: "CAA",
    fqdn: "customer.com",
    expect: '0 issue "letsencrypt.org"',
  };
  const answering = (value: string) =>
    fakeResolver({ resolveCaa: async () => [{ critical: 0, issue: value }] });
  const ok = await verifyRecord(
    expected,
    sameAnswerEverywhere(answering("letsencrypt.org"), "customer.com"),
  );
  assert.equal(ok.outcome, "verified");
  const wrongCase = await verifyRecord(
    expected,
    sameAnswerEverywhere(answering("LetsEncrypt.org"), "customer.com"),
  );
  assert.equal(wrongCase.present, false);
});

test("NS below the root verifies from the delegated servers' answer and fails closed on NODATA or a lame delegation", async () => {
  const expected: ExpectedRecord = {
    type: "NS",
    fqdn: "eu.customer.com",
    expect: "ns1.provider.net",
  };
  const delegated = fakeResolver({
    resolveNs: async () => ["NS1.provider.net.", "ns2.provider.net"],
  });
  const live = await verifyRecord(expected, sameAnswerEverywhere(delegated, "eu.customer.com"));
  assert.equal(live.outcome, "verified");

  const noData = Object.assign(new Error("no data"), { code: "ENODATA" });
  const undelegated = fakeResolver({
    resolveNs: async () => {
      throw noData;
    },
  });
  const before = await verifyRecord(expected, sameAnswerEverywhere(undelegated, "customer.com"));
  assert.equal(before.present, false);
  assert.equal(before.outcome, "absent");

  const lame = fakeResolver({
    resolveNs: async () => {
      throw Object.assign(new Error("refused"), { code: "EREFUSED" });
    },
  });
  const broken = await verifyRecord(expected, sameAnswerEverywhere(lame, "eu.customer.com"));
  assert.equal(broken.present, false);
  assert.equal(broken.outcome, "indeterminate");
});

test("isNsAtZoneApex is true for the registrable apex only", () => {
  assert.equal(isNsAtZoneApex("customer.com"), true);
  assert.equal(isNsAtZoneApex("Customer.co.uk."), true);
  assert.equal(isNsAtZoneApex("eu.customer.com"), false);
  assert.equal(isNsAtZoneApex("eu.customer.co.uk"), false);
});

// ── Cloudflare writer ────────────────────────────────────────────────────────

interface FakeRequest {
  method: string;
  headers: Record<string, string>;
  body?: string;
}

/** A fake fetch (MOCK: no request reaches Cloudflare) that records every call. */
function fakeCloudflare(json: (url: string, opts: FakeRequest) => unknown) {
  const calls: Array<{ url: string; opts: FakeRequest }> = [];
  const impl = (async (url: string, opts: FakeRequest) => {
    calls.push({ url, opts });
    return { ok: true, status: 200, text: async () => JSON.stringify(json(url, opts)) };
  }) as unknown as typeof fetch;
  return { impl, calls };
}

test("Cloudflare createRecord sends SRV and CAA as structured data, never as content", async () => {
  const { impl, calls } = fakeCloudflare(() => ({
    success: true,
    result: { id: "r1", type: "SRV", name: "x", content: "" },
  }));
  await createRecord(
    "tok",
    "zone",
    { type: "SRV", name: "_sip._tcp.customer.com", ...cloudflareValueFields(SRV) },
    impl,
  );
  await createRecord(
    "tok",
    "zone",
    { type: "CAA", name: "customer.com", ...cloudflareValueFields(CAA) },
    impl,
  );
  const [srvBody, caaBody] = calls.map((c) => JSON.parse(c.opts.body!) as Record<string, unknown>);
  assert.deepEqual(srvBody!.data, {
    priority: 10,
    weight: 5,
    port: 5060,
    target: "sip.provider.net",
  });
  assert.equal(srvBody!.content, undefined);
  assert.equal(srvBody!.priority, undefined, "the SRV priority travels inside data");
  assert.deepEqual(caaBody!.data, { flags: 0, tag: "issue", value: "letsencrypt.org" });
  assert.equal(caaBody!.content, undefined);
});

test("cloudflareValueFields refuses an SRV or CAA record missing its fields; NS is plain content", () => {
  assert.throws(
    () => cloudflareValueFields({ type: "SRV", value: "t", priority: 1 }),
    /weight and port/,
  );
  assert.throws(() => cloudflareValueFields({ type: "CAA", value: "x" }), /flags and tag/);
  assert.deepEqual(cloudflareValueFields(NS), { content: "ns1.provider.net" });
});

test("cloudflareRecordAnswer reads SRV and CAA back from data in the verified spelling", () => {
  assert.equal(
    cloudflareRecordAnswer("SRV", {
      id: "a",
      content: "5 5060 sip.provider.net",
      priority: 10,
      data: { priority: 10, weight: 5, port: 5060, target: "sip.provider.net" },
    }),
    "10 5 5060 sip.provider.net",
  );
  assert.equal(
    cloudflareRecordAnswer("SRV", { id: "a", content: "5 5060 sip.provider.net", priority: 10 }),
    "10 5 5060 sip.provider.net",
    "without data, content plus the top-level priority",
  );
  assert.equal(
    cloudflareRecordAnswer("CAA", {
      id: "b",
      content: '0 issue "letsencrypt.org"',
      data: { flags: 0, tag: "issue", value: "letsencrypt.org" },
    }),
    '0 issue "letsencrypt.org"',
  );
});

test("verifyRecordViaApi matches a Cloudflare SRV read-back on every field", async () => {
  const { impl } = fakeCloudflare(() => ({
    success: true,
    result: [
      {
        id: "x",
        content: "",
        data: { priority: 10, weight: 5, port: 9999, target: "sip.provider.net" },
      },
      {
        id: "y",
        content: "",
        data: { priority: 10, weight: 5, port: 5060, target: "sip.provider.net" },
      },
    ],
  }));
  const v = await verifyRecordViaApi(
    "tok",
    "zone",
    "SRV",
    "_sip._tcp.customer.com",
    expectedAnswerFor(SRV),
    10,
    impl,
  );
  assert.deepEqual(v, {
    present: true,
    match: true,
    value: "10 5 5060 sip.provider.net",
    proxied: false,
  });
});

test("applySessionRecords writes SRV/CAA/NS with their fields and refuses an apex NS as not writable", async () => {
  const created: unknown[] = [];
  const result = await applySessionRecords(
    [SRV, CAA, NS, { type: "NS", host: "@", value: "ns1.hijack.net" }],
    { token: "tok", zoneId: "zone", domain: "customer.com" },
    {
      listRecords: async () => [],
      createRecord: async (_t, _z, input) => {
        created.push(input);
        return { id: "new", type: input.type, name: input.name, content: input.content };
      },
      updateRecordContent: async () => {
        throw new Error("no record here should be patched");
      },
      verifyRecordViaApi: async (_t, _z, _type, _name, expect) => ({
        present: true,
        match: true,
        value: expect,
        proxied: false,
      }),
    },
  );
  assert.deepEqual(created, [
    {
      type: "SRV",
      name: "_sip._tcp.customer.com",
      proxied: false,
      content: "sip.provider.net",
      data: { priority: 10, weight: 5, port: 5060, target: "sip.provider.net" },
    },
    {
      type: "CAA",
      name: "customer.com",
      proxied: false,
      content: "letsencrypt.org",
      data: { flags: 0, tag: "issue", value: "letsencrypt.org" },
    },
    { type: "NS", name: "eu.customer.com", proxied: false, content: "ns1.provider.net" },
  ]);
  const apexNs = result.results[3]!;
  assert.deepEqual(
    [apexNs.writable, apexNs.match, apexNs.fqdn],
    [false, false, "customer.com"],
    "an apex NS is never written and blocks allLive",
  );
  assert.equal(result.allLive, false);
});

// ── Porkbun DNS Connect request ──────────────────────────────────────────────

test("porkbunRecords maps SRV to prio + 'weight port target', CAA to its presentation form, NS to its host", () => {
  const { domain, records } = porkbunRecords("app.customer.com", [SRV, CAA, NS]);
  assert.equal(domain, "customer.com");
  assert.deepEqual(records, [
    { type: "SRV", host: "_sip._tcp.app", content: "5 5060 sip.provider.net", prio: 10 },
    { type: "CAA", host: "app", content: '0 issue "letsencrypt.org"' },
    { type: "NS", host: "eu.app", content: "ns1.provider.net" },
  ]);
});

test("porkbunRecords refuses an NS at the zone apex and an SRV missing its fields", () => {
  assert.throws(
    () => porkbunRecords("customer.com", [{ type: "NS", host: "@", value: "ns1.hijack.net" }]),
    /below the root only/,
  );
  const { port: _p, ...noPort } = SRV;
  assert.throws(() => porkbunRecords("customer.com", [noPort]), /SRV records require/);
});

test("the Porkbun request JWT carries the integrator's display name as `service`, normalized", () => {
  const config = {
    // MOCK Porkbun signing key, generated in memory; never a configured secret.
    clientSecret: randomBytes(32).toString("base64url"),
    redirectUri: "http://localhost:3939/api/v1/porkbun/callback",
  };
  const base = {
    config,
    domain: "customer.com",
    records: [SRV],
    state: "s".repeat(32),
    nowSeconds: 1790000000,
    expiresSeconds: 1790001800,
  };
  const payloadOf = (url: string) =>
    JSON.parse(
      Buffer.from(new URL(url).searchParams.get("request")!.split(".")[1]!, "base64url").toString(),
    ) as Record<string, unknown>;
  assert.equal(
    payloadOf(buildPorkbunAuthorizeUrl({ ...base, service: "  Acme \n Status  " })).service,
    "Acme Status",
  );
  assert.equal(
    "service" in payloadOf(buildPorkbunAuthorizeUrl({ ...base, service: "   " })),
    false,
  );
  assert.equal("service" in payloadOf(buildPorkbunAuthorizeUrl(base)), false);
  assert.equal(porkbunServiceName("x".repeat(150))?.length, 100);
});

test("porkbunOneClickBlocker names the cap and the count; SRV/CAA/NS are not blockers", () => {
  const txt = (i: number) => ({ type: "TXT", host: `r${i}`, value: "v" });
  assert.equal(porkbunOneClickBlocker([SRV, CAA, NS]), null);
  assert.deepEqual(porkbunOneClickBlocker(Array.from({ length: 26 }, (_, i) => txt(i))), {
    reason: "too_many_records",
    limit: 25,
    count: 26,
  });
  assert.equal(porkbunOneClickBlocker(Array.from({ length: 25 }, (_, i) => txt(i))), null);
  assert.deepEqual(porkbunOneClickBlocker([]), { reason: "no_records" });
});

// ── the type x tier matrix ───────────────────────────────────────────────────

test("TIER_WRITABLE_TYPES: Cloudflare, Porkbun and manual write every type; Domain Connect only template types", () => {
  assert.deepEqual([...TIER_WRITABLE_TYPES.cloudflare_oauth], [...RECORD_TYPES]);
  assert.deepEqual([...TIER_WRITABLE_TYPES.porkbun_dns_connect], [...RECORD_TYPES]);
  assert.deepEqual([...TIER_WRITABLE_TYPES.manual], [...RECORD_TYPES]);
  assert.deepEqual([...TIER_WRITABLE_TYPES.domain_connect], ["A", "AAAA", "CNAME", "TXT", "MX"]);
  for (const type of ["SRV", "CAA", "NS"]) {
    assert.equal(tierCanWrite("cloudflare_oauth", type), true);
    assert.equal(tierCanWrite("domain_connect", type), false);
  }
  assert.deepEqual(typesTierCannotWrite("domain_connect", [SRV, CAA, SRV, { type: "TXT" }]), [
    "SRV",
    "CAA",
  ]);
  assert.deepEqual(typesTierCannotWrite("cloudflare_oauth", [SRV, CAA, NS]), []);
});

test("compileToRecipe refuses a Domain Connect recipe carrying an SRV record, by name", () => {
  assert.throws(
    () =>
      compileToRecipe(
        [
          { type: "TXT", name: "@", value: "dodomain-verify=abc" },
          { type: "srv", name: "_sip._tcp", value: "sip.provider.net" },
        ],
        "cloudflare",
      ),
    (e: unknown) =>
      e instanceof RecipeError &&
      e.message ===
        "Domain Connect templates cannot carry SRV records; use the OAuth/API or manual fallback.",
  );
});
