import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { inspect } from "node:util";

import {
  applyOvhRecords,
  OVH_API_BASES,
  OvhError,
  ovhRecordBodies,
  ovhRegionForNameServers,
  ovhZoneAccessRules,
  ovhZoneName,
  requestOvhConsent,
  signOvhRequest,
  zOvhCallback,
} from "../src/ovh.ts";
import { RECORD_TYPES, TIER_WRITABLE_TYPES } from "../src/record-capabilities.ts";
import type { SessionRecord } from "../src/records.ts";

// Vectors from OVH's own wrapper test suite, github.com/ovh/python-ovh
// tests/test_client.py `test_call_signature` (MockApplicationSecret,
// MockConsumerKey, MockTime, urlAuth, j_body copied verbatim).
const AS = "9ufkBmLaTQ9nz5yMUlg79taH0GNnzDjk";
const CK = "5mBuy6SUQcRw2ZUxg0cG68BoDKpED4KY";
const AK = "TDPKJdwZwAQPwKX2";
const T = 1457018875;
const URL_AUTH = "https://eu.api.ovh.com/1.0/auth";
const J_BODY = '{"a":"b","c":"d"}';

const application = { applicationKey: AK, applicationSecret: AS };
const zone = "customer.com";
const state = "s".repeat(32);

test("the OVH signature reproduces OVH's published python-ovh vectors for GET, POST, PUT and DELETE", () => {
  const expected = {
    GET: ["", "$1$e9556054b6309771395efa467c22e627407461ad"],
    POST: [J_BODY, "$1$ec2fb5c7a81f64723c77d2e5b609ae6f58a84fc1"],
    PUT: [J_BODY, "$1$8a75a9e7c8e7296c9dbeda6a2a735eb6bd58ec4b"],
    DELETE: ["", "$1$a1eecd00b3b02b6cf5708b84b9ff42059a950d85"],
  } as const;
  for (const [method, [body, sig]] of Object.entries(expected)) {
    assert.equal(
      signOvhRequest({ appSecret: AS, consumerKey: CK, method, url: URL_AUTH, body, timestamp: T }),
      sig,
      method,
    );
  }
});

test("the OVH signature follows the documented AS+CK+METHOD+URL+BODY+TSTAMP order with the query string", () => {
  const url = "https://eu.api.ovh.com/1.0/domain/zone/example.com/record?fieldType=TXT";
  const manual = "$1$" + createHash("sha1").update(`${AS}+${CK}+GET+${url}++${T}`).digest("hex");
  assert.equal(
    signOvhRequest({ appSecret: AS, consumerKey: CK, method: "get", url, body: "", timestamp: T }),
    manual,
  );
});

test("an OVH zone on .ovh.ca nameservers is Canada, on .ovh.net Europe, and a mixed or foreign set is not routed", () => {
  assert.equal(ovhRegionForNameServers(["dns10.ovh.ca", "ns10.ovh.ca."]), "ca");
  assert.equal(ovhRegionForNameServers(["DNS10.OVH.NET", "ns10.ovh.net"]), "eu");
  assert.equal(ovhRegionForNameServers(["dns10.ovh.ca", "ns10.ovh.net"]), null);
  assert.equal(ovhRegionForNameServers(["dns10.ovh.ca", "ns1.cloudflare.com"]), null);
  assert.equal(ovhRegionForNameServers([]), null);
  assert.equal(ovhRegionForNameServers(["evilovh.ca"]), null);
});

test("the OVH access rules stay inside the one zone, with no registrar, account or order path", () => {
  const rules = ovhZoneAccessRules("customer-site.co.uk");
  assert.equal(rules.length, 5);
  for (const r of rules) {
    assert.ok(
      r.path === "/domain/zone/customer-site.co.uk" ||
        r.path.startsWith("/domain/zone/customer-site.co.uk/"),
      `rule escapes the zone: ${r.method} ${r.path}`,
    );
    const wild = r.path.indexOf("*");
    if (wild !== -1) assert.equal(r.path, "/domain/zone/customer-site.co.uk/record/*");
    assert.doesNotMatch(r.path, /^\/(me|order|domain\/(?!zone\/))/);
  }
  assert.deepEqual(
    rules
      .filter((r) => r.method !== "GET")
      .map((r) => `${r.method} ${r.path}`)
      .sort(),
    // Add-only grant: the customer's OVH approval page never shows a
    // modify or delete permission the adapter does not use.
    [
      "POST /domain/zone/customer-site.co.uk/record",
      "POST /domain/zone/customer-site.co.uk/refresh",
    ],
  );
});

test("OVH zone names that could widen an access rule are refused before any request", () => {
  for (const bad of [
    "*",
    "example.com/*",
    "example.com*",
    "*.example.com",
    "../me",
    "example",
    "",
    "exa mple.com",
    "-a.com",
    "a_b.com",
  ]) {
    assert.equal(ovhZoneName(bad), null, bad);
    assert.throws(() => ovhZoneAccessRules(bad), OvhError, bad);
  }
  assert.throws(() => ovhZoneAccessRules("Example.com"), OvhError);
  assert.equal(ovhZoneName("Example.COM."), "example.com");
  assert.equal(ovhZoneName("bücher.example"), "xn--bcher-kva.example");
});

// Request bodies here are always JSON strings; anything else fails the test.
function bodyOf(init?: RequestInit): string {
  if (init?.body === undefined || init.body === null) return "";
  assert.equal(typeof init.body, "string");
  return init.body as string;
}
function urlOf(input: Parameters<typeof fetch>[0]): string {
  return input instanceof Request ? input.url : input.toString();
}

test("the OVH consent request is unsigned and carries only the zone rules and our callback with its state", async () => {
  const calls: { url: string; init: RequestInit }[] = [];
  // MOCK OVH: answers the credential request, no network.
  const fetcher = (async (input: Parameters<typeof fetch>[0], init: RequestInit = {}) => {
    calls.push({ url: urlOf(input), init });
    return Response.json({
      consumerKey: CK,
      validationUrl: "https://ca.ovh.com/auth/sso/api?credentialToken=mock",
      state: "pendingValidation",
    });
  }) as typeof fetch;
  const consent = await requestOvhConsent(
    {
      region: "ca",
      application,
      zone,
      callbackUrl: "https://app.dodomain.io/api/v1/ovh/callback",
      state,
    },
    fetcher,
  );
  assert.deepEqual(consent, {
    consumerKey: CK,
    validationUrl: "https://ca.ovh.com/auth/sso/api?credentialToken=mock",
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.url, `${OVH_API_BASES.ca}/auth/credential`);
  assert.equal(calls[0]!.init.method, "POST");
  assert.deepEqual(calls[0]!.init.headers, {
    "X-Ovh-Application": AK,
    "Content-Type": "application/json",
  });
  assert.deepEqual(JSON.parse(bodyOf(calls[0]!.init)), {
    accessRules: ovhZoneAccessRules(zone),
    redirection: `https://app.dodomain.io/api/v1/ovh/callback?state=${state}`,
  });
  assert.equal(zOvhCallback.safeParse({ state, extra: "ignored" }).success, true);
  assert.equal(zOvhCallback.safeParse({ state: "short" }).success, false);
});

test("an OVH consent answer that points the user off OVH or lacks a pending key is refused", async () => {
  for (const body of [
    { consumerKey: CK, validationUrl: "https://evil.example/approve", state: "pendingValidation" },
    { consumerKey: CK, validationUrl: "http://www.ovh.com/auth", state: "pendingValidation" },
    {
      consumerKey: CK,
      validationUrl: "https://www.ovh.com.evil.example/",
      state: "pendingValidation",
    },
    {
      consumerKey: "bad key!",
      validationUrl: "https://www.ovh.com/auth",
      state: "pendingValidation",
    },
    { consumerKey: CK, validationUrl: "https://www.ovh.com/auth", state: "validated" },
  ]) {
    // MOCK OVH answer, no network.
    const fetcher = (async () => Response.json(body)) as unknown as typeof fetch;
    await assert.rejects(
      requestOvhConsent(
        {
          region: "eu",
          application,
          zone,
          callbackUrl: "https://app.dodomain.io/api/v1/ovh/callback",
          state,
        },
        fetcher,
      ),
      (error: unknown) => error instanceof OvhError && error.stage === "consent",
    );
  }
  // MOCK OVH answer: an invalid application key, whose text never escapes.
  const refused = (async () =>
    Response.json(
      { class: "Client::Forbidden", message: "Invalid application key" },
      { status: 403 },
    )) as unknown as typeof fetch;
  await assert.rejects(
    requestOvhConsent(
      {
        region: "eu",
        application,
        zone,
        callbackUrl: "https://app.dodomain.io/api/v1/ovh/callback",
        state,
      },
      refused,
    ),
    (error: unknown) =>
      error instanceof OvhError &&
      error.status === 403 &&
      !error.message.includes("Invalid application key"),
  );
});

test("OVH record bodies are zone-relative, CNAME and MX absolute with a trailing dot, MX priority packed and TXT raw", () => {
  const records: SessionRecord[] = [
    { type: "TXT", host: "_dodomain-challenge", value: "dodomain-verify=abc" },
    { type: "CNAME", host: "@", value: "edge.example.net" },
    { type: "MX", host: "@", value: "mx.example.net.", priority: 10 },
    { type: "A", host: "@", value: "192.0.2.1", ttl: 300 },
  ];
  assert.deepEqual(ovhRecordBodies("app.customer.com", records, zone), [
    { fieldType: "TXT", subDomain: "_dodomain-challenge.app", target: "dodomain-verify=abc" },
    { fieldType: "CNAME", subDomain: "app", target: "edge.example.net." },
    { fieldType: "MX", subDomain: "app", target: "10 mx.example.net." },
    { fieldType: "A", subDomain: "app", target: "192.0.2.1", ttl: 300 },
  ]);
  assert.deepEqual(
    ovhRecordBodies("customer.com", [{ type: "A", host: "@", value: "192.0.2.1" }], zone),
    [{ fieldType: "A", subDomain: "", target: "192.0.2.1" }],
  );
  assert.deepEqual(TIER_WRITABLE_TYPES.ovh_consent, ["A", "AAAA", "CNAME", "TXT", "MX"]);
  for (const type of RECORD_TYPES.filter((t) => !TIER_WRITABLE_TYPES.ovh_consent.includes(t)))
    assert.throws(
      () => ovhRecordBodies("customer.com", [{ type, host: "@", value: "x" }], zone),
      OvhError,
      type,
    );
  assert.throws(
    () => ovhRecordBodies("other.com", [{ type: "A", host: "@", value: "192.0.2.1" }], zone),
    OvhError,
  );
  assert.throws(
    () =>
      ovhRecordBodies("customer.com", [{ type: "MX", host: "@", value: "mx.example.net" }], zone),
    OvhError,
  );
  assert.throws(() => ovhRecordBodies("customer.com", [], zone), OvhError);
});

interface MockRecord {
  id: number;
  fieldType: string;
  subDomain: string;
  target: string;
}

/** MOCK OVH API for one zone: records, credential status, revoke. No network. */
function mockOvh(
  options: {
    status?: string;
    rules?: unknown;
    existing?: MockRecord[];
    failAt?: { path: RegExp; method?: string; status: number; body?: unknown };
  } = {},
) {
  const events: string[] = [];
  const signed: { url: string; method: string; headers: Record<string, string>; body: string }[] =
    [];
  const existing = options.existing ?? [];
  const fetcher = (async (input: Parameters<typeof fetch>[0], init: RequestInit = {}) => {
    const url = new URL(urlOf(input));
    const method = init.method ?? "GET";
    const headers = (init.headers ?? {}) as Record<string, string>;
    const path = url.pathname.replace(/^\/1\.0/, "");
    if (headers["X-Ovh-Signature"]) {
      signed.push({ url: url.toString(), method, headers, body: bodyOf(init) });
    }
    const fail = options.failAt;
    if (fail && fail.path.test(path) && (fail.method ?? method) === method) {
      events.push(`fail:${method} ${path}`);
      return Response.json(fail.body ?? { message: "mock failure" }, { status: fail.status });
    }
    if (path === "/auth/time") {
      events.push("time");
      return Response.json(Math.floor(Date.now() / 1000) + 5);
    }
    if (path === "/auth/currentCredential") {
      events.push("credential");
      return Response.json({
        status: options.status ?? "validated",
        rules: options.rules === undefined ? ovhZoneAccessRules(zone) : options.rules,
      });
    }
    if (path === "/auth/logout") {
      events.push("revoke");
      return new Response(null, { status: 200 });
    }
    if (path === `/domain/zone/${zone}/record` && method === "GET") {
      events.push("list");
      const sub = url.searchParams.get("subDomain");
      return Response.json(existing.filter((r) => r.subDomain === sub).map((r) => r.id));
    }
    const one = new RegExp(`^/domain/zone/${zone}/record/(\\d+)$`).exec(path);
    if (one && method === "GET") {
      events.push("get");
      return Response.json(existing.find((r) => r.id === Number(one[1])));
    }
    if (path === `/domain/zone/${zone}/record` && method === "POST") {
      events.push(`write:${JSON.parse(bodyOf(init)).fieldType}`);
      return Response.json({ id: 99, zone, ...JSON.parse(bodyOf(init)) });
    }
    if (path === `/domain/zone/${zone}/refresh` && method === "POST") {
      events.push("refresh");
      return new Response(null, { status: 200 });
    }
    events.push(`unexpected:${method} ${path}`);
    return Response.json({}, { status: 404 });
  }) as typeof fetch;
  return { events, signed, fetcher };
}

const applyInput = (records: SessionRecord[]) => ({
  region: "eu" as const,
  application,
  consumerKey: CK,
  zone,
  domain: "app.customer.com",
  records,
  expiresAt: new Date(Date.now() + 3600_000),
});

test("an OVH apply checks the validated credential, reads, writes, refreshes the zone, then revokes the key", async () => {
  const mock = mockOvh();
  const outcome = await applyOvhRecords(
    applyInput([{ type: "TXT", host: "@", value: "mock-proof" }]),
    mock.fetcher,
  );
  assert.deepEqual(outcome, { ok: true, revokeFailure: null });
  assert.deepEqual(mock.events, ["time", "credential", "list", "write:TXT", "refresh", "revoke"]);
  for (const call of mock.signed) {
    assert.equal(call.headers["X-Ovh-Application"], AK);
    assert.equal(call.headers["X-Ovh-Consumer"], CK);
    assert.equal(
      call.headers["X-Ovh-Signature"],
      signOvhRequest({
        appSecret: AS,
        consumerKey: CK,
        method: call.method,
        url: call.url,
        body: call.body,
        timestamp: call.headers["X-Ovh-Timestamp"]!,
      }),
    );
  }
  assert.ok(
    mock.signed.some(
      (call) => call.url === `${OVH_API_BASES.eu}/domain/zone/${zone}/record?subDomain=app`,
    ),
  );
});

test("an OVH apply whose records already exist writes nothing, skips the refresh and still revokes", async () => {
  const mock = mockOvh({
    existing: [{ id: 1, fieldType: "TXT", subDomain: "app", target: '"mock-proof"' }],
  });
  const outcome = await applyOvhRecords(
    applyInput([{ type: "TXT", host: "@", value: "mock-proof" }]),
    mock.fetcher,
  );
  assert.equal(outcome.ok, true);
  assert.deepEqual(mock.events, ["time", "credential", "list", "get", "revoke"]);
});

test("an OVH consent the user refused, left pending or let expire writes nothing and names the reason", async () => {
  for (const [status, stage] of [
    ["refused", "refused"],
    ["pendingValidation", "pending"],
    ["expired", "expired"],
  ] as const) {
    const mock = mockOvh({ status });
    const outcome = await applyOvhRecords(
      applyInput([{ type: "A", host: "@", value: "192.0.2.1" }]),
      mock.fetcher,
    );
    assert.equal(outcome.ok, false);
    assert.equal(!outcome.ok && outcome.error.stage, stage);
    assert.equal(
      mock.events.some((e) => e.startsWith("write")),
      false,
    );
    assert.equal(mock.events.at(-1), "revoke");
  }
});

test("an OVH credential carrying any rule beyond the requested zone is refused before reading records", async () => {
  const mock = mockOvh({ rules: [...ovhZoneAccessRules(zone), { method: "GET", path: "/me" }] });
  const outcome = await applyOvhRecords(
    applyInput([{ type: "A", host: "@", value: "192.0.2.1" }]),
    mock.fetcher,
  );
  assert.equal(!outcome.ok && outcome.error.stage, "scope");
  assert.deepEqual(mock.events, ["time", "credential", "revoke"]);
});

test("an OVH key the customer revoked after approving surfaces as revoked, never as a silent failure", async () => {
  const mock = mockOvh({
    failAt: {
      path: /^\/auth\/currentCredential$/,
      status: 403,
      body: { class: "Client::Forbidden", message: "This credential is not valid" },
    },
  });
  const outcome = await applyOvhRecords(
    applyInput([{ type: "A", host: "@", value: "192.0.2.1" }]),
    mock.fetcher,
  );
  assert.equal(outcome.ok, false);
  assert.ok(!outcome.ok && outcome.error.revoked && outcome.error.status === 403);
  assert.equal(outcome.revokeFailure, null);
  assert.equal(
    inspect(outcome, { depth: null, showHidden: true }).includes("This credential is not valid"),
    false,
  );
});

test("an OVH conflicting CNAME, a differing A or a second SPF policy is refused before any write", async () => {
  for (const [existing, record] of [
    [
      { id: 1, fieldType: "CNAME", subDomain: "app", target: "other.example.net." },
      { type: "A", host: "@", value: "192.0.2.1" },
    ],
    [
      { id: 1, fieldType: "A", subDomain: "app", target: "198.51.100.7" },
      { type: "A", host: "@", value: "192.0.2.1" },
    ],
    [
      { id: 1, fieldType: "TXT", subDomain: "app", target: '"v=spf1 include:other.example ~all"' },
      { type: "TXT", host: "@", value: "v=spf1 include:amazonses.com ~all" },
    ],
  ] as const) {
    const mock = mockOvh({ existing: [existing] });
    const outcome = await applyOvhRecords(applyInput([record as SessionRecord]), mock.fetcher);
    assert.equal(!outcome.ok && outcome.error.stage, "conflict", JSON.stringify(existing));
    assert.equal(
      mock.events.some((e) => e.startsWith("write") || e === "refresh"),
      false,
    );
    assert.equal(mock.events.at(-1), "revoke");
  }
});

test("an existing OVH CNAME stored relative to the zone matches the same absolute target and an unrelated TXT coexists", async () => {
  const mock = mockOvh({
    existing: [
      { id: 1, fieldType: "CNAME", subDomain: "app", target: "edge" },
      {
        id: 2,
        fieldType: "TXT",
        subDomain: "_dodomain-challenge.app",
        target: '"google-site-verification=x"',
      },
    ],
  });
  const outcome = await applyOvhRecords(
    applyInput([
      { type: "CNAME", host: "@", value: "edge.customer.com" },
      { type: "TXT", host: "_dodomain-challenge", value: "dodomain-verify=abc" },
    ]),
    mock.fetcher,
  );
  assert.equal(outcome.ok, true);
  assert.deepEqual(
    mock.events.filter((e) => e.startsWith("write")),
    ["write:TXT"],
  );
});

test("an OVH write failure still refreshes nothing, revokes the key and keeps the response body out of the error", async () => {
  const mock = mockOvh({
    failAt: {
      path: new RegExp(`^/domain/zone/${zone}/record$`),
      method: "POST",
      status: 400,
      body: { message: CK },
    },
  });
  const outcome = await applyOvhRecords(
    applyInput([{ type: "A", host: "@", value: "192.0.2.1" }]),
    mock.fetcher,
  );
  assert.equal(!outcome.ok && outcome.error.stage, "write");
  assert.equal(!outcome.ok && outcome.error.status, 400);
  assert.equal(mock.events.includes("refresh"), false);
  assert.equal(mock.events.at(-1), "revoke");
  assert.equal(inspect(outcome, { depth: null, showHidden: true }).includes(CK), false);
});

test("an OVH revoke failure is reported on its own and never turns a landed apply into a failure", async () => {
  const mock = mockOvh({ failAt: { path: /^\/auth\/logout$/, method: "POST", status: 500 } });
  const outcome = await applyOvhRecords(
    applyInput([{ type: "A", host: "@", value: "192.0.2.1" }]),
    mock.fetcher,
  );
  assert.equal(outcome.ok, true);
  assert.ok(outcome.revokeFailure instanceof OvhError);
  assert.equal(outcome.revokeFailure.stage, "revoke");
  assert.equal(outcome.revokeFailure.status, 500);
});
