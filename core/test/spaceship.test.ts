import assert from "node:assert/strict";
import { test } from "node:test";

import {
  applySpaceshipRecords,
  normalizeSpaceshipZone,
  planSpaceshipWrite,
  spaceshipRecordItems,
  SpaceshipError,
  SPACESHIP_API_ORIGIN,
  type SpaceshipStage,
} from "../src/spaceship.ts";
import type { SessionRecord } from "../src/records.ts";

// MOCK credential values: not real Spaceship keys, chosen to be easy to find
// in any string they might leak into.
const MOCK_KEY = "MOCKSPACESHIPKEY0000";
const MOCK_SECRET = "MOCK-SPACESHIP-SECRET-DO-NOT-LOG-0000000000000000";
const credentials = { apiKey: MOCK_KEY, apiSecret: MOCK_SECRET };
const inAnHour = () => new Date(Date.now() + 3600_000);

interface Call {
  method: string;
  url: URL;
  headers: Record<string, string>;
  body: unknown;
}

/** MOCK Spaceship API: an in-memory account owning `customer.com`, with the
 * zone items given. Every override answers instead of the default route. No
 * network is ever opened. */
function mockSpaceshipFetch(
  zone: unknown[] = [],
  override: (call: Call) => Response | Promise<Response> | undefined = () => undefined,
) {
  const calls: Call[] = [];
  const fetcher: typeof fetch = async (input, init) => {
    const call: Call = {
      method: init?.method ?? "GET",
      url: new URL(input instanceof Request ? input.url : input.toString()),
      headers: Object.fromEntries(Object.entries((init?.headers ?? {}) as Record<string, string>)),
      body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
    };
    calls.push(call);
    assert.equal(init?.redirect, "error");
    assert.equal(init?.cache, "no-store");
    const answered = await override(call);
    if (answered) return answered;
    const path = call.url.pathname;
    if (path === "/api/v1/domains/customer.com") return Response.json({ name: "customer.com" });
    if (path === "/api/v1/dns/records/customer.com" && call.method === "GET") {
      const skip = Number(call.url.searchParams.get("skip"));
      const take = Number(call.url.searchParams.get("take"));
      return Response.json({ items: zone.slice(skip, skip + take), total: zone.length });
    }
    if (path === "/api/v1/dns/records/customer.com" && call.method === "PUT")
      return new Response(null, { status: 204 });
    return Response.json({ detail: "MOCK not found" }, { status: 404 });
  };
  return { fetcher, calls };
}

const cname: SessionRecord = { type: "CNAME", host: "app", value: "target.example.net." };

test("save-records items are named relative to the registered zone with each type's own value field", () => {
  const items = spaceshipRecordItems("app.customer.com", [
    { type: "CNAME", host: "@", value: "Target.Example.NET." },
    { type: "TXT", host: "_dodomain-challenge", value: "dodomain-verify=CaseMatters", ttl: 30 },
    { type: "MX", host: "@", value: "mx.example.net.", priority: 10, ttl: 86400 },
    { type: "A", host: "www", value: "192.0.2.10", ttl: 300 },
    { type: "AAAA", host: "v6", value: "2001:db8::1" },
  ]);
  assert.deepEqual(items, [
    { type: "CNAME", name: "app", cname: "Target.Example.NET" },
    // TXT goes as is (Spaceship matches TXT case-sensitively) and a TTL under
    // Spaceship's 60 s floor is raised to it.
    { type: "TXT", name: "_dodomain-challenge.app", ttl: 60, value: "dodomain-verify=CaseMatters" },
    // Over the 3600 s ceiling is lowered to it.
    { type: "MX", name: "app", ttl: 3600, exchange: "mx.example.net", preference: 10 },
    { type: "A", name: "www.app", ttl: 300, address: "192.0.2.10" },
    { type: "AAAA", name: "v6.app", address: "2001:db8::1" },
  ]);
  assert.deepEqual(spaceshipRecordItems("customer.com", [{ type: "TXT", host: "@", value: "x" }]), [
    { type: "TXT", name: "@", value: "x" },
  ]);
});

test("records Spaceship cannot take are refused before any provider call", () => {
  for (const records of [
    [],
    [{ type: "MX", host: "@", value: "mx.example.net" }],
    [{ type: "MX", host: "@", value: "mx.example.net", priority: 70000 }],
    [{ type: "TXT", host: "@", value: "x", ttl: 0 }],
    [{ type: "CAA", host: "@", value: "0 issue x" }],
    [{ type: "A", host: "@", value: "   " }],
  ] as SessionRecord[][]) {
    assert.throws(
      () => spaceshipRecordItems("customer.com", records),
      (err: unknown) => err instanceof SpaceshipError && err.stage === "records",
    );
  }
  assert.throws(
    () => spaceshipRecordItems("not a domain!", [cname]),
    (err: unknown) => err instanceof SpaceshipError && err.stage === "records",
  );
});

test("zone normalisation reads relative, apex and fully qualified names and every value field", () => {
  const zone = normalizeSpaceshipZone(
    [
      { type: "A", name: "@", address: "192.0.2.1", group: { type: "custom" } },
      {
        type: "cname",
        name: "APP.customer.com.",
        cname: "target.example.net.",
        group: { type: "custom" },
      },
      { type: "TXT", name: "customer.com", value: "v=spf1 -all", group: { type: "product" } },
      {
        type: "MX",
        name: "",
        exchange: "mx.example.net",
        preference: 5,
        group: { type: "custom" },
      },
      { type: "NS", name: "sub", nameserver: "ns1.example.net", group: { type: "custom" } },
    ],
    "customer.com",
  );
  assert.deepEqual(zone, [
    { name: "@", type: "A", answer: "192.0.2.1" },
    { name: "app", type: "CNAME", answer: "target.example.net." },
    { name: "@", type: "TXT", answer: "v=spf1 -all" },
    { name: "@", type: "MX", answer: "5 mx.example.net" },
    // A type we never compare by value can only ever conflict by type.
    { name: "sub", type: "NS", answer: null },
  ]);
});

test("a zone item that cannot be read with confidence is unreadable, never guessed", () => {
  for (const item of [
    null,
    { type: "A", name: "@" },
    { type: "TXT", name: "@", value: "" },
    { type: "MX", name: "@", exchange: "mx.example.net" },
    { type: "A", name: "bad name!", address: "192.0.2.1" },
    { type: "A?", name: "@", address: "192.0.2.1" },
  ]) {
    assert.throws(
      () => normalizeSpaceshipZone([item], "customer.com"),
      (err: unknown) => err instanceof SpaceshipError && err.stage === "unreadable",
    );
  }
});

test("the conflict guard skips records already present and refuses anything that changes the zone", () => {
  const plan = (records: SessionRecord[], existing: Parameters<typeof planSpaceshipWrite>[3]) =>
    planSpaceshipWrite("customer.com", records, "customer.com", existing);
  const conflict = (err: unknown) => err instanceof SpaceshipError && err.stage === "conflict";

  // Already there (host-like comparison): nothing to write.
  assert.deepEqual(
    plan([cname], [{ name: "app", type: "CNAME", answer: "TARGET.example.net" }]),
    [],
  );
  // An unrelated name or a TXT beside other TXTs is written.
  const proof: SessionRecord = { type: "TXT", host: "@", value: "dodomain-verify=abc" };
  assert.deepEqual(
    plan([cname, proof], [{ name: "@", type: "TXT", answer: "google-site-verification=x" }]),
    [cname, proof],
  );
  // A CNAME never shares its name, in either direction, nor does an ALIAS.
  assert.throws(() => plan([cname], [{ name: "app", type: "A", answer: "192.0.2.1" }]), conflict);
  assert.throws(
    () =>
      plan(
        [{ type: "A", host: "app", value: "192.0.2.2" }],
        [{ name: "app", type: "CNAME", answer: "x.example.net" }],
      ),
    conflict,
  );
  assert.throws(
    () =>
      plan(
        [{ type: "A", host: "@", value: "192.0.2.2" }],
        [{ name: "@", type: "ALIAS", answer: null }],
      ),
    conflict,
  );
  // A second A or MX value beside a different one would split traffic or mail.
  assert.throws(
    () =>
      plan(
        [{ type: "A", host: "@", value: "192.0.2.2" }],
        [{ name: "@", type: "A", answer: "192.0.2.1" }],
      ),
    conflict,
  );
  assert.throws(
    () =>
      plan(
        [{ type: "MX", host: "@", value: "mx.new.net", priority: 10 }],
        [{ name: "@", type: "MX", answer: "10 mx.old.net" }],
      ),
    conflict,
  );
  // A second, different SPF policy is refused; a different kind of TXT is not.
  assert.throws(
    () =>
      plan(
        [{ type: "TXT", host: "@", value: "v=spf1 include:amazonses.com ~all" }],
        [{ name: "@", type: "TXT", answer: "v=spf1 include:_spf.google.com ~all" }],
      ),
    conflict,
  );
});

test("an apply against the MOCK API proves ownership, reads every page and adds only the missing records", async () => {
  // 150 unrelated records: two pages of 100 at most, as the docs cap the GET.
  const filler = Array.from({ length: 150 }, (_, i) => ({
    type: "TXT",
    name: `filler${i}`,
    value: `v${i}`,
    group: { type: "custom" },
  }));
  const present = {
    type: "TXT",
    name: "_dd",
    value: "dodomain-verify=abc",
    group: { type: "custom" },
  };
  const mock = mockSpaceshipFetch([...filler, present]);
  const outcome = await applySpaceshipRecords(
    {
      credentials,
      domain: "customer.com",
      records: [cname, { type: "TXT", host: "_dd", value: "dodomain-verify=abc" }],
      expiresAt: inAnHour(),
    },
    mock.fetcher,
  );
  assert.deepEqual(outcome, { ok: true, written: 1 });
  assert.deepEqual(
    mock.calls.map((call) => `${call.method} ${call.url.pathname}${call.url.search}`),
    [
      "GET /api/v1/domains/customer.com",
      "GET /api/v1/dns/records/customer.com?take=100&skip=0",
      "GET /api/v1/dns/records/customer.com?take=100&skip=100",
      "PUT /api/v1/dns/records/customer.com",
    ],
  );
  for (const call of mock.calls) {
    assert.equal(call.url.origin + "/api/v1", SPACESHIP_API_ORIGIN);
    assert.equal(call.headers["X-API-Key"], MOCK_KEY);
    assert.equal(call.headers["X-API-Secret"], MOCK_SECRET);
  }
  // Additive upsert with Spaceship's conflict checker on; the present TXT is not resent.
  assert.deepEqual(mock.calls.at(-1)!.body, {
    force: false,
    items: [{ type: "CNAME", name: "app", cname: "target.example.net" }],
  });
  assert.equal(mock.calls.at(-1)!.headers["Content-Type"], "application/json");
});

test("records that are all present already send no write", async () => {
  const mock = mockSpaceshipFetch([
    { type: "CNAME", name: "app", cname: "target.example.net", group: { type: "custom" } },
  ]);
  const outcome = await applySpaceshipRecords(
    { credentials, domain: "customer.com", records: [cname], expiresAt: inAnHour() },
    mock.fetcher,
  );
  assert.deepEqual(outcome, { ok: true, written: 0 });
  assert.equal(
    mock.calls.some((call) => call.method !== "GET"),
    false,
  );
});

const failures: Array<{
  name: string;
  stage: SpaceshipStage;
  status?: number;
  zone?: unknown[];
  expiresAt?: Date;
  respond?: (call: Call) => Response | Promise<Response> | undefined;
}> = [
  {
    name: "a refused key",
    stage: "credentials",
    status: 401,
    respond: () => Response.json({ detail: "Api key or secret not provided." }, { status: 401 }),
  },
  {
    name: "a key without dnsrecords:write",
    stage: "scope",
    status: 403,
    respond: (c) =>
      c.method === "PUT" ? Response.json({ detail: "no" }, { status: 403 }) : undefined,
  },
  {
    name: "a domain outside the account",
    stage: "ownership",
    status: 404,
    respond: (c) =>
      c.url.pathname.startsWith("/api/v1/domains/")
        ? Response.json({}, { status: 404 })
        : undefined,
  },
  {
    name: "domain info naming another domain",
    stage: "ownership",
    respond: (c) =>
      c.url.pathname.startsWith("/api/v1/domains/")
        ? Response.json({ name: "other.com" })
        : undefined,
  },
  {
    name: "Spaceship's rate limit",
    stage: "rate_limited",
    status: 429,
    respond: () => new Response(null, { status: 429 }),
  },
  {
    name: "a zone read that fails in transit",
    stage: "read",
    respond: (c) => {
      if (c.url.pathname.startsWith("/api/v1/dns/"))
        throw new Error(`socket hang up ${MOCK_SECRET}`);
      return undefined;
    },
  },
  {
    name: "a zone read with a server error",
    stage: "read",
    status: 500,
    respond: (c) =>
      c.url.pathname.startsWith("/api/v1/dns/") ? Response.json({}, { status: 500 }) : undefined,
  },
  {
    name: "a zone answer in an unknown shape",
    stage: "unreadable",
    respond: (c) =>
      c.url.pathname.startsWith("/api/v1/dns/") ? Response.json({ records: [] }) : undefined,
  },
  {
    name: "an existing record in the way",
    stage: "conflict",
    zone: [{ type: "A", name: "app", address: "192.0.2.1", group: { type: "custom" } }],
  },
  {
    name: "Spaceship's own conflict checker",
    stage: "conflict",
    status: 422,
    respond: (c) =>
      c.method === "PUT"
        ? Response.json({ detail: "conflict", data: [] }, { status: 422 })
        : undefined,
  },
  {
    name: "a write that fails after it was sent",
    stage: "write",
    status: 500,
    respond: (c) =>
      c.method === "PUT" ? Response.json({ detail: MOCK_SECRET }, { status: 500 }) : undefined,
  },
  { name: "a session that expired before the write", stage: "expired", expiresAt: new Date(0) },
];

for (const failure of failures) {
  test(`${failure.name} stops the apply at ${failure.stage} with no key material on the error`, async () => {
    const mock = mockSpaceshipFetch(failure.zone ?? [], failure.respond);
    const outcome = await applySpaceshipRecords(
      {
        credentials,
        domain: "customer.com",
        records: [cname],
        expiresAt: failure.expiresAt ?? inAnHour(),
      },
      mock.fetcher,
    );
    assert.equal(outcome.ok, false);
    if (outcome.ok) return;
    const { error } = outcome;
    assert.ok(error instanceof SpaceshipError);
    assert.equal(error.stage, failure.stage);
    assert.equal(error.status, failure.status);
    assert.equal(error.cause, undefined);
    // The thrown error, every property it has and its stack carry no key or secret.
    const everything = [
      error.message,
      String(error.stack),
      JSON.stringify(error),
      JSON.stringify(Object.getOwnPropertyNames(error).map((k) => (error as never)[k])),
      JSON.stringify(outcome),
    ].join("\n");
    assert.equal(everything.includes(MOCK_KEY), false);
    assert.equal(everything.includes(MOCK_SECRET), false);
    // Never a delete, and no write after a refusal that came before it.
    assert.equal(
      mock.calls.some((call) => call.method === "DELETE"),
      false,
    );
    if (!["scope", "conflict", "write"].includes(failure.stage) || failure.zone)
      assert.equal(
        mock.calls.some((call) => call.method === "PUT"),
        false,
      );
  });
}

test("a transport exception that quotes the key becomes a fixed-stage error without it", async () => {
  const outcome = await applySpaceshipRecords(
    { credentials, domain: "customer.com", records: [cname], expiresAt: inAnHour() },
    (() => {
      throw new TypeError(`fetch exploded with ${MOCK_KEY}`);
    }) as unknown as typeof fetch,
  );
  assert.equal(outcome.ok, false);
  if (outcome.ok) return;
  assert.equal(outcome.error.stage, "ownership");
  assert.equal(String(outcome.error.stack).includes(MOCK_KEY), false);
});
