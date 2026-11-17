import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import {
  applyDigitalOceanRecords,
  buildDigitalOceanAuthorizeUrl,
  digitaloceanPkce,
  digitaloceanRecordBodies,
  digitaloceanOwnedZone,
  registerDigitalOceanClient,
  DIGITALOCEAN_AUTHORIZE_URL,
  DIGITALOCEAN_TOKEN_URL,
  DIGITALOCEAN_REVOKE_URL,
  DigitalOceanError,
} from "../src/digitalocean.ts";
import { detectProvider } from "../src/detect.ts";
import type { SessionRecord } from "../src/records.ts";

const config = {
  clientId: "mock-public-client",
  redirectUri: "https://dev-app.dodomain.io/api/v1/digitalocean/callback",
};
const records: SessionRecord[] = [{ type: "TXT", host: "@", value: "mock-proof" }];
const input = {
  config,
  code: "mock-code",
  verifier: "mock-verifier",
  domain: "app.customer.com",
  records,
  expiresAt: new Date(Date.now() + 3600_000),
};
const mockCredential = "MOCK-CREDENTIAL-NEVER-LOG";
function urlOf(input: Parameters<typeof fetch>[0]): URL {
  return new URL(input instanceof Request ? input.url : input.toString());
}
function bodyOf(init?: RequestInit): string {
  assert.equal(typeof init?.body, "string");
  return init!.body as string;
}

// MOCK DigitalOcean HTTP. Every call is confined to these fake responses;
// no real provider, resolver, database, credentials or queue.
function mockDigitalOcean(
  options: {
    existing?: unknown[];
    domains?: unknown[];
    fail?: string;
    status?: number;
  } = {},
) {
  const calls: string[] = [];
  const writes: unknown[] = [];
  const revoked: string[] = [];
  const fetcher: typeof fetch = async (rawUrl, init) => {
    const url = urlOf(rawUrl);
    const stage =
      url.href === DIGITALOCEAN_TOKEN_URL
        ? "exchange"
        : url.href === DIGITALOCEAN_REVOKE_URL
          ? "revoke"
          : url.pathname === "/v2/domains"
            ? "portfolio"
            : init?.method === "POST" || init?.method === "PUT"
              ? "write"
              : "read";
    calls.push(stage);
    assert.equal(init?.cache, "no-store");
    assert.equal(init?.redirect, "error");
    assert.ok(init?.signal);
    assert.notEqual(init?.method, "DELETE");
    if (stage === "revoke") {
      assert.equal(new Headers(init?.headers).get("Authorization"), `Bearer ${mockCredential}`);
      revoked.push(new URLSearchParams(bodyOf(init)).get("token")!);
    }
    if (stage === options.fail)
      return Response.json({ message: mockCredential }, { status: options.status ?? 422 });
    if (stage === "exchange") {
      const body = new URLSearchParams(bodyOf(init));
      assert.equal(body.get("code_verifier"), input.verifier);
      assert.equal(body.get("grant_type"), "authorization_code");
      assert.equal(body.has("client_secret"), false);
      return Response.json({
        access_token: mockCredential,
        refresh_token: mockCredential,
        info: { team_uuid: "mock-team" },
      });
    }
    if (stage === "revoke") return Response.json({});
    assert.equal(new Headers(init?.headers).get("Authorization"), `Bearer ${mockCredential}`);
    assert.equal(url.origin, "https://api.digitalocean.com");
    if (stage === "portfolio")
      return Response.json({ domains: options.domains ?? [{ name: "customer.com" }] });
    if (stage === "read") return Response.json({ domain_records: options.existing ?? [] });
    writes.push(JSON.parse(bodyOf(init)));
    return Response.json({ domain_record: { id: 123 } }, { status: 201 });
  };
  return { calls, writes, revoked, fetcher };
}

test("DigitalOcean nameservers are detected at tier 3 while lookalikes stay unknown", async () => {
  for (const ns of [
    "ns1.digitalocean.com",
    "ns2.digitalocean.com",
    "NS3.DIGITALOCEAN.COM.",
    "ns1.evil-digitalocean.com",
    "ns1.digitalocean.com.evil.example",
  ]) {
    const match = await detectProvider("customer.com", {
      // MOCK DNS and discovery, no external requests.
      resolveNs: async () => [ns],
      parentNs: async () => [ns],
      discover: async () => {
        throw new Error("MOCK no Domain Connect");
      },
    });
    assert.equal(match.provider, ns.includes("evil") ? "unknown" : "digitalocean");
    assert.equal(match.tier, 3);
    assert.equal(match.method, "guided");
    if (!ns.includes("evil")) assert.equal(match.confidence, "high");
  }
});

test("authorize uses PKCE S256, public client parameters and only the three DNS scopes", () => {
  const { verifier, challenge } = digitaloceanPkce();
  assert.match(verifier, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(challenge, createHash("sha256").update(verifier).digest("base64url"));
  assert.notEqual(digitaloceanPkce().verifier, verifier);
  const state = "s".repeat(32);
  const url = new URL(buildDigitalOceanAuthorizeUrl(config, state, challenge));
  assert.equal(url.origin + url.pathname, DIGITALOCEAN_AUTHORIZE_URL);
  assert.deepEqual(Object.fromEntries(url.searchParams), {
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    response_type: "code",
    scope: "domain:read domain:create domain:update",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  assert.equal(url.href.includes(verifier), false);
  assert.throws(() => buildDigitalOceanAuthorizeUrl(config, "bad", challenge));
});

test("DCR registers the callback as a public client and exposes only its client id", async () => {
  const clientId = await registerDigitalOceanClient(config.redirectUri, async (url, init) => {
    assert.equal(urlOf(url).href, "https://cloud.digitalocean.com/v1/oauth/register");
    assert.equal(init?.method, "POST");
    assert.deepEqual(JSON.parse(bodyOf(init)), {
      client_name: "DoDomain",
      redirect_uris: [config.redirectUri],
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
    });
    return Response.json({ client_id: "mock-client", registration_access_token: mockCredential });
  });
  assert.equal(clientId, "mock-client");
  await assert.rejects(
    registerDigitalOceanClient("https://evil.example/incorrect"),
    /register failed/,
  );
});

test("longest owned suffix wins, including delegated zones and label boundaries", () => {
  const rows = [
    null,
    {},
    { name: "" },
    { name: "not a domain!" },
    { name: "CUSTOMER.COM." },
    { name: "app.customer.com" },
  ];
  assert.equal(digitaloceanOwnedZone("www.app.customer.com", rows), "app.customer.com");
  assert.equal(digitaloceanOwnedZone("app.customer.com", rows), "app.customer.com");
  assert.equal(digitaloceanOwnedZone("evilcustomer.com", rows), null);
});

test("record bodies use zone-relative names, raw unquoted TXT, absolute CNAME and separate MX priority", () => {
  assert.deepEqual(
    digitaloceanRecordBodies(
      "app.customer.com",
      [
        { type: "TXT", host: "@", value: 'Case "Sensitive" \\ proof', ttl: 300 },
        { type: "CNAME", host: "www", value: "Target.example." },
        { type: "MX", host: "mail", value: "mx.example", priority: 0 },
      ],
      "app.customer.com",
    ),
    [
      { type: "TXT", name: "@", data: 'Case "Sensitive" \\ proof', ttl: 300 },
      { type: "CNAME", name: "www", data: "Target.example." },
      { type: "MX", name: "mail", data: "mx.example.", priority: 0 },
    ],
  );
  assert.equal(digitaloceanRecordBodies(input.domain, records, "customer.com")[0]!.name, "app");
  for (const type of ["SRV", "CAA", "NS"]) {
    assert.throws(
      () =>
        digitaloceanRecordBodies(input.domain, [
          { type: type as SessionRecord["type"], host: "@", value: "mock" },
        ]),
      /records failed/,
    );
  }
  assert.throws(
    () => digitaloceanRecordBodies(input.domain, [{ type: "MX", host: "@", value: "mx.example" }]),
    /records failed/,
  );
});

test("missing records are created then credentials are revoked before returning", async () => {
  const mock = mockDigitalOcean();
  assert.deepEqual(await applyDigitalOceanRecords(input, mock.fetcher), {
    ok: true,
    revokeFailure: null,
  });
  assert.deepEqual(mock.calls, ["exchange", "portfolio", "read", "write", "revoke"]);
  assert.deepEqual(mock.writes, [{ type: "TXT", name: "app", data: "mock-proof" }]);
});

for (const [label, requested, existing] of [
  ["address", { type: "A", host: "@", value: "192.0.2.1" }, { type: "A", data: "192.0.2.2" }],
  [
    "CNAME value",
    { type: "CNAME", host: "@", value: "new.example" },
    { type: "CNAME", data: "old.example." },
  ],
  [
    "CNAME coexistence",
    { type: "TXT", host: "@", value: "mock" },
    { type: "CNAME", data: "old.example." },
  ],
  [
    "MX",
    { type: "MX", host: "@", value: "new.example", priority: 10 },
    { type: "MX", data: "old.example.", priority: 10 },
  ],
  [
    "MX priority",
    { type: "MX", host: "@", value: "mx.example", priority: 10 },
    { type: "MX", data: "mx.example.", priority: 20 },
  ],
  [
    "SPF",
    { type: "TXT", host: "@", value: "v=spf1 include:new.example -all" },
    { type: "TXT", data: '"v=spf1 include:old.example -all"' },
  ],
] as const) {
  test(`Hostinger-compatible ${label} conflict stays untouched, with revocation`, async () => {
    const mock = mockDigitalOcean({ existing: [{ id: 1, name: "app", ...existing }] });
    const outcome = await applyDigitalOceanRecords(
      { ...input, records: [requested] },
      mock.fetcher,
    );
    assert.equal(outcome.ok, false);
    if (!outcome.ok) assert.equal(outcome.error.message, "DigitalOcean conflict failed");
    assert.deepEqual(mock.writes, []);
    assert.equal(mock.calls.at(-1), "revoke");
  });
}

test("unrelated TXT values coexist; canonical TXT and dotted CNAME are not rewritten", async () => {
  const coexist = mockDigitalOcean({
    existing: [{ id: 1, name: "app", type: "TXT", data: '"v=spf1 -all"' }],
  });
  assert.equal((await applyDigitalOceanRecords(input, coexist.fetcher)).ok, true);
  assert.equal(coexist.writes.length, 1);
  for (const [record, data] of [
    [{ type: "TXT", host: "@", value: "mock-proof" }, '"mock-proof"'],
    [{ type: "CNAME", host: "@", value: "target.example" }, "target.example."],
  ] as const) {
    const mock = mockDigitalOcean({ existing: [{ id: 1, name: "app", type: record.type, data }] });
    assert.equal(
      (await applyDigitalOceanRecords({ ...input, records: [record] }, mock.fetcher)).ok,
      true,
    );
    assert.deepEqual(mock.writes, []);
  }
});

test("equivalent records are applied without canonicalization writes or TTL changes", async () => {
  for (const [record, data] of [
    [{ type: "TXT", host: "@", value: "mock-proof", ttl: 300 }, '"mock" "-proof"'],
    [{ type: "CNAME", host: "@", value: "target.example", ttl: 300 }, "TARGET.EXAMPLE"],
  ] as const) {
    const mock = mockDigitalOcean({
      existing: [{ id: 42, name: "app", type: record.type, data, ttl: 3600 }],
    });
    const fetcher: typeof fetch = (url, init) => {
      if (urlOf(url).pathname.startsWith("/v2/domains/") && init?.method !== undefined) {
        assert.fail("an equivalent customer record must never be written");
      }
      return mock.fetcher(url, init);
    };
    assert.equal(
      (await applyDigitalOceanRecords({ ...input, records: [record] }, fetcher)).ok,
      true,
    );
    assert.deepEqual(mock.writes, []);
  }
  const policy = mockDigitalOcean({
    existing: [
      {
        id: 42,
        name: "app",
        type: "TXT",
        data: '"v=spf1 include:new.example include:old.example -all"',
      },
    ],
  });
  assert.equal(
    (
      await applyDigitalOceanRecords(
        {
          ...input,
          records: [{ type: "TXT", host: "@", value: "v=spf1 include:new.example -all" }],
        },
        policy.fetcher,
      )
    ).ok,
    true,
  );
  assert.deepEqual(policy.writes, []);
  const missingTtl = mockDigitalOcean({
    existing: [{ id: 42, name: "app", type: "TXT", data: '"mock" "-proof"' }],
  });
  assert.equal((await applyDigitalOceanRecords(input, missingTtl.fetcher)).ok, true);
  assert.deepEqual(missingTtl.writes, []);
});

for (const [type, values] of [
  ["MX", ["mx1.example", "mx2.example"]],
  ["A", ["192.0.2.1", "192.0.2.2"]],
  ["AAAA", ["2001:db8::1", "2001:db8::2"]],
  ["TXT", ["mock-proof-one", "mock-proof-two"]],
] as const) {
  test(`a partial ${type} write retries only missing members and a complete set needs no writes`, async () => {
    const requested: SessionRecord[] = values.map((value, index) => ({
      type,
      host: "@",
      value,
      ...(type === "MX" ? { priority: index * 10 } : {}),
    }));
    // MOCK persistent provider snapshot: the first write lands, the second fails once.
    const existing: unknown[] = [];
    const mock = mockDigitalOcean({ existing });
    let failSecond = true;
    const fetcher: typeof fetch = async (url, init) => {
      if (urlOf(url).pathname.endsWith("/records") && init?.method === "POST") {
        if (existing.length === 1 && failSecond) {
          failSecond = false;
          return Response.json({}, { status: 500 });
        }
        const body = JSON.parse(bodyOf(init)) as Record<string, unknown>;
        existing.push({ id: existing.length + 1, ...body });
      }
      return mock.fetcher(url, init);
    };
    assert.equal(
      (await applyDigitalOceanRecords({ ...input, records: requested }, fetcher)).ok,
      false,
    );
    assert.equal(existing.length, 1);
    assert.equal(
      (await applyDigitalOceanRecords({ ...input, records: requested }, fetcher)).ok,
      true,
    );
    assert.equal(existing.length, 2);
    assert.equal(mock.writes.length, 2);
    assert.equal(
      (await applyDigitalOceanRecords({ ...input, records: requested }, fetcher)).ok,
      true,
    );
    assert.equal(mock.writes.length, 2);
    assert.equal(mock.revoked.length, 3);
  });
}

for (const requested of [
  [
    { type: "CNAME", host: "@", value: "target.example" },
    { type: "TXT", host: "app.customer.com", value: "mock-proof" },
  ],
  [
    { type: "CNAME", host: "@", value: "one.example" },
    { type: "CNAME", host: "@", value: "two.example" },
  ],
  [
    { type: "TXT", host: "@", value: "v=spf1 include:one.example -all" },
    { type: "TXT", host: "@", value: "v=spf1 include:two.example -all" },
  ],
] satisfies SessionRecord[][]) {
  test(`requested ${requested.map((r) => r.type).join("/")} conflicts are refused before any write in either order`, async () => {
    for (const batch of [requested, [...requested].reverse()]) {
      const mock = mockDigitalOcean();
      const outcome = await applyDigitalOceanRecords(
        { ...input, records: [{ type: "TXT", host: "unrelated", value: "mock-proof" }, ...batch] },
        mock.fetcher,
      );
      assert.equal(outcome.ok, false);
      if (!outcome.ok) assert.equal(outcome.error.message, "DigitalOcean conflict failed");
      assert.deepEqual(mock.writes, []);
      assert.equal(mock.calls.at(-1), "revoke");
    }
  });
}

test("TTLs below thirty seconds reject the whole batch before any write", async () => {
  for (const ttl of [1, 29]) {
    const requested: SessionRecord[] = [
      { type: "TXT", host: "first", value: "mock-first", ttl: 300 },
      { type: "TXT", host: "second", value: "mock-second", ttl },
    ];
    assert.throws(() => digitaloceanRecordBodies(input.domain, requested), /records failed/);
    const mock = mockDigitalOcean();
    const outcome = await applyDigitalOceanRecords({ ...input, records: requested }, mock.fetcher);
    assert.equal(outcome.ok, false);
    assert.deepEqual(mock.writes, []);
    assert.equal(mock.calls.at(-1), "revoke");
  }
  for (const ttl of [30, 300, undefined]) {
    const requested: SessionRecord[] = [
      { type: "TXT", host: "@", value: "mock", ...(ttl === undefined ? {} : { ttl }) },
    ];
    const mock = mockDigitalOcean();
    assert.equal(
      (await applyDigitalOceanRecords({ ...input, records: requested }, mock.fetcher)).ok,
      true,
    );
    assert.deepEqual(mock.writes, [
      { type: "TXT", name: "app", data: "mock", ...(ttl === undefined ? {} : { ttl }) },
    ]);
  }
});

test("all requested conflicts are checked before any write and duplicate requests create only once", async () => {
  const mock = mockDigitalOcean({
    existing: [{ id: 1, name: "app", type: "A", data: "192.0.2.3" }],
  });
  const conflict = await applyDigitalOceanRecords(
    {
      ...input,
      records: [
        { type: "TXT", host: "new", value: "mock" },
        { type: "A", host: "@", value: "192.0.2.1" },
        { type: "A", host: "@", value: "192.0.2.2" },
      ],
    },
    mock.fetcher,
  );
  assert.equal(conflict.ok, false);
  assert.deepEqual(mock.writes, []);
  const duplicate = mockDigitalOcean();
  assert.equal(
    (
      await applyDigitalOceanRecords(
        { ...input, records: [...records, ...records] },
        duplicate.fetcher,
      )
    ).ok,
    true,
  );
  assert.equal(duplicate.writes.length, 1);
});

test("an explicitly requested multi-value MX set is created together when the name has no MX", async () => {
  const mock = mockDigitalOcean();
  const outcome = await applyDigitalOceanRecords(
    {
      ...input,
      records: [
        { type: "MX", host: "@", value: "mx1.example", priority: 10 },
        { type: "MX", host: "@", value: "mx2.example", priority: 20 },
      ],
    },
    mock.fetcher,
  );
  assert.equal(outcome.ok, true);
  assert.equal(mock.writes.length, 2);
});

test("paginated zones choose the more specific zone and a later record page blocks writes", async () => {
  const mock = mockDigitalOcean();
  const readUrls: string[] = [];
  const fetcher: typeof fetch = (rawUrl, init) => {
    const url = urlOf(rawUrl);
    if (url.pathname === "/v2/domains")
      return Promise.resolve(
        Response.json({
          domains: [
            { name: url.searchParams.get("page") === "1" ? "customer.com" : "app.customer.com" },
          ],
          ...(url.searchParams.get("page") === "1"
            ? { links: { pages: { next: "https://evil.example/steal" } } }
            : {}),
        }),
      );
    if (url.pathname.endsWith("/records") && init?.method !== "POST") {
      readUrls.push(url.href);
      return Promise.resolve(
        Response.json({
          domain_records:
            url.searchParams.get("page") === "1"
              ? []
              : [{ id: 1, name: "@", type: "CNAME", data: "old.example." }],
          ...(url.searchParams.get("page") === "1"
            ? { links: { pages: { next: "https://evil.example/steal" } } }
            : {}),
        }),
      );
    }
    return mock.fetcher(rawUrl, init);
  };
  const outcome = await applyDigitalOceanRecords(input, fetcher);
  assert.equal(outcome.ok, false);
  assert.deepEqual(
    readUrls,
    [1, 2].map(
      (p) =>
        `https://api.digitalocean.com/v2/domains/app.customer.com/records?per_page=200&page=${p}`,
    ),
  );
  assert.deepEqual(mock.writes, []);
  assert.equal(mock.calls.at(-1), "revoke");
});

for (const stage of ["portfolio", "read", "write"]) {
  for (const status of [401, 403, 422, 429]) {
    test(`DigitalOcean ${stage} HTTP ${status} exposes fixed diagnostics and still revokes`, async () => {
      const mock = mockDigitalOcean({ fail: stage, status });
      const outcome = await applyDigitalOceanRecords(input, mock.fetcher);
      assert.equal(outcome.ok, false);
      if (!outcome.ok) {
        assert.ok(outcome.error instanceof DigitalOceanError);
        assert.equal(outcome.error.status, status);
        assert.equal(outcome.error.stage, stage);
        assert.equal(outcome.error.cause, undefined);
      }
      assert.equal(JSON.stringify(outcome).includes(mockCredential), false);
      assert.equal(mock.calls.at(-1), "revoke");
    });
  }
}

test("malformed exchange still revokes issued credentials and tries both after revoke failure", async () => {
  const revoked: string[] = [];
  const outcome = await applyDigitalOceanRecords(input, async (url, init) => {
    if (urlOf(url).href === DIGITALOCEAN_TOKEN_URL)
      return Response.json({ access_token: "", refresh_token: "MOCK-refresh" });
    assert.equal(urlOf(url).href, DIGITALOCEAN_REVOKE_URL);
    revoked.push(new URLSearchParams(bodyOf(init)).get("token")!);
    return Response.json({});
  });
  assert.equal(outcome.ok, false);
  assert.deepEqual(revoked, ["MOCK-refresh"]);
  const mock = mockDigitalOcean({ fail: "revoke", status: 503 });
  const second = await applyDigitalOceanRecords(input, (url, init) =>
    urlOf(url).href === DIGITALOCEAN_TOKEN_URL
      ? Promise.resolve(
          Response.json({ access_token: mockCredential, refresh_token: "MOCK-refresh" }),
        )
      : mock.fetcher(url, init),
  );
  assert.equal(second.ok, true);
  assert.equal(second.revokeFailure?.status, 503);
  assert.deepEqual(mock.revoked, ["MOCK-refresh", mockCredential]);
});

test("expiry and transport exceptions stop writes and do not prevent revocation", async () => {
  const expired = mockDigitalOcean();
  assert.equal(
    (await applyDigitalOceanRecords({ ...input, expiresAt: new Date(0) }, expired.fetcher)).ok,
    false,
  );
  assert.deepEqual(expired.writes, []);
  assert.equal(expired.calls.at(-1), "revoke");
  const mock = mockDigitalOcean();
  const outcome = await applyDigitalOceanRecords(input, (url, init) =>
    urlOf(url).pathname === "/v2/domains"
      ? Promise.reject(new Error(mockCredential))
      : mock.fetcher(url, init),
  );
  assert.equal(outcome.ok, false);
  assert.equal(JSON.stringify(outcome).includes(mockCredential), false);
  assert.equal(mock.calls.at(-1), "revoke");
});
