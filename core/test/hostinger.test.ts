import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import {
  applyHostingerRecords,
  buildHostingerAuthorizeUrl,
  hostingerPkce,
  hostingerZoneBody,
  HOSTINGER_AUTHORIZE_URL,
  HOSTINGER_TOKEN_URL,
  HOSTINGER_REVOKE_URL,
  type HostingerApplyOutcome,
} from "../src/hostinger.ts";
import { RECORD_TYPES, TIER_WRITABLE_TYPES } from "../src/record-capabilities.ts";
import type { SessionRecord } from "../src/records.ts";
import { detectProvider } from "../src/detect.ts";

const config = {
  clientId: "mock-public-client",
  redirectUri: "https://app.dodomain.io/api/v1/hostinger/callback",
};
const records: SessionRecord[] = [{ type: "TXT", host: "@", value: "mock-proof" }];

function requestUrl(input: Parameters<typeof fetch>[0]): string {
  return input instanceof Request ? input.url : input.toString();
}
function requestBody(init?: RequestInit): string {
  assert.ok(typeof init?.body === "string");
  return init.body;
}

test("Hostinger detection requires its nameserver domain and keeps the guided fallback", async () => {
  for (const nameserver of [
    "ns1.dns-parking.com",
    "ns2.dns-parking.com",
    "dns1.hostinger.com",
    "ns1.evil-dns-parking.com",
  ]) {
    // MOCK DNS; no provider or resolver network calls.
    const result = await detectProvider("customer.com", {
      resolveNs: async () => [nameserver],
      discover: async () => {
        throw new Error("MOCK no Domain Connect");
      },
    });
    assert.equal(result.provider, nameserver.includes("evil-") ? "unknown" : "hostinger");
    assert.equal(result.method, "guided");
    assert.equal(result.tier, 3);
  }
});

test("Hostinger authorize uses S256 and public client parameters without scopes or secrets", () => {
  const { verifier, challenge } = hostingerPkce();
  assert.match(verifier, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(challenge, createHash("sha256").update(verifier).digest("base64url"));
  assert.notEqual(hostingerPkce().verifier, verifier);
  const state = "s".repeat(32);
  const url = new URL(buildHostingerAuthorizeUrl(config, state, challenge));
  assert.equal(url.origin + url.pathname, HOSTINGER_AUTHORIZE_URL);
  assert.deepEqual(Object.fromEntries(url.searchParams), {
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    response_type: "code",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  assert.equal(url.toString().includes(verifier), false);
});

test("zone mapping groups values, preserves TXT and MX priority, and always appends", () => {
  const body = hostingerZoneBody("App.Customer.co.uk.", [
    { type: "TXT", host: "@", value: "Case Sensitive", ttl: 300 },
    { type: "TXT", host: "@", value: "second-value", ttl: 300 },
    { type: "MX", host: "mail", value: "mx.example.net", priority: 0 },
  ]);
  assert.deepEqual(body, {
    overwrite: false,
    zone: [
      {
        name: "app",
        type: "TXT",
        ttl: 300,
        records: [{ content: "Case Sensitive" }, { content: "second-value" }],
      },
      { name: "mail.app", type: "MX", records: [{ content: "0 mx.example.net" }] },
    ],
  });
  assert.equal(hostingerZoneBody("customer.com", records).zone[0]!.name, "@");
  // Every type in Hostinger's row of the type x tier matrix appends...
  for (const type of TIER_WRITABLE_TYPES.hostinger_oauth) {
    assert.equal(
      hostingerZoneBody("customer.com", [{ type, host: "www", value: "mock-value", priority: 10 }])
        .overwrite,
      false,
    );
  }
  // ...and every accepted type outside it (SRV, CAA, NS) fails closed, so a
  // session asking for one never reaches Hostinger's API half-written.
  const outside = RECORD_TYPES.filter((t) => !TIER_WRITABLE_TYPES.hostinger_oauth.includes(t));
  assert.ok(outside.length > 0);
  for (const type of outside) {
    assert.throws(
      () =>
        hostingerZoneBody("customer.com", [
          { type, host: "www", value: "mock-value", priority: 10 },
        ]),
      (err: unknown) => err instanceof Error && (err as { stage?: string }).stage === "records",
    );
  }
});

test("invalid or unsupported records fail closed instead of dropping part of a request", () => {
  for (const invalid of [
    [{ type: "SRV", host: "@", value: "bad" }],
    [{ type: "MX", host: "@", value: "mx.example.net" }],
    [{ type: "TXT", host: "@", value: "proof", ttl: -1 }],
    [],
  ])
    assert.throws(
      () => hostingerZoneBody("customer.com", invalid as SessionRecord[]),
      /Hostinger records failed/,
    );
});

// MOCK Hostinger HTTP, no credentials, network, or database. Every request is checked.
function mockHostinger(failure?: string) {
  const calls: string[] = [];
  const secret = "MOCK-account-token-never-log";
  const fetcher: typeof fetch = async (url, init) => {
    const endpoint = requestUrl(url);
    const stage =
      endpoint === HOSTINGER_TOKEN_URL
        ? "exchange"
        : endpoint === HOSTINGER_REVOKE_URL
          ? "revoke"
          : endpoint.endsWith("/portfolio")
            ? "portfolio"
            : endpoint.endsWith("/validate")
              ? "validate"
              : init?.method === "PUT"
                ? "write"
                : "read";
    calls.push(stage);
    assert.equal(init?.cache, "no-store");
    assert.equal(init?.redirect, "error");
    assert.ok(init?.signal);
    assert.notEqual(init?.method, "DELETE");
    if (stage === failure)
      return new Response(JSON.stringify({ message: secret }), { status: 422 });
    if (stage === "exchange") {
      const body = new URLSearchParams(requestBody(init));
      assert.equal(body.get("grant_type"), "authorization_code");
      assert.equal(body.get("code_verifier"), "mock-verifier");
      assert.equal(body.has("client_secret"), false);
      return Response.json({ access_token: secret, refresh_token: secret });
    }
    if (stage === "revoke") {
      assert.deepEqual(JSON.parse(requestBody(init)), {
        token: secret,
        client_id: config.clientId,
      });
      return Response.json({});
    }
    assert.equal(new Headers(init?.headers).get("Authorization"), `Bearer ${secret}`);
    if (stage === "portfolio")
      return Response.json(
        failure === "ownership" ? [{ domain: "foreign.com" }] : [{ domain: "CUSTOMER.COM." }],
      );
    if (stage === "read") return Response.json([]);
    const body = JSON.parse(requestBody(init));
    assert.equal(body.overwrite, false);
    assert.equal(body.zone[0].name, "app");
    return Response.json({ message: "Request accepted" });
  };
  return { calls, secret, fetcher };
}
const input = {
  config,
  code: "mock-code",
  verifier: "mock-verifier",
  domain: "app.customer.com",
  records,
  expiresAt: new Date(Date.now() + 3600_000),
};

/** The operation's own failure; the outcome must not be a success. */
function failureOf(outcome: HostingerApplyOutcome): Error {
  assert.equal(outcome.ok, false);
  return (outcome as { error: Error }).error;
}

test("portfolio ownership precedes validation/write and success revokes before returning", async () => {
  const mock = mockHostinger();
  assert.deepEqual(await applyHostingerRecords(input, mock.fetcher), {
    ok: true,
    revokeFailure: null,
  });
  assert.deepEqual(mock.calls, ["exchange", "portfolio", "read", "validate", "write", "revoke"]);
});

for (const stage of ["portfolio", "ownership", "read", "validate", "write"]) {
  test(`Hostinger ${stage} failure revokes the token and exposes no provider body`, async () => {
    const mock = mockHostinger(stage);
    const outcome = await applyHostingerRecords(input, mock.fetcher);
    const error = failureOf(outcome);
    assert.match(error.message, new RegExp(`Hostinger ${stage} failed`));
    assert.equal(JSON.stringify(outcome).includes(mock.secret), false);
    assert.equal(error.stack?.includes(mock.secret), false);
    assert.equal(error.cause, undefined);
    assert.equal(outcome.revokeFailure, null);
    assert.equal(mock.calls.at(-1), "revoke");
    assert.equal(mock.calls.filter((call) => call === "revoke").length, 1);
    if (stage === "ownership") assert.deepEqual(mock.calls, ["exchange", "portfolio", "revoke"]);
  });
}

test("a revoke failure after a landed write never masks the write: ok stays true, the failure rides beside it", async () => {
  const mock = mockHostinger("revoke");
  const outcome = await applyHostingerRecords(input, mock.fetcher);
  assert.equal(outcome.ok, true);
  assert.equal(outcome.revokeFailure?.message, "Hostinger revoke failed (HTTP 422)");
  assert.equal(outcome.revokeFailure?.stage, "revoke");
  assert.equal(JSON.stringify(outcome).includes(mock.secret), false);
  assert.equal(outcome.revokeFailure?.stack?.includes(mock.secret), false);
  assert.deepEqual(mock.calls, ["exchange", "portfolio", "read", "validate", "write", "revoke"]);
});

test("a revoke failure after a refused write keeps the write's own error, not the revoke's", async () => {
  const mock = mockHostinger("write");
  const fetcher: typeof fetch = (url, init) =>
    requestUrl(url) === HOSTINGER_REVOKE_URL
      ? Promise.resolve(new Response("{}", { status: 503 }))
      : mock.fetcher(url, init);
  const outcome = await applyHostingerRecords(input, fetcher);
  assert.equal(failureOf(outcome).message, "Hostinger write failed (HTTP 422)");
  assert.equal(outcome.revokeFailure?.message, "Hostinger revoke failed (HTTP 503)");
});

for (const issued of [
  { access_token: "MOCK-access-strict-fail", refresh_token: 42 },
  { access_token: "", refresh_token: "MOCK-refresh-strict-fail" },
  { access_token: "MOCK-access-strict-fail", refresh_token: "" },
]) {
  test(`an exchange response that fails strict validation still revokes what it carried (${JSON.stringify(issued)})`, async () => {
    const revoked: string[] = [];
    const fetcher: typeof fetch = (url, init) => {
      const endpoint = requestUrl(url);
      if (endpoint === HOSTINGER_TOKEN_URL) return Promise.resolve(Response.json(issued));
      if (endpoint === HOSTINGER_REVOKE_URL) {
        revoked.push((JSON.parse(requestBody(init)) as { token: string }).token);
        return Promise.resolve(Response.json({}));
      }
      throw new Error(`MOCK: no Hostinger API call may follow a refused exchange (${endpoint})`);
    };
    const outcome = await applyHostingerRecords(input, fetcher);
    assert.equal(failureOf(outcome).message, "Hostinger exchange failed");
    assert.equal(outcome.revokeFailure, null);
    assert.deepEqual(
      revoked,
      [issued.access_token, issued.refresh_token].filter(
        (v): v is string => typeof v === "string" && v.length > 0,
      ),
    );
    assert.equal(JSON.stringify(outcome).includes("MOCK-"), false);
  });
}

test("a distinct refresh token is revoked too, even when the access-token revoke fails", async () => {
  const mock = mockHostinger();
  const revoked: string[] = [];
  const fetcher: typeof fetch = (url, init) => {
    const endpoint = requestUrl(url);
    if (endpoint === HOSTINGER_TOKEN_URL)
      return Promise.resolve(
        Response.json({ access_token: mock.secret, refresh_token: "MOCK-distinct-refresh" }),
      );
    if (endpoint === HOSTINGER_REVOKE_URL) {
      const { token } = JSON.parse(requestBody(init)) as { token: string };
      revoked.push(token);
      return Promise.resolve(new Response("{}", { status: token === mock.secret ? 500 : 200 }));
    }
    return mock.fetcher(url, init);
  };
  const outcome = await applyHostingerRecords(input, fetcher);
  assert.equal(outcome.ok, true);
  assert.equal(outcome.revokeFailure?.message, "Hostinger revoke failed (HTTP 500)");
  assert.deepEqual(revoked, [mock.secret, "MOCK-distinct-refresh"]);
});

test("transport exceptions cannot carry credentials outside the request boundary", async () => {
  const mock = mockHostinger();
  const fetcher: typeof fetch = (url, init) =>
    requestUrl(url).endsWith("/portfolio")
      ? Promise.reject(new Error(mock.secret))
      : mock.fetcher(url, init);
  assert.equal(
    failureOf(await applyHostingerRecords(input, fetcher)).message,
    "Hostinger portfolio failed",
  );
  assert.equal(mock.calls.at(-1), "revoke");
});

test("conflicting SPF is left for guided setup; existing values are never replaced", async () => {
  const mock = mockHostinger();
  const fetcher: typeof fetch = (url, init) =>
    requestUrl(url).endsWith("/zones/customer.com") && init?.method !== "PUT"
      ? Promise.resolve(
          Response.json([
            { name: "app", type: "TXT", records: [{ content: "v=spf1 include:old.example -all" }] },
          ]),
        )
      : mock.fetcher(url, init);
  const outcome = await applyHostingerRecords(
    { ...input, records: [{ type: "TXT", host: "@", value: "v=spf1 include:new.example -all" }] },
    fetcher,
  );
  assert.equal(failureOf(outcome).message, "Hostinger conflict failed");
  assert.equal(mock.calls.includes("write"), false);
  assert.equal(mock.calls.at(-1), "revoke");
});

test("session expiry during provider I/O prevents a write and still revokes", async () => {
  const mock = mockHostinger();
  assert.match(
    failureOf(await applyHostingerRecords({ ...input, expiresAt: new Date(0) }, mock.fetcher))
      .message,
    /Hostinger write failed/,
  );
  assert.equal(mock.calls.includes("write"), false);
  assert.equal(mock.calls.at(-1), "revoke");
});

test("a published SPF that already satisfies the request is not appended as a second policy", async () => {
  const mock = mockHostinger();
  const fetcher: typeof fetch = (url, init) =>
    requestUrl(url).endsWith("/zones/customer.com") && init?.method !== "PUT"
      ? Promise.resolve(
          Response.json([
            {
              name: "app",
              type: "TXT",
              records: [{ content: "v=spf1 include:new.example include:old.example -all" }],
            },
          ]),
        )
      : mock.fetcher(url, init);
  const outcome = await applyHostingerRecords(
    { ...input, records: [{ type: "TXT", host: "@", value: "v=spf1 include:new.example -all" }] },
    fetcher,
  );
  assert.equal(outcome.ok, true);
  assert.equal(mock.calls.includes("write"), false);
  assert.equal(mock.calls.at(-1), "revoke");
});

// MOCK Hostinger zone for apex sessions on customer.com: the portfolio and the
// zone GET are overridden, validate/write bodies are captured, nothing is real.
function apexZone(existing: unknown[], portfolio: unknown[] = [{ domain: "customer.com" }]) {
  const mock = mockHostinger();
  const written: { zone: { name: string; type: string; ttl?: number }[] }[] = [];
  const fetcher: typeof fetch = (url, init) => {
    const endpoint = requestUrl(url);
    if (endpoint.endsWith("/portfolio")) {
      mock.calls.push("portfolio");
      return Promise.resolve(Response.json(portfolio));
    }
    if (endpoint.endsWith("/validate")) {
      mock.calls.push("validate");
      return Promise.resolve(Response.json({}));
    }
    if (endpoint.endsWith("/zones/customer.com")) {
      mock.calls.push(init?.method === "PUT" ? "write" : "read");
      if (init?.method !== "PUT") return Promise.resolve(Response.json(existing));
      written.push(JSON.parse(requestBody(init)) as (typeof written)[number]);
      return Promise.resolve(Response.json({}));
    }
    return mock.fetcher(url, init);
  };
  return { calls: mock.calls, fetcher, written };
}
const apexInput = { ...input, domain: "customer.com" };

for (const [label, set] of [
  [
    "a quoted SPF on the full name with a trailing dot",
    { name: "customer.com.", content: '"v=spf1 include:old.example -all"' },
  ],
  [
    "a split SPF on the upper-case full name",
    { name: "CUSTOMER.COM", content: '"v=spf1 include:old" ".example -all"' },
  ],
  ["a quoted SPF on an empty name", { name: "", content: '"v=spf1 include:old.example ~all"' }],
] as const) {
  test(`the conflict guard sees ${label} as the apex SPF and refuses a second one`, async () => {
    const zone = apexZone([{ name: set.name, type: "TXT", records: [{ content: set.content }] }]);
    const outcome = await applyHostingerRecords(
      {
        ...apexInput,
        records: [{ type: "TXT", host: "@", value: "v=spf1 include:new.example -all" }],
      },
      zone.fetcher,
    );
    assert.equal(failureOf(outcome).message, "Hostinger conflict failed");
    assert.equal(zone.calls.includes("write"), false);
    assert.equal(zone.calls.at(-1), "revoke");
  });
}

for (const name of ["customer.com.", "Customer.Com", "@"]) {
  test(`the conflict guard sees an A on "${name}" as the apex and refuses a second apex A`, async () => {
    const zone = apexZone([{ name, type: "A", records: [{ content: "198.51.100.7" }] }]);
    const outcome = await applyHostingerRecords(
      { ...apexInput, records: [{ type: "A", host: "@", value: "192.0.2.10" }] },
      zone.fetcher,
    );
    assert.equal(failureOf(outcome).message, "Hostinger conflict failed");
    assert.equal(zone.calls.includes("write"), false);
  });
}

test("a quoted or split copy of our own TXT already at the apex counts as present, not as a new value", async () => {
  for (const content of ['"mock-proof"', '"mock" "-proof"']) {
    const zone = apexZone([{ name: "customer.com.", type: "TXT", records: [{ content }] }]);
    const outcome = await applyHostingerRecords(apexInput, zone.fetcher);
    assert.equal(outcome.ok, true);
    assert.equal(zone.calls.includes("write"), false);
  }
});

for (const [label, set] of [
  ["an unbalanced TXT quote", { name: "@", type: "TXT", content: '"v=spf1 -all' }],
  ["a TXT escape it cannot read", { name: "@", type: "TXT", content: '"v=spf1\\059 -all"' }],
  [
    "a record name that is not a DNS name",
    { name: "bad name!", type: "A", content: "198.51.100.7" },
  ],
  ["a record type that is not a type", { name: "www", type: "A A", content: "198.51.100.7" }],
] as const) {
  test(`${label} in the existing zone refuses the write instead of guessing`, async () => {
    const zone = apexZone([
      { name: set.name, type: set.type, records: [{ content: set.content }] },
    ]);
    const outcome = await applyHostingerRecords(apexInput, zone.fetcher);
    assert.equal(failureOf(outcome).message, "Hostinger conflict failed");
    assert.equal(zone.calls.includes("write"), false);
  });
}

test("null, empty or invalid portfolio rows are skipped and the owned domain still matches", async () => {
  const bad = [null, {}, { domain: "" }, { domain: 7 }, { domain: "not a domain!" }, "x"];
  const zone = apexZone([], [...bad, { domain: "CUSTOMER.COM." }]);
  assert.deepEqual(await applyHostingerRecords(apexInput, zone.fetcher), {
    ok: true,
    revokeFailure: null,
  });
  assert.ok(zone.calls.includes("write"));
  const unowned = apexZone([], bad);
  assert.equal(
    failureOf(await applyHostingerRecords(apexInput, unowned.fetcher)).message,
    "Hostinger ownership failed",
  );
});

test("a record set the zone already has goes out without our TTL; a new set keeps it", async () => {
  const zone = apexZone([
    { name: "@", type: "TXT", records: [{ content: '"v=spf1 include:customer.example ~all"' }] },
  ]);
  const outcome = await applyHostingerRecords(
    {
      ...apexInput,
      records: [
        { type: "TXT", host: "@", value: "mock-proof", ttl: 300 },
        { type: "TXT", host: "_dodomain", value: "mock-proof", ttl: 300 },
      ],
    },
    zone.fetcher,
  );
  assert.equal(outcome.ok, true);
  assert.deepEqual(
    zone.written[0]!.zone.map(({ name, type, ttl }) => ({ name, type, ttl })),
    [
      { name: "@", type: "TXT", ttl: undefined },
      { name: "_dodomain", type: "TXT", ttl: 300 },
    ],
  );
  assert.equal("ttl" in zone.written[0]!.zone[0]!, false);
});
