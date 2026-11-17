import assert from "node:assert/strict";
import { createHmac, randomBytes } from "node:crypto";
import { test } from "node:test";

import {
  buildPorkbunAuthorizeUrl,
  isPorkbunErrorCode,
  porkbunRecords,
  zPorkbunCallback,
} from "../src/porkbun.ts";
import { detectProvider } from "../src/detect.ts";

// MOCK Porkbun signing key: generated only in memory for offline protocol tests.
// This is never a configured secret and makes no request to Porkbun.
const mockPorkbunKey = randomBytes(32).toString("base64url");
const state = "s".repeat(32);
const input = {
  config: {
    clientSecret: mockPorkbunKey,
    redirectUri: "http://localhost:3939/api/v1/porkbun/callback",
  },
  domain: "app.customer.co.uk",
  records: [
    { type: "A" as const, host: "@", value: "192.0.2.1", ttl: 600 },
    { type: "MX" as const, host: "@", value: "mail.example.net", priority: 0 },
  ],
  state,
  nowSeconds: 1790000000,
  expiresSeconds: 1790001800,
};

test("Porkbun receives one HS256 request JWT with the registered issuer, exact records and no OAuth parameters", () => {
  const url = new URL(buildPorkbunAuthorizeUrl(input));
  // The consent host given in Porkbun's approval email for our client (2026-10-28).
  assert.equal(url.origin + url.pathname, "https://porkbun.com/dnsconnect/authorize");
  assert.deepEqual([...url.searchParams.keys()], ["request"]);
  const [header, payload, signature] = url.searchParams.get("request")!.split(".");
  assert.deepEqual(JSON.parse(Buffer.from(header!, "base64url").toString()), {
    alg: "HS256",
    typ: "JWT",
  });
  assert.deepEqual(JSON.parse(Buffer.from(payload!, "base64url").toString()), {
    iss: "dc_dodomain_fb0f78",
    domain: "customer.co.uk",
    records: [
      { type: "A", host: "app", content: "192.0.2.1", ttl: 600 },
      { type: "MX", host: "app", content: "mail.example.net", prio: 0 },
    ],
    redirect_uri: input.config.redirectUri,
    state,
    iat: input.nowSeconds,
    exp: input.expiresSeconds,
  });
  assert.equal(
    signature,
    createHmac("sha256", mockPorkbunKey).update(`${header}.${payload}`).digest("base64url"),
  );
});

test("Porkbun uses punycode and preserves the relative host of a subdomain session", () => {
  assert.deepEqual(
    porkbunRecords("BÜCHER.de", [{ type: "TXT", host: "_verify", value: "token" }]),
    {
      domain: "xn--bcher-kva.de",
      records: [{ type: "TXT", host: "_verify", content: "token" }],
    },
  );
});

test("Porkbun keeps SPF merge semantics and does not request replacement of existing records", () => {
  const result = porkbunRecords("customer.com", [
    { type: "TXT", host: "@", value: "v=spf1 include:example.net ~all" },
  ]);
  assert.equal(Object.hasOwn(result.records[0]!, "replace"), false);
});

test("Porkbun refuses empty/oversized requests, invalid priorities and excessive lifetimes", () => {
  assert.throws(() => buildPorkbunAuthorizeUrl({ ...input, records: [] }));
  assert.throws(() =>
    buildPorkbunAuthorizeUrl({
      ...input,
      records: Array.from({ length: 26 }, () => input.records[0]!),
    }),
  );
  assert.throws(
    () =>
      buildPorkbunAuthorizeUrl({
        ...input,
        expiresSeconds: input.nowSeconds + 3601,
      }),
    /lifetime/,
  );
  assert.throws(
    () => porkbunRecords("customer.com", [{ type: "MX", host: "@", value: "mail.example.net" }]),
    /priority/,
  );
  assert.throws(() =>
    porkbunRecords("customer.com", [
      { type: "MX", host: "@", value: "mail.example.net", priority: -1 },
    ]),
  );
});

test("only Porkbun's four callback statuses are accepted, each with its own error shape", () => {
  for (const status of ["applied", "partial"]) {
    assert.equal(zPorkbunCallback.safeParse({ state, status }).success, true);
  }
  assert.equal(
    zPorkbunCallback.safeParse({
      state,
      status: "denied",
      error: "access_denied",
    }).success,
    true,
  );
  for (const error of ["domain_not_in_account", "domain_not_active", "invalid_records"]) {
    assert.equal(zPorkbunCallback.safeParse({ state, status: "error", error }).success, true);
  }
  for (const value of [
    { status: "applied" },
    { state: "short", status: "applied" },
    { state, status: "applied", error: "access_denied" },
    { state, status: "partial", error: "invalid_records" },
    { state, status: "denied", error: "domain_not_active" },
    { state, status: "error" },
    { state, status: "error", error: "Not A Code <script>" },
    { state, status: "unknown" },
  ])
    assert.equal(zPorkbunCallback.safeParse(value).success, false);
});

test("a denial without its access_denied code is still a denial", () => {
  assert.equal(zPorkbunCallback.safeParse({ state, status: "denied" }).success, true);
});

test("an undocumented status=error code is accepted as a failure but is not one of the documented codes", () => {
  const parsed = zPorkbunCallback.safeParse({ state, status: "error", error: "invented_error" });
  assert.equal(parsed.success, true);
  assert.equal(isPorkbunErrorCode("invented_error"), false);
  for (const code of ["domain_not_in_account", "domain_not_active", "invalid_records"]) {
    assert.equal(isPorkbunErrorCode(code), true);
  }
});

test("an apex record is sent with Porkbun's documented root host @", () => {
  assert.deepEqual(
    porkbunRecords("customer.com", [{ type: "A", host: "@", value: "192.0.2.1" }]).records,
    [{ type: "A", host: "@", content: "192.0.2.1" }],
  );
});

test("Porkbun detection retains guided setup as its fallback", async () => {
  // MOCK DNS discovery: no network or real customer domain is queried.
  const result = await detectProvider("customer.com", {
    resolveNs: async () => ["curitiba.ns.porkbun.com"],
    discover: async () => {
      throw new Error("MOCK no Domain Connect discovery");
    },
  });
  assert.equal(result.provider, "porkbun");
  assert.equal(result.method, "guided");
  assert.equal(result.tier, 3);
});
