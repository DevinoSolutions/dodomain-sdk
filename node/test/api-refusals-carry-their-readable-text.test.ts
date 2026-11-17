import assert from "node:assert/strict";
import { test } from "node:test";

import { DoDomain, DoDomainError, DoDomainKeylessError } from "../src/index.ts";

// 0.9.2 (T-18329): an API refusal's human text reaches `e.message`. Before,
// the message was `body.error` alone ("invalid_request", "quota_exceeded"), so
// a developer or an agent logging `e.message` never saw the API's own words:
// what was wrong and what to do next. Same injected-fetch unit style as the
// other suites here; nothing reaches the network.

const SECRET_KEY = "dd_sk_test_123";
const KEYLESS_KEY = "dd_ks_scripted_key";
const INPUT = {
  domain: "acme.com",
  records: [{ type: "CNAME" as const, host: "app", value: "edge.example.net" }],
};

/** MOCK fetch: answers every call with this one scripted body and status. */
function answering(body: unknown, status: number): typeof fetch {
  return async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/problem+json" },
    });
}

async function refusalOf(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => assert.fail("the call should have been refused"),
    (error: unknown) => error,
  );
}

const PLACEHOLDER_DETAIL =
  '"customer.com" is a placeholder or reserved name, so its DNS records can never be added. Change "domain" to a domain whose DNS records you can add.';

test("a 400 with an RFC 9457 detail reads as the machine error then the detail, with error and code as fields", async () => {
  const dd = new DoDomain({
    secretKey: SECRET_KEY,
    fetchImpl: answering(
      {
        type: "about:blank",
        title: "Bad Request",
        status: 400,
        detail: "records[0].host must be a hostname label.",
        error: "invalid_request",
        message: "records[0].host must be a hostname label.",
        code: "INVALID_RECORD",
      },
      400,
    ),
  });
  const refusal = await refusalOf(dd.sessions.create(INPUT));
  assert.ok(refusal instanceof DoDomainError);
  assert.ok(!(refusal instanceof DoDomainKeylessError), "a non-keyless code stays a plain error");
  assert.equal(refusal.message, "invalid_request: records[0].host must be a hostname label.");
  assert.ok(refusal.message.startsWith("invalid_request"), "existing prefix checks keep working");
  assert.equal(refusal.error, "invalid_request");
  assert.equal(refusal.code, "INVALID_RECORD");
  assert.equal(refusal.status, 400);
});

test("a keyless start for a placeholder domain is a DoDomainKeylessError KEYLESS_PLACEHOLDER_DOMAIN that says what to change", async () => {
  const dd = new DoDomain({
    keyless: true,
    fetchImpl: answering(
      {
        type: "about:blank",
        title: "Bad Request",
        status: 400,
        detail: PLACEHOLDER_DETAIL,
        error: "invalid_request",
        message: PLACEHOLDER_DETAIL,
        code: "KEYLESS_PLACEHOLDER_DOMAIN",
        details: { domain: "customer.com" },
      },
      400,
    ),
  });
  const refusal = await refusalOf(dd.sessions.create({ ...INPUT, domain: "customer.com" }));
  assert.ok(refusal instanceof DoDomainKeylessError);
  assert.equal(refusal.code, "KEYLESS_PLACEHOLDER_DOMAIN");
  assert.equal(refusal.error, "invalid_request");
  assert.equal(refusal.message, `invalid_request: ${PLACEHOLDER_DETAIL}`);
  assert.equal(refusal.details?.domain, "customer.com");
  assert.equal(refusal.status, 400);
});

test("a 402 keyless refusal keeps its fair-share explanation in the message and its retryAt, sharedNetwork and scope in details", async () => {
  const explanation =
    "This network shares its keyless allowance with other developers and its share is used for today. It resets at 2026-11-18T00:00:00.000Z. Claim the app or sign up for your own allowance.";
  const dd = new DoDomain({
    keyless: true,
    keylessKey: KEYLESS_KEY,
    fetchImpl: answering(
      {
        error: "quota_exceeded",
        code: "KEYLESS_LIMIT_REACHED",
        message: explanation,
        details: {
          reason: "keyless_limit_reached",
          scope: "network",
          sharedNetwork: true,
          retryAt: "2026-11-18T00:00:00.000Z",
          limit: 10,
        },
      },
      402,
    ),
  });
  const refusal = await refusalOf(dd.sessions.create(INPUT));
  assert.ok(refusal instanceof DoDomainKeylessError);
  assert.equal(refusal.message, `quota_exceeded: ${explanation}`);
  assert.ok(refusal.message.startsWith("quota_exceeded"), "existing prefix checks keep working");
  assert.equal(refusal.error, "quota_exceeded");
  assert.equal(refusal.code, "KEYLESS_LIMIT_REACHED");
  assert.equal(refusal.details?.retryAt, "2026-11-18T00:00:00.000Z");
  assert.equal(refusal.details?.sharedNetwork, true);
  assert.equal(refusal.details?.scope, "network");
});

test("a dd_ks_ key inside a refusal's human text is cut to its prefix in the message", async () => {
  const secret = "dd_ks_live_secret_part_9f8e7d";
  const dd = new DoDomain({
    keyless: true,
    keylessKey: secret,
    fetchImpl: answering(
      {
        error: "quota_exceeded",
        code: "KEYLESS_LIMIT_REACHED",
        message: `Claim it at https://app.dodomain.io/claim/keyless#${secret} to continue.`,
      },
      402,
    ),
  });
  const refusal = await refusalOf(dd.sessions.create(INPUT));
  assert.ok(refusal instanceof DoDomainKeylessError);
  assert.equal(
    refusal.message,
    "quota_exceeded: Claim it at https://app.dodomain.io/claim/keyless#dd_ks_… to continue.",
  );
  for (const rendered of [refusal.message, String(refusal), refusal.stack ?? ""]) {
    assert.ok(!rendered.includes(secret), `the key leaked: ${rendered}`);
  }
});

test("a refusal with no human text keeps the bare machine error, or HTTP <status> with no error either", async () => {
  const bare = await refusalOf(
    new DoDomain({
      secretKey: SECRET_KEY,
      fetchImpl: answering({ error: "not_found" }, 404),
    }).sessions.get("sess_missing"),
  );
  assert.ok(bare instanceof DoDomainError);
  assert.equal(bare.message, "not_found");
  assert.equal(bare.error, "not_found");
  assert.equal(bare.code, undefined);

  const blank = await refusalOf(
    new DoDomain({
      secretKey: SECRET_KEY,
      fetchImpl: answering({ error: "not_found", detail: "   ", message: "" }, 404),
    }).sessions.get("sess_missing"),
  );
  assert.ok(blank instanceof DoDomainError);
  assert.equal(blank.message, "not_found", "blank human text adds nothing");

  const nothing = await refusalOf(
    new DoDomain({ secretKey: SECRET_KEY, fetchImpl: answering({}, 502) }).sessions.get(
      "sess_missing",
    ),
  );
  assert.ok(nothing instanceof DoDomainError);
  assert.equal(nothing.message, "HTTP 502");
  assert.equal(nothing.error, undefined);
});
