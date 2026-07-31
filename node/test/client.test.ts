import { test } from "node:test";
import assert from "node:assert/strict";

import { signWebhook } from "@dodomain/core/webhook";

import { DoDomain, verifyWebhook } from "../src/index.ts";

// F-010 new-behavior tests ONLY. sdk.test.ts (F-008, already landed) already
// characterizes request()'s JSON-guard/response-schema-validation/
// invalid-input/constructor behavior — this file does NOT re-duplicate that
// ground (see PLAN-F-010 binding reconciliation #1: F-008's node SDK work
// stays as-is, verified not re-implemented). This file covers only what
// F-010 actually changed: the DODOMAIN_DEFAULT_ORIGIN default (was the
// unregistered https://api.dodomain.io) and the verifyWebhook re-export.

const VALID_KEY = "dd_sk_test_123";
const VALID_INPUT = {
  domain: "acme.com",
  records: [{ type: "CNAME" as const, host: "app", value: "cname.example.com" }],
};
const VALID_SESSION_BODY = {
  id: "sess_1",
  token: "dd_sess_abc",
  expiresAt: "2026-01-01T00:00:00.000Z",
  connectUrl: "https://app.dodomain.io/connect/dd_sess_abc",
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

function urlOf(input: string | URL | Request): string {
  // The SDK always calls fetch with a string URL — fail loudly if that drifts
  // rather than stringifying a Request/URL object ("[object Request]").
  if (typeof input !== "string") throw new Error("SDK must call fetch with a string URL");
  return input;
}

test("F-010: default baseUrl is DODOMAIN_DEFAULT_ORIGIN (https://app.dodomain.io), not the unregistered https://api.dodomain.io", async () => {
  let seenUrl: string | undefined;
  const fetchImpl: typeof fetch = async (input) => {
    seenUrl = urlOf(input);
    return jsonResponse(VALID_SESSION_BODY);
  };

  const dd = new DoDomain({ secretKey: VALID_KEY, fetchImpl });
  await dd.sessions.create(VALID_INPUT);

  assert.equal(seenUrl, "https://app.dodomain.io/api/v1/sessions");
});

test("F-010: an explicit baseUrl still overrides the DODOMAIN_DEFAULT_ORIGIN default", async () => {
  let seenUrl: string | undefined;
  const fetchImpl: typeof fetch = async (input) => {
    seenUrl = urlOf(input);
    return jsonResponse(VALID_SESSION_BODY);
  };

  const dd = new DoDomain({
    secretKey: VALID_KEY,
    baseUrl: "https://self-hosted.example.com/",
    fetchImpl,
  });
  await dd.sessions.create(VALID_INPUT);

  assert.equal(seenUrl, "https://self-hosted.example.com/api/v1/sessions");
});

test("F-010: verifyWebhook is re-exported from @dodomain/node and validates a signature produced by core's signWebhook", () => {
  const secret = "whsec_test";
  const body = JSON.stringify({ event: "connection.verified", data: { domain: "acme.com" } });
  const now = 1_700_000_000_000;
  const sig = signWebhook(secret, body, now);

  assert.ok(verifyWebhook(secret, body, sig, 5 * 60 * 1000, now));
  assert.equal(verifyWebhook("whsec_wrong", body, sig, 5 * 60 * 1000, now), false);
});
