import { test } from "node:test";
import assert from "node:assert/strict";

import { signWebhook, verifyWebhook } from "../src/webhook.ts";

const SECRET = "whsec_testsecret";
const BODY = JSON.stringify({ event: "connection.verified", data: { domain: "acme.com" } });

test("sign → verify round-trips", () => {
  const now = 1_700_000_000_000;
  const sig = signWebhook(SECRET, BODY, now);
  assert.ok(verifyWebhook(SECRET, BODY, sig, 5 * 60 * 1000, now));
});

test("verify rejects a tampered body", () => {
  const now = 1_700_000_000_000;
  const sig = signWebhook(SECRET, BODY, now);
  assert.equal(verifyWebhook(SECRET, BODY + "x", sig, 5 * 60 * 1000, now), false);
});

test("verify rejects a wrong secret", () => {
  const now = 1_700_000_000_000;
  const sig = signWebhook(SECRET, BODY, now);
  assert.equal(verifyWebhook("whsec_other", BODY, sig, 5 * 60 * 1000, now), false);
});

test("verify rejects an expired timestamp (replay protection)", () => {
  const signedAt = 1_700_000_000_000;
  const sig = signWebhook(SECRET, BODY, signedAt);
  const muchLater = signedAt + 10 * 60 * 1000; // 10 min later, tolerance 5 min
  assert.equal(verifyWebhook(SECRET, BODY, sig, 5 * 60 * 1000, muchLater), false);
});

test("verify rejects a malformed header", () => {
  assert.equal(verifyWebhook(SECRET, BODY, "garbage", 5 * 60 * 1000, Date.now()), false);
});

// verifyWebhook runs inside the INTEGRATOR's request handler over a header an
// attacker fully controls, so every malformed shape must RETURN FALSE — a
// throw there is a 500 on their endpoint, not a failed verification.
// These four all carry a valid, in-tolerance `t`, so they reach the signature
// comparison the earlier tests never exercise.
const NOW = 1_700_000_000_000;
const withV1 = (v1: string) => `t=${NOW},v1=${v1}`;

test("verify returns false (never throws) for a 64-CHARACTER v1 containing a multi-byte codepoint", () => {
  // The regression: the old guard compared JS string length while Buffer.from
  // is utf-8, so this 64-char value produced a 65+ BYTE buffer and
  // timingSafeEqual threw RangeError inside the integrator's handler.
  const multibyte = "é".repeat(1) + "a".repeat(63);
  assert.equal(multibyte.length, 64, "the fixture must be exactly 64 CHARACTERS");
  assert.ok(Buffer.from(multibyte).length > 64, "…and more than 64 BYTES");
  assert.equal(verifyWebhook(SECRET, BODY, withV1(multibyte), 5 * 60 * 1000, NOW), false);
});

test("verify returns false for a v1 that is not 64 hex characters (too short, too long, non-hex)", () => {
  for (const v1 of ["abc", "a".repeat(63), "a".repeat(65), "z".repeat(64), ""]) {
    assert.equal(
      verifyWebhook(SECRET, BODY, withV1(v1), 5 * 60 * 1000, NOW),
      false,
      `v1=${JSON.stringify(v1.slice(0, 8))}… must not verify`,
    );
  }
});

test("verify returns false for an UPPERCASE-hex v1 (the signature we emit is lowercase)", () => {
  const sig = signWebhook(SECRET, BODY, NOW);
  const upper = sig.replace(/v1=(.+)$/, (_m, hex: string) => `v1=${hex.toUpperCase()}`);
  assert.notEqual(upper, sig, "the fixture must actually differ in case");
  assert.equal(verifyWebhook(SECRET, BODY, upper, 5 * 60 * 1000, NOW), false);
});

test("verify returns false for a header with no v1 part at all", () => {
  assert.equal(verifyWebhook(SECRET, BODY, `t=${NOW}`, 5 * 60 * 1000, NOW), false);
});
