// T-18114: the keyless sandbox's one home (src/sandbox.ts). A REAL domain must
// never become a sandbox session (a sandbox session is never metered and never
// checked against DNS), so the match is exact: no case folding, no suffix
// match, no trailing dot, no punycode or prototype-key surprises.
import assert from "node:assert/strict";
import { test } from "node:test";

import {
  connectSessionModeFor,
  isSandboxDomain,
  isSandboxMode,
  SANDBOX_DOMAIN_NAMES,
  SANDBOX_NOTE,
  SANDBOX_SLOW_VERIFY_AFTER_MS,
  sandboxDetection,
  sandboxScenarioFor,
  simulateSandboxVerification,
} from "../src/sandbox.ts";
import { zConnectSessionMode, zCreateSessionResponse } from "../src/schemas.ts";
import type { ExpectedRecord } from "../src/verify-types.ts";

test("the five reserved names map to their scenarios", () => {
  assert.deepEqual(SANDBOX_DOMAIN_NAMES, [
    "verified.test",
    "pending.test",
    "slow.test",
    "wrong-record.test",
    "unsupported.test",
  ]);
  assert.equal(sandboxScenarioFor("verified.test"), "verified");
  assert.equal(sandboxScenarioFor("pending.test"), "pending");
  assert.equal(sandboxScenarioFor("slow.test"), "slow");
  assert.equal(sandboxScenarioFor("wrong-record.test"), "wrong_record");
  assert.equal(sandboxScenarioFor("unsupported.test"), "unsupported");
  for (const name of SANDBOX_DOMAIN_NAMES) {
    assert.equal(connectSessionModeFor(name), "sandbox", name);
    assert.equal(isSandboxDomain(name), true, name);
  }
});

test("a lookalike, a subdomain, a case or trailing-dot variant and punycode are never sandbox", () => {
  const lookalikes = [
    "verified.test.evil.com",
    "xverified.test",
    "www.verified.test",
    "verified.test.",
    "Verified.Test",
    "VERIFIED.TEST",
    " verified.test",
    "verified.test ",
    "xn--verifed-test.com",
    "xn--vrified-6ya.test",
    "verified.tes",
    "verified-test",
    "test",
    ".test",
    "foo.test",
    "example.com",
    "",
    "constructor",
    "__proto__",
    "toString",
    "hasOwnProperty",
  ];
  for (const domain of lookalikes) {
    assert.equal(sandboxScenarioFor(domain), null, domain);
    assert.equal(connectSessionModeFor(domain), "live", domain);
  }
});

test("isSandboxMode reads only the stored sandbox mode", () => {
  assert.equal(isSandboxMode("sandbox"), true);
  assert.equal(isSandboxMode("live"), false);
  assert.deepEqual(zConnectSessionMode.options, ["live", "sandbox"]);
});

test("the create response carries the mode, so a keyless or keyed SDK can read it", () => {
  const base = {
    id: "s",
    token: "dd_sess_x",
    expiresAt: new Date().toISOString(),
    connectUrl: "https://app.dodomain.io/connect/dd_sess_x",
    records: [],
  };
  assert.equal(zCreateSessionResponse.safeParse({ ...base, mode: "sandbox" }).success, true);
  assert.equal(zCreateSessionResponse.safeParse({ ...base, mode: "live" }).success, true);
  assert.equal(zCreateSessionResponse.safeParse({ ...base, mode: "test" }).success, false);
});

const expected: ExpectedRecord[] = [
  { type: "CNAME", fqdn: "app.verified.test", expect: "edge.example.net" },
  { type: "TXT", fqdn: "_dd.verified.test", expect: "proof-1" },
];
const createdAt = new Date("2026-11-17T12:00:00Z");

test("verified and unsupported verify on the first check, with no DNS and a sandbox note", () => {
  for (const scenario of ["verified", "unsupported"] as const) {
    const results = simulateSandboxVerification(scenario, expected, { createdAt, now: createdAt });
    assert.equal(results.length, 2);
    for (const [i, r] of results.entries()) {
      assert.equal(r.present, true);
      assert.equal(r.outcome, "verified");
      assert.equal(r.fqdn, expected[i]!.fqdn);
      assert.deepEqual(r.authoritativeFound, [expected[i]!.expect]);
      assert.equal(r.note, SANDBOX_NOTE);
    }
  }
});

test("pending never verifies, however late", () => {
  const later = new Date(createdAt.getTime() + 365 * 24 * 3600_000);
  const results = simulateSandboxVerification("pending", expected, { createdAt, now: later });
  assert.ok(results.every((r) => !r.present && r.outcome === "absent"));
  assert.ok(results.every((r) => r.authoritativeFound.length === 0));
});

test("slow verifies only once SANDBOX_SLOW_VERIFY_AFTER_MS have passed since creation", () => {
  const early = new Date(createdAt.getTime() + SANDBOX_SLOW_VERIFY_AFTER_MS - 1);
  const due = new Date(createdAt.getTime() + SANDBOX_SLOW_VERIFY_AFTER_MS);
  assert.ok(
    simulateSandboxVerification("slow", expected, { createdAt, now: early }).every(
      (r) => !r.present,
    ),
  );
  assert.ok(
    simulateSandboxVerification("slow", expected, { createdAt, now: due }).every((r) => r.present),
  );
});

test("wrong-record finds a record with a WRONG value on every check", () => {
  const results = simulateSandboxVerification("wrong_record", expected, {
    createdAt,
    now: new Date(createdAt.getTime() + 3600_000),
  });
  for (const [i, r] of results.entries()) {
    assert.equal(r.present, false);
    assert.equal(r.outcome, "absent");
    assert.equal(r.authoritativeFound.length, 1);
    assert.notEqual(r.authoritativeFound[0], expected[i]!.expect);
  }
});

test("detection is always the guided manual tier; unsupported reports the unknown provider", () => {
  const d = sandboxDetection("verified", "verified.test");
  assert.equal(d.tier, 3);
  assert.equal(d.method, "guided");
  assert.equal(d.provider, "sandbox");
  assert.equal(d.zone, "verified.test");
  assert.deepEqual(d.nameServers, []);
  const u = sandboxDetection("unsupported", "unsupported.test");
  assert.equal(u.tier, 3);
  assert.equal(u.provider, "unknown");
  assert.equal(u.confidence, "low");
});
