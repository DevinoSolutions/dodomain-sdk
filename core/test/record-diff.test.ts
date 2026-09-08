import assert from "node:assert/strict";
import { test } from "node:test";

import { diffExpectedRecord } from "../src/record-diff.ts";
import { isProxyableRecordType } from "../src/record-capabilities.ts";
import { matches } from "../src/verify.ts";
import type { ExpectedRecord } from "../src/verify-types.ts";

// The mismatch classifier (record-diff.ts). Its one hard invariant is agreement
// with the verifier: `reason: "match"` must hold for exactly the inputs
// verify.ts's `matches` accepts, because the connect flow renders a "we couldn't
// match this" explanation next to a status chip the verifier decided. A
// classifier that disagreed would put a red diff beside a green chip.
//
// That guarantee is STRUCTURAL, not statistical: both functions bottom out in
// the same `recordAnswerMatches` predicate, so they cannot diverge by
// construction. The two agreement tests below are hand-picked pairs — they
// document the intent and would catch someone re-implementing the comparison
// locally, but they are illustrative, not an exhaustive proof.

const TXT: ExpectedRecord = {
  type: "TXT",
  fqdn: "_dodomain-challenge.example.com",
  expect: "dodomain-verify=AbC123",
};

const CNAME: ExpectedRecord = {
  type: "CNAME",
  fqdn: "status.example.com",
  expect: "target.dodomain.io",
};

const MX: ExpectedRecord = {
  type: "MX",
  fqdn: "example.com",
  expect: "mx.dodomain.io",
  priority: 10,
};

test("agrees with the verifier on every matching answer", () => {
  const cases: Array<[ExpectedRecord, string[]]> = [
    [TXT, ["dodomain-verify=AbC123"]],
    [TXT, ["some-other-token", "dodomain-verify=AbC123"]],
    // Host-like types normalize trailing dot + case, so these ARE matches.
    [CNAME, ["target.dodomain.io."]],
    [CNAME, ["TARGET.DODOMAIN.IO"]],
    [MX, ["10 mx.dodomain.io"]],
    [MX, ["20 other.example.net", "10 mx.dodomain.io"]],
  ];
  for (const [rec, found] of cases) {
    assert.equal(matches(found, rec), true, `verifier should match ${JSON.stringify(found)}`);
    assert.equal(
      diffExpectedRecord(rec, found).reason,
      "match",
      `classifier should agree on ${JSON.stringify(found)}`,
    );
  }
});

test("agrees with the verifier on every non-matching answer", () => {
  const cases: Array<[ExpectedRecord, string[]]> = [
    [TXT, []],
    [TXT, ["dodomain-verify=abc123"]],
    [CNAME, ["elsewhere.example.net"]],
    [MX, ["20 mx.dodomain.io"]],
  ];
  for (const [rec, found] of cases) {
    assert.equal(matches(found, rec), false, `verifier should reject ${JSON.stringify(found)}`);
    assert.notEqual(
      diffExpectedRecord(rec, found).reason,
      "match",
      `classifier should agree on ${JSON.stringify(found)}`,
    );
  }
});

test("nothing published is distinct from a wrong value", () => {
  const empty = diffExpectedRecord(TXT, []);
  assert.equal(empty.reason, "nothing_published");
  assert.deepEqual(empty.published, []);
  // A reason with no answer to point at — a `closest` here would be a
  // fabricated value the UI could render as "we found this".
  assert.equal(empty.closest, undefined);

  // The "wrong value" half is asserted on CNAME, NOT TXT. An unrecognised value
  // at a TXT name is not a fault at all (TXT names hold unrelated tokens by
  // design — see the SPF test below); this assertion originally used TXT and so
  // encoded the very bug that made an apex with SPF report a mismatch.
  const wrong = diffExpectedRecord(CNAME, ["totally-unrelated.example.net"]);
  assert.equal(wrong.reason, "different_value");
  assert.equal(wrong.closest, "totally-unrelated.example.net");
});

test("a lower-cased TXT token reports case_differs, not different_value", () => {
  // The highest-value hint: TXT is compared case-sensitively on purpose, so a
  // provider UI that lower-cased the token yields a record that looks right to
  // the user and never verifies.
  const diff = diffExpectedRecord(TXT, ["dodomain-verify=abc123"]);
  assert.equal(diff.reason, "case_differs");
  assert.equal(diff.closest, "dodomain-verify=abc123");
});

test("a stray space reports whitespace_differs on every type", () => {
  assert.equal(diffExpectedRecord(TXT, [" dodomain-verify=AbC123"]).reason, "whitespace_differs");
  // No comparison in the product trims, so whitespace breaks the host-like
  // types too — even though they normalize dot and case.
  assert.equal(diffExpectedRecord(CNAME, ["target.dodomain.io "]).reason, "whitespace_differs");
});

test("a trailing dot reports trailing_dot_differs on TXT only", () => {
  assert.equal(diffExpectedRecord(TXT, ["dodomain-verify=AbC123."]).reason, "trailing_dot_differs");
  // On CNAME the verifier already strips the dot, so the same shape is a match
  // and can never be reported as a near miss.
  assert.equal(diffExpectedRecord(CNAME, ["target.dodomain.io."]).reason, "match");
});

test("the right exchange at the wrong preference reports mx_priority_differs", () => {
  const diff = diffExpectedRecord(MX, ["20 mx.dodomain.io"]);
  assert.equal(diff.reason, "mx_priority_differs");
  assert.equal(diff.closest, "20 mx.dodomain.io");
});

test("a wrong MX exchange is a different_value, not a priority problem", () => {
  assert.equal(diffExpectedRecord(MX, ["10 mail.elsewhere.net"]).reason, "different_value");
});

test("an apex TXT holding somebody else's SPF is NOT a mismatch", () => {
  // The most common apex layout there is: SPF (and often other vendors'
  // ownership proofs) already live at the name our token is meant to JOIN.
  // Reported as `different_value` this made the flow say "waiting won't change
  // this" while pointing at the user's SPF record — inverting the feature's
  // whole thesis on the case it meets most often.
  const diff = diffExpectedRecord(TXT, ["v=spf1 include:_spf.google.com -all"]);
  assert.equal(diff.reason, "nothing_published");
  // No `closest`: pointing at the SPF record would invite the UI to render it
  // as though it were our failed record.
  assert.equal(diff.closest, undefined);
  // The answers are still carried — they are true, just not evidence of fault.
  assert.deepEqual(diff.published, ["v=spf1 include:_spf.google.com -all"]);
});

test("coexistence does NOT suppress a real near miss on the same name", () => {
  // The rungs run before the coexistence guard, so our own token published with
  // the wrong case is still called out even though an SPF record sits beside it.
  // Losing this would trade one false negative for a much worse one.
  const diff = diffExpectedRecord(TXT, ["v=spf1 -all", "dodomain-verify=abc123"]);
  assert.equal(diff.reason, "case_differs");
  assert.equal(diff.closest, "dodomain-verify=abc123");
});

test("a non-coexisting type still reports different_value", () => {
  // CNAME/A/AAAA/MX are not bags of independent values — something else at the
  // name genuinely is the problem, so the guard must not over-apply.
  assert.equal(diffExpectedRecord(CNAME, ["elsewhere.example.net"]).reason, "different_value");
  assert.equal(diffExpectedRecord(MX, ["10 mail.elsewhere.net"]).reason, "different_value");
});

test("a legacy MX record with no expected priority never reports a priority problem", () => {
  // Sessions predating the F-002 creation guard carry no expected preference,
  // and the verifier compares the exchange alone — so any preference matches
  // and there is nothing for the classifier to complain about.
  const legacy: ExpectedRecord = { type: "MX", fqdn: "example.com", expect: "mx.dodomain.io" };
  assert.equal(matches(["99 mx.dodomain.io"], legacy), true);
  assert.equal(diffExpectedRecord(legacy, ["99 mx.dodomain.io"]).reason, "match");
});

test("an answer with two defects is still explained, not dismissed", () => {
  // Padded AND lower-cased: neither trimming alone nor case-folding alone makes
  // this match, so single-relaxation probes would report `different_value` —
  // "something unrelated is published" — about the user's own value. The
  // cumulative ladder names the substantive defect instead.
  const diff = diffExpectedRecord(TXT, [" dodomain-verify=abc123 "]);
  assert.equal(diff.reason, "case_differs");
  assert.equal(diff.closest, " dodomain-verify=abc123 ");
});

test("the ladder reports the smallest relaxation that explains the failure", () => {
  // Padding alone stops at the first rung rather than being folded into the
  // case rung further down.
  assert.equal(diffExpectedRecord(TXT, [" dodomain-verify=AbC123"]).reason, "whitespace_differs");
  // A trailing dot alone stops at the second.
  assert.equal(diffExpectedRecord(TXT, ["dodomain-verify=AbC123."]).reason, "trailing_dot_differs");
});

test("the most specific reason wins across several published answers", () => {
  // Scanning by reason rather than by answer order: the near miss is reported
  // even though an unrelated record is listed first.
  const diff = diffExpectedRecord(TXT, ["v=spf1 -all", "dodomain-verify=abc123"]);
  assert.equal(diff.reason, "case_differs");
  assert.equal(diff.closest, "dodomain-verify=abc123");
  // Every published answer is carried through for display, not just the match.
  assert.deepEqual(diff.published, ["v=spf1 -all", "dodomain-verify=abc123"]);
});

test("isProxyableRecordType: only the address types a CDN can stand in front of", () => {
  // Drives the connect flow's "set it to DNS only" hint. The negative half is
  // the load-bearing one: pointing a user at their proxy settings because a TXT
  // token didn't match would send them to an innocent switch.
  assert.equal(isProxyableRecordType("CNAME"), true);
  assert.equal(isProxyableRecordType("A"), true);
  assert.equal(isProxyableRecordType("AAAA"), true);
  assert.equal(isProxyableRecordType("TXT"), false);
  assert.equal(isProxyableRecordType("MX"), false);
});

test("published answers are carried verbatim", () => {
  // The bytes ARE the diagnostic — normalizing them for display would hide the
  // exact defect the user has to fix.
  const raw = ["  dodomain-verify=AbC123  "];
  const diff = diffExpectedRecord(TXT, raw);
  assert.deepEqual(diff.published, raw);
  assert.equal(diff.closest, raw[0]);
});
