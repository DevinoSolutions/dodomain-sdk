// SPF / DKIM / DMARC semantics (email-records.ts), against real-shaped records.
// Every fixture below is the shape a real provider publishes — Google, SES,
// Microsoft 365, Resend — not a minimal string that happens to pass.

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  dkimRecordSatisfies,
  dmarcRecordSatisfies,
  emailPolicyKindOf,
  emailPolicyTxtMatches,
  mergeSpfRecordTerms,
  parseSpfRecord,
  parseTagValueList,
  SPF_MAX_DNS_LOOKUPS,
  spfDnsLookupTermCount,
  spfRecordSatisfies,
  spfSoleIncludeHost,
} from "../src/email-records.ts";
import { recordValueMatches } from "../src/record-capabilities.ts";
import { diffExpectedRecord } from "../src/record-diff.ts";
import { matches } from "../src/verify.ts";

// ── classification ──────────────────────────────────────────────────────────

test("emailPolicyKindOf recognises the three policies by their version tag and nothing else", () => {
  assert.equal(emailPolicyKindOf("v=spf1 include:_spf.google.com ~all"), "spf");
  assert.equal(emailPolicyKindOf("V=SPF1 -all"), "spf");
  assert.equal(emailPolicyKindOf("v=DMARC1; p=reject; rua=mailto:d@x.example"), "dmarc");
  assert.equal(emailPolicyKindOf("v=DKIM1; k=rsa; p=MIGf"), "dkim");
  // Tokens and arbitrary text are NOT policies — the exact rule stays in force.
  assert.equal(emailPolicyKindOf("dodomain-verify=abc"), null);
  assert.equal(emailPolicyKindOf("v=spf1x"), null);
  assert.equal(emailPolicyKindOf("google-site-verification=abc"), null);
  // A DKIM key without its RECOMMENDED v= tag is valid but unrecognisable — unknown ≠ no.
  assert.equal(emailPolicyKindOf("k=rsa; p=MIGf"), null);
});

// ── SPF ─────────────────────────────────────────────────────────────────────

test("parseSpfRecord splits terms from the version and the terminal all", () => {
  assert.deepEqual(parseSpfRecord("v=spf1 include:_spf.google.com ip4:203.0.113.0/24 ~all"), {
    terms: ["include:_spf.google.com", "ip4:203.0.113.0/24"],
    all: "~all",
  });
  assert.deepEqual(parseSpfRecord("v=spf1 -all"), { terms: [], all: "-all" });
  // Terms after `all` are never evaluated (RFC 7208 §5.1).
  assert.deepEqual(parseSpfRecord("v=spf1 ~all include:late.example"), { terms: [], all: "~all" });
  assert.equal(parseSpfRecord("dodomain-verify=x"), null);
});

test("spfSoleIncludeHost accepts exactly one include mechanism — the SPFM shape the template merges", () => {
  assert.equal(
    spfSoleIncludeHost("v=spf1 include:_spf.mailer.example ~all"),
    "_spf.mailer.example",
  );
  assert.equal(spfSoleIncludeHost("v=spf1 +include:amazonses.com -all"), "amazonses.com");
  assert.equal(spfSoleIncludeHost("v=spf1 include:amazonses.com"), "amazonses.com");
  // Anything richer is entered by hand, never merged blind.
  assert.equal(spfSoleIncludeHost("v=spf1 include:a.example include:b.example ~all"), null);
  assert.equal(spfSoleIncludeHost("v=spf1 ip4:203.0.113.10 ~all"), null);
  assert.equal(spfSoleIncludeHost("v=spf1 mx include:a.example ~all"), null);
  assert.equal(spfSoleIncludeHost("v=spf1 ~all"), null);
});

test("SPF: the merged zone record satisfies the session's include — the healthy outcome verifies", () => {
  const expected = "v=spf1 include:_spf.mailer.example ~all";
  // Google's SPF was already there; the provider merged ours in (SPFM).
  const merged = "v=spf1 include:_spf.google.com include:_spf.mailer.example ~all";
  assert.equal(spfRecordSatisfies(expected, merged), true);
  assert.equal(recordValueMatches("TXT", expected, merged), true);
  assert.equal(matches([merged], { type: "TXT", fqdn: "acme.example", expect: expected }), true);
});

test("SPF: the terminal qualifier is not compared (the zone owner's -all/~all is theirs)", () => {
  assert.equal(
    spfRecordSatisfies("v=spf1 include:x.example ~all", "v=spf1 include:x.example -all"),
    true,
  );
});

test("SPF: mechanism names and domains compare case-insensitively; a + qualifier is the default", () => {
  assert.equal(
    spfRecordSatisfies(
      "v=spf1 include:_SPF.Mailer.Example ~all",
      "v=spf1 +INCLUDE:_spf.mailer.example -all",
    ),
    true,
  );
});

test("SPF: a zone record that lacks the expected mechanism does NOT satisfy it", () => {
  const expected = "v=spf1 include:_spf.mailer.example ~all";
  assert.equal(spfRecordSatisfies(expected, "v=spf1 include:_spf.google.com ~all"), false);
  assert.equal(spfRecordSatisfies(expected, "v=spf1 -all"), false);
  // and a non-SPF TXT at the apex is never a match for an SPF expectation.
  assert.equal(spfRecordSatisfies(expected, "google-site-verification=abc"), false);
  assert.equal(recordValueMatches("TXT", expected, "google-site-verification=abc"), false);
});

test("SPF merge: the expected mechanism is inserted before the published terminal all, which is kept as the owner wrote it", () => {
  assert.equal(
    mergeSpfRecordTerms(
      "v=spf1 include:_spf.mailer.example ~all",
      "v=spf1 include:_spf.google.com -all",
    ),
    "v=spf1 include:_spf.google.com include:_spf.mailer.example -all",
  );
  // A record with no terminal at all keeps having none; ours goes at the end.
  assert.equal(
    mergeSpfRecordTerms("v=spf1 include:b.example ~all", "v=spf1 include:a.example"),
    "v=spf1 include:a.example include:b.example",
  );
});

test("SPF merge: a record that already carries the mechanism comes back unchanged, so the caller writes nothing", () => {
  const published = "v=spf1 +INCLUDE:_spf.Mailer.Example -all";
  assert.equal(
    mergeSpfRecordTerms("v=spf1 include:_spf.mailer.example ~all", published),
    published,
  );
});

test("SPF merge: everything the zone published survives — its own terms, their order, and the tail after all", () => {
  assert.equal(
    mergeSpfRecordTerms(
      "v=spf1 include:_spf.mailer.example ~all",
      // ip4 first, and an (RFC 7208 §5.1 never-evaluated) term after the terminal.
      "v=spf1 ip4:203.0.113.10 mx ~all exp=why.example",
    ),
    "v=spf1 ip4:203.0.113.10 mx include:_spf.mailer.example ~all exp=why.example",
  );
});

test("SPF merge: a non-SPF value on either side is not something to merge", () => {
  assert.equal(
    mergeSpfRecordTerms("dodomain-verify=tok-abc123", "v=spf1 include:a.example ~all"),
    null,
  );
  assert.equal(
    mergeSpfRecordTerms("v=spf1 include:a.example ~all", "google-site-verification=abc"),
    null,
  );
});

test("SPF diff: an existing SPF record without our include reads spf_terms_missing, never 'wait'", () => {
  const rec = {
    type: "TXT" as const,
    fqdn: "acme.example",
    expect: "v=spf1 include:_spf.mailer.example ~all",
  };
  const diff = diffExpectedRecord(rec, [
    "google-site-verification=abc",
    "v=spf1 include:_spf.google.com ~all",
  ]);
  assert.equal(diff.reason, "spf_terms_missing");
  assert.equal(diff.closest, "v=spf1 include:_spf.google.com ~all");
  // With no SPF record at all, "nothing published" is right — adding ours IS the fix.
  assert.equal(
    diffExpectedRecord(rec, ["google-site-verification=abc"]).reason,
    "nothing_published",
  );
  // And once merged, match.
  assert.equal(
    diffExpectedRecord(rec, ["v=spf1 include:_spf.google.com include:_spf.mailer.example ~all"])
      .reason,
    "match",
  );
});

test("SPF lookup count: counts the DNS-querying terms of the record as written (a floor, not a total)", () => {
  assert.equal(
    spfDnsLookupTermCount("v=spf1 include:a.example include:b.example ip4:203.0.113.0/24 ~all"),
    2,
  );
  assert.equal(
    spfDnsLookupTermCount("v=spf1 a mx ptr exists:%{i}.x.example redirect=y.example"),
    5,
  );
  assert.equal(spfDnsLookupTermCount("v=spf1 a:mail.example mx:mx.example ~all"), 2);
  assert.equal(spfDnsLookupTermCount("v=spf1 ip4:1.2.3.4 ip6:::1 all"), 0);
  assert.equal(spfDnsLookupTermCount("not spf"), 0);
  const eleven = `v=spf1 ${Array.from({ length: 11 }, (_, i) => `include:i${i}.example`).join(" ")} ~all`;
  assert.ok(spfDnsLookupTermCount(eleven) > SPF_MAX_DNS_LOOKUPS);
});

// ── DKIM ────────────────────────────────────────────────────────────────────

const SES_KEY =
  "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5N7Yq2dC9mQ0k4b9v7Q3m1bA0hZbP5c4X9Yq2dC9mQ0k4b9v7Q3m1bA0hZbP5c4X9Yq2dC9mQ0k4b9v7Q3m1bA0hZbP5c4X9Yq2dC9mQ0k4b9v7Q3m1bA0hZbP5c4X9Yq2dC9mQ0k4b9v7Q3m1bA0hZbP5c4XQIDAQAB";

test("parseTagValueList tolerates spacing, a trailing semicolon and mixed-case tags", () => {
  const tags = parseTagValueList(" V=DKIM1 ;k = rsa; p=abc ;");
  assert.equal(tags.get("v"), "DKIM1");
  assert.equal(tags.get("k"), "rsa");
  assert.equal(tags.get("p"), "abc");
});

test("DKIM: a key re-spaced by the provider, or re-joined from split TXT strings, still satisfies", () => {
  const expected = `v=DKIM1; k=rsa; p=${SES_KEY}`;
  assert.equal(dkimRecordSatisfies(expected, `v=DKIM1;k=rsa;p=${SES_KEY}`), true);
  // Long keys come back as two strings verify.ts joins — whitespace inside p= is ignored (RFC 6376).
  const split = `v=DKIM1; k=rsa; p=${SES_KEY.slice(0, 100)} ${SES_KEY.slice(100)}`;
  assert.equal(dkimRecordSatisfies(expected, split), true);
  // The RECOMMENDED tags may be omitted by the publisher — defaults apply.
  assert.equal(dkimRecordSatisfies(expected, `p=${SES_KEY}`), true);
  assert.equal(recordValueMatches("TXT", expected, `p=${SES_KEY}`), true);
});

test("DKIM: a different key, a different algorithm, or a missing key is a mismatch", () => {
  const expected = `v=DKIM1; k=rsa; p=${SES_KEY}`;
  assert.equal(
    dkimRecordSatisfies(expected, `v=DKIM1; k=rsa; p=${SES_KEY.slice(0, -4)}AAAA`),
    false,
  );
  assert.equal(dkimRecordSatisfies(expected, `v=DKIM1; k=ed25519; p=${SES_KEY}`), false);
  assert.equal(dkimRecordSatisfies(expected, "v=DKIM1; k=rsa"), false);
  assert.equal(dkimRecordSatisfies("v=DKIM1; k=rsa", `v=DKIM1; k=rsa; p=${SES_KEY}`), false);
});

test("DKIM diff: a different key at the selector is different_value — a selector holds ONE key", () => {
  const rec = {
    type: "TXT" as const,
    fqdn: "s1._domainkey.acme.example",
    expect: `v=DKIM1; k=rsa; p=${SES_KEY}`,
  };
  const other = `v=DKIM1; k=rsa; p=${SES_KEY.slice(0, -4)}AAAA`;
  const diff = diffExpectedRecord(rec, [other]);
  assert.equal(diff.reason, "different_value");
  assert.equal(diff.closest, other);
});

// ── DMARC ───────────────────────────────────────────────────────────────────

test("DMARC: the published policy satisfies the expected tags; extra tags are the owner's choice", () => {
  const expected = "v=DMARC1; p=quarantine; rua=mailto:dmarc@mailer.example";
  assert.equal(
    dmarcRecordSatisfies(expected, "v=DMARC1; p=quarantine; rua=mailto:dmarc@mailer.example"),
    true,
  );
  assert.equal(
    dmarcRecordSatisfies(
      expected,
      "v=DMARC1;p=QUARANTINE;rua=mailto:dmarc@mailer.example;pct=100;adkim=s",
    ),
    true,
  );
  // rua is a URI LIST — order and case carry no meaning.
  assert.equal(
    dmarcRecordSatisfies(
      "v=DMARC1; p=none; rua=mailto:a@x.example,mailto:b@x.example",
      "v=DMARC1; p=none; rua=mailto:B@x.example, mailto:a@x.example",
    ),
    true,
  );
  assert.equal(
    recordValueMatches(
      "TXT",
      expected,
      "v=DMARC1; p=quarantine; rua=mailto:dmarc@mailer.example; sp=none",
    ),
    true,
  );
});

test("DMARC: a weaker policy, a missing report address, or a non-DMARC record is a mismatch", () => {
  const expected = "v=DMARC1; p=quarantine; rua=mailto:dmarc@mailer.example";
  assert.equal(
    dmarcRecordSatisfies(expected, "v=DMARC1; p=none; rua=mailto:dmarc@mailer.example"),
    false,
  );
  assert.equal(dmarcRecordSatisfies(expected, "v=DMARC1; p=quarantine"), false);
  assert.equal(
    dmarcRecordSatisfies(expected, "p=quarantine; rua=mailto:dmarc@mailer.example"),
    false,
  );
  assert.equal(dmarcRecordSatisfies(expected, "dodomain-verify=x"), false);
});

test("DMARC diff: a different policy at _dmarc is different_value — waiting will not change it", () => {
  const rec = {
    type: "TXT" as const,
    fqdn: "_dmarc.acme.example",
    expect: "v=DMARC1; p=reject; rua=mailto:d@x.example",
  };
  const diff = diffExpectedRecord(rec, ["v=DMARC1; p=none"]);
  assert.equal(diff.reason, "different_value");
  assert.equal(diff.closest, "v=DMARC1; p=none");
});

// ── the dispatch, and the token rule it must NOT touch ──────────────────────

test("emailPolicyTxtMatches returns null for a non-policy TXT, so tokens stay exact and case-sensitive", () => {
  assert.equal(emailPolicyTxtMatches("dodomain-verify=AbC", "dodomain-verify=AbC"), null);
  assert.equal(recordValueMatches("TXT", "dodomain-verify=AbC", "dodomain-verify=abc"), false);
  assert.equal(recordValueMatches("TXT", "dodomain-verify=AbC", "dodomain-verify=AbC"), true);
  // An expected token is never satisfied by an SPF record that happens to contain it.
  assert.equal(
    recordValueMatches("TXT", "dodomain-verify=AbC", "v=spf1 include:dodomain-verify=AbC ~all"),
    false,
  );
});
