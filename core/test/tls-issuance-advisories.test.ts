// Offline tests for the TLS-issuance advisories — every DNS answer is a fake
// shaped like what node:dns returns for real zones (google.com's CAA set,
// a Cloudflare-style delegated `_acme-challenge` CNAME, a Let's Encrypt
// DNS-01 token). No network: a network call here would hang CI, which is the
// enforcing check for the DnsResolver seam (verify.ts).

import assert from "node:assert/strict";
import { test } from "node:test";

import { detectTlsIssuanceAdvisories, judgeCaaAnswers } from "../src/tls-issuance-advisories.ts";
import type { TlsIssuanceAdvisory } from "../src/tls-issuance-advisory-types.ts";
import type { AuthoritativeResolution, CaaAnswer, DnsResolver } from "../src/verify.ts";
import type { ExpectedRecord } from "../src/verify-types.ts";

function dnsError(code: string): Error {
  return Object.assign(new Error(code), { code });
}

/** Per-name answer table. A missing name answers ENODATA, like a real empty RRset. */
interface ZoneFixture {
  caa?: Record<string, CaaAnswer[] | Error>;
  cname?: Record<string, string[] | Error>;
  txt?: Record<string, string[][] | Error>;
}

function fakeResolver(fixture: ZoneFixture, calls: string[] = []): DnsResolver {
  const answer = <T>(table: Record<string, T | Error> | undefined, name: string, kind: string) => {
    calls.push(`${kind} ${name}`);
    const value = table?.[name];
    if (value === undefined) throw dnsError("ENODATA");
    if (value instanceof Error) throw value;
    return value;
  };
  const notImplemented = (name: string) => async () => {
    throw new Error(`fakeResolver: ${name} not stubbed for this test`);
  };
  return {
    resolveNs: notImplemented("resolveNs"),
    resolve4: notImplemented("resolve4"),
    resolve6: notImplemented("resolve6"),
    resolveMx: notImplemented("resolveMx"),
    resolveCaa: async (name) => answer(fixture.caa, name, "CAA"),
    resolveCname: async (name) => answer(fixture.cname, name, "CNAME"),
    resolveTxt: async (name) => answer(fixture.txt, name, "TXT"),
  };
}

/** Both resolvers pinned to the same fixture, zone pre-resolved (no NS walk). */
function depsFor(fixture: ZoneFixture, zone: string, calls: string[] = []) {
  const resolver = fakeResolver(fixture, calls);
  return {
    resolver,
    zone,
    authoritativeResolverFor: async (): Promise<AuthoritativeResolution> => ({
      kind: "resolver",
      resolver,
    }),
  };
}

const CNAME_WWW: ExpectedRecord = {
  type: "CNAME",
  fqdn: "www.customer.com",
  expect: "edge.integrator.app",
};

// google.com's real CAA set (2026): `0 issue "pki.goog"` — the canonical
// "someone else's CA" fixture.
const GOOGLE_STYLE_CAA: CaaAnswer[] = [{ critical: 0, issue: "pki.goog" }];

function codes(advisories: TlsIssuanceAdvisory[]): string[] {
  return advisories.map((a) => a.code);
}

test("no CAA anywhere up to the apex and no challenge record → no advisories (clean is clean)", async () => {
  const calls: string[] = [];
  const out = await detectTlsIssuanceAdvisories(
    [CNAME_WWW],
    "letsencrypt.org",
    depsFor({}, "customer.com", calls),
  );
  assert.deepEqual(out, []);
  // The climb went host → apex, then read the challenge name once each way.
  assert.deepEqual(calls, [
    "CAA www.customer.com",
    "CAA customer.com",
    "CNAME _acme-challenge.www.customer.com",
    "TXT _acme-challenge.www.customer.com",
  ]);
});

test("a CAA set at the APEX that names another CA excludes the configured issuer — inherited by the host (RFC 8659 climb)", async () => {
  const out = await detectTlsIssuanceAdvisories(
    [CNAME_WWW],
    "letsencrypt.org",
    depsFor({ caa: { "customer.com": GOOGLE_STYLE_CAA } }, "customer.com"),
  );
  assert.equal(out.length, 1);
  const [advisory] = out;
  assert.equal(advisory!.code, "caa_excludes_issuer");
  assert.equal(advisory!.severity, "warning");
  assert.equal(advisory!.fqdn, "www.customer.com");
  assert.equal(advisory!.evidenceFqdn, "customer.com");
  assert.deepEqual(advisory!.evidence, ['issue "pki.goog"']);
  assert.match(advisory!.note, /allows only pki\.goog/);
  assert.match(advisory!.note, /letsencrypt\.org is not on it/);
});

test("the FIRST CAA set found on the climb wins: a host-level set shadows a stricter apex set", async () => {
  const out = await detectTlsIssuanceAdvisories(
    [CNAME_WWW],
    "letsencrypt.org",
    depsFor(
      {
        caa: {
          "www.customer.com": [{ critical: 0, issue: "letsencrypt.org" }],
          "customer.com": GOOGLE_STYLE_CAA,
        },
      },
      "customer.com",
    ),
  );
  assert.deepEqual(out, []);
});

test("issuer matching is case-insensitive, trailing-dot-insensitive and ignores `;` parameters", () => {
  const answers: CaaAnswer[] = [
    { critical: 0, issue: "LetsEncrypt.ORG.; validationmethods=dns-01" },
  ];
  assert.equal(
    judgeCaaAnswers("www.customer.com", "customer.com", answers, "letsencrypt.org"),
    null,
  );
  assert.equal(
    judgeCaaAnswers("www.customer.com", "customer.com", answers, "LETSENCRYPT.org."),
    null,
  );
});

test('`issue ";"` (empty issuer) forbids every CA', () => {
  const verdict = judgeCaaAnswers(
    "www.customer.com",
    "customer.com",
    [{ critical: 0, issue: ";" }],
    "letsencrypt.org",
  );
  assert.equal(verdict?.code, "caa_excludes_issuer");
  assert.match(verdict!.note, /forbids every certificate authority/);
});

test("a CAA set with only iodef/issuewild tags restricts nothing for a non-wildcard name", () => {
  const verdict = judgeCaaAnswers(
    "www.customer.com",
    "customer.com",
    [
      { critical: 0, iodef: "mailto:security@customer.com" },
      { critical: 0, issuewild: "sectigo.com" },
    ],
    "letsencrypt.org",
  );
  assert.equal(verdict, null);
});

test("a CAA set with NO configured CA is reported as info (`caa_restricts_issuance`) — a fact, not a verdict", () => {
  const verdict = judgeCaaAnswers("www.customer.com", "customer.com", GOOGLE_STYLE_CAA, null);
  assert.equal(verdict?.code, "caa_restricts_issuance");
  assert.equal(verdict?.severity, "info");
  assert.deepEqual(verdict?.evidence, ['issue "pki.goog"']);
});

test("a delegated `_acme-challenge` CNAME is a stale-challenge warning quoting the target", async () => {
  const out = await detectTlsIssuanceAdvisories(
    [CNAME_WWW],
    "letsencrypt.org",
    depsFor(
      { cname: { "_acme-challenge.www.customer.com": ["www.customer.com.acme.old-vendor.net"] } },
      "customer.com",
    ),
  );
  assert.deepEqual(codes(out), ["stale_acme_challenge"]);
  assert.equal(out[0]!.evidenceFqdn, "_acme-challenge.www.customer.com");
  assert.deepEqual(out[0]!.evidence, ["CNAME www.customer.com.acme.old-vendor.net"]);
});

test("a leftover DNS-01 TXT token is a stale-challenge warning quoting the token verbatim", async () => {
  const token = "gfj9Xq_Ro8m1WQ4nxZoQZsgLHPjFwx2Jgd7T4C5N0Ns";
  const out = await detectTlsIssuanceAdvisories(
    [CNAME_WWW],
    "letsencrypt.org",
    depsFor({ txt: { "_acme-challenge.www.customer.com": [[token]] } }, "customer.com"),
  );
  assert.deepEqual(codes(out), ["stale_acme_challenge"]);
  assert.deepEqual(out[0]!.evidence, [token]);
});

test("CAA and ACME advisories for one host are both reported, CAA first", async () => {
  const out = await detectTlsIssuanceAdvisories(
    [CNAME_WWW],
    "letsencrypt.org",
    depsFor(
      {
        caa: { "customer.com": GOOGLE_STYLE_CAA },
        txt: { "_acme-challenge.www.customer.com": [["stale"]] },
      },
      "customer.com",
    ),
  );
  assert.deepEqual(codes(out), ["caa_excludes_issuer", "stale_acme_challenge"]);
});

test("only TLS-terminating records are inspected: a TXT-only session produces nothing and touches no DNS", async () => {
  const calls: string[] = [];
  const out = await detectTlsIssuanceAdvisories(
    [{ type: "TXT", fqdn: "_dodomain.customer.com", expect: "dodomain-verify=abc" }],
    "letsencrypt.org",
    depsFor({ caa: { "customer.com": GOOGLE_STYLE_CAA } }, "customer.com", calls),
  );
  assert.deepEqual(out, []);
  assert.deepEqual(calls, []);
});

test("an A and an AAAA for the same host are inspected ONCE", async () => {
  const calls: string[] = [];
  await detectTlsIssuanceAdvisories(
    [
      { type: "A", fqdn: "customer.com", expect: "203.0.113.10" },
      { type: "AAAA", fqdn: "customer.com", expect: "2001:db8::1" },
    ],
    null,
    depsFor({}, "customer.com", calls),
  );
  assert.equal(calls.filter((c) => c === "CAA customer.com").length, 1);
});

test("a CAA lookup that FAILS (SERVFAIL) yields `tls_issuance_unchecked`, never an empty list — unknown ≠ clean", async () => {
  const out = await detectTlsIssuanceAdvisories(
    [CNAME_WWW],
    "letsencrypt.org",
    depsFor({ caa: { "www.customer.com": dnsError("ESERVFAIL") } }, "customer.com"),
  );
  assert.deepEqual(codes(out), ["tls_issuance_unchecked"]);
  assert.equal(out[0]!.severity, "info");
  assert.match(out[0]!.note, /ESERVFAIL/);
});

test("unresolvable nameservers yield one `tls_issuance_unchecked` per host and no other lookups", async () => {
  const calls: string[] = [];
  const out = await detectTlsIssuanceAdvisories([CNAME_WWW], "letsencrypt.org", {
    resolver: fakeResolver({}, calls),
    zone: "customer.com",
    authoritativeResolverFor: async () => ({ kind: "ns_unresolvable" }),
  });
  assert.deepEqual(codes(out), ["tls_issuance_unchecked"]);
  assert.deepEqual(calls, []);
});

test("names ABOVE a delegated zone cut are read through the public resolver, names at/below it authoritatively", async () => {
  // Session host lives in the delegated subzone dc.customer.com (its own NS),
  // but the CAA policy is published at the registrable apex customer.com.
  const authoritativeCalls: string[] = [];
  const publicCalls: string[] = [];
  const authoritative = fakeResolver({}, authoritativeCalls);
  const publicResolver = fakeResolver({ caa: { "customer.com": GOOGLE_STYLE_CAA } }, publicCalls);
  const out = await detectTlsIssuanceAdvisories(
    [{ type: "CNAME", fqdn: "app.dc.customer.com", expect: "edge.integrator.app" }],
    "letsencrypt.org",
    {
      resolver: publicResolver,
      zone: "dc.customer.com",
      authoritativeResolverFor: async () => ({ kind: "resolver", resolver: authoritative }),
    },
  );
  assert.deepEqual(codes(out), ["caa_excludes_issuer"]);
  assert.equal(out[0]!.evidenceFqdn, "customer.com");
  assert.deepEqual(
    authoritativeCalls.filter((c) => c.startsWith("CAA")),
    ["CAA app.dc.customer.com", "CAA dc.customer.com"],
  );
  assert.deepEqual(publicCalls, ["CAA customer.com"]);
});
