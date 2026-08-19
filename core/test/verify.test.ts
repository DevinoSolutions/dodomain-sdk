// Pure-function tests for verify.ts's MX matcher — no DNS, no network. F-002 hop
// 2: MX verification now compares exchange AND priority, not exchange alone (the
// old code mapped MX DNS answers to `exchange` only, so a record applied with
// the wrong preference still "verified").

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  matches,
  verifyRecord,
  verifyRecords,
  type AuthoritativeResolution,
  type DnsResolver,
  type VerifyDeps,
} from "../src/verify.ts";
import type { ExpectedRecord } from "../src/types.ts";

const MX: ExpectedRecord = {
  type: "MX",
  fqdn: "mail.customer.com",
  expect: "feedback-smtp.us-east-1.amazonses.com",
  priority: 10,
};

test("MX matches when exchange AND priority both match", () => {
  assert.equal(matches(["10 feedback-smtp.us-east-1.amazonses.com"], MX), true);
});

test("MX rejects a priority mismatch even when the exchange matches", () => {
  assert.equal(matches(["20 feedback-smtp.us-east-1.amazonses.com"], MX), false);
});

test("MX rejects an exchange mismatch even when the priority matches", () => {
  assert.equal(matches(["10 evil-relay.example.net"], MX), false);
});

test("MX is case-insensitive and trailing-dot-insensitive on the exchange", () => {
  assert.equal(matches(["10 Feedback-SMTP.us-east-1.amazonses.com."], MX), true);
});

test("MX with no expected priority falls back to comparing the exchange only (legacy/pre-fix sessions)", () => {
  const legacy: ExpectedRecord = {
    type: "MX",
    fqdn: "mail.customer.com",
    expect: "feedback-smtp.us-east-1.amazonses.com",
  };
  assert.equal(matches(["10 feedback-smtp.us-east-1.amazonses.com"], legacy), true);
  assert.equal(matches(["10 evil-relay.example.net"], legacy), false);
});

test("CNAME/A/AAAA remain exact-match, case/trailing-dot-insensitive (unchanged by F-011)", () => {
  const cname: ExpectedRecord = {
    type: "CNAME",
    fqdn: "www.acme.com",
    expect: "target.example.com",
  };
  assert.equal(matches(["target.example.com."], cname), true);
  assert.equal(matches(["other.example.com"], cname), false);

  const a: ExpectedRecord = { type: "A", fqdn: "acme.com", expect: "203.0.113.10" };
  assert.equal(matches(["203.0.113.10"], a), true);

  const aaaa: ExpectedRecord = { type: "AAAA", fqdn: "acme.com", expect: "2001:db8::1" };
  assert.equal(matches(["2001:db8::1"], aaaa), true);
});

// FIXED(F-011, step 4): TXT was matched by substring ("contains") — a
// verification token like "TOKEN" would pass inside "othertokenXYZ",
// weakening the ownership proof. Now exact, case-sensitive (PM-018: no
// SPF-fragment-merging usage in this codebase — grep-confirmed).
test("TXT is exact-match, case-sensitive (F-011 — was substring/contains)", () => {
  const txt: ExpectedRecord = { type: "TXT", fqdn: "acme.com", expect: "v=spf1" };
  assert.equal(matches(["v=spf1"], txt), true);
  // No longer matches merely because the found value CONTAINS the expected token.
  assert.equal(matches(["v=spf1 include:_spf.example.com ~all"], txt), false);
  assert.equal(matches(["v=DMARC1; p=none;"], txt), false);

  // Case-sensitivity: verification tokens are case-significant.
  const token: ExpectedRecord = {
    type: "TXT",
    fqdn: "_dodomain.acme.com",
    expect: "dodomain-verify=abc123",
  };
  assert.equal(matches(["dodomain-verify=abc123"], token), true);
  assert.equal(matches(["DODOMAIN-VERIFY=ABC123"], token), false);
});

// ─────────────────────────────────────────────────────────────────────────
// F-011: characterization tests for verifyRecord() (previously ZERO tests —
// PLAN-F-011 §4). All offline via the VerifyDeps seam added in this step —
// no DNS/network. Each BUG-labeled test pins CURRENT (pre-fix) behavior; it
// is flipped to the corrected expectation in the commit named in its
// comment, same pin-then-flip convention as the F-002 tests above.
// ─────────────────────────────────────────────────────────────────────────

// A DnsResolver fake: a test only overrides the method(s) it actually
// exercises; any other method throws loudly if accidentally called, so an
// unexpected code path fails fast instead of silently resolving.
function fakeResolver(overrides: Partial<DnsResolver> = {}): DnsResolver {
  const notImplemented = (name: string) => async () => {
    throw new Error(`fakeResolver: ${name} not stubbed for this test`);
  };
  return {
    resolveNs: overrides.resolveNs ?? notImplemented("resolveNs"),
    resolve4: overrides.resolve4 ?? notImplemented("resolve4"),
    resolve6: overrides.resolve6 ?? notImplemented("resolve6"),
    resolveCname: overrides.resolveCname ?? notImplemented("resolveCname"),
    resolveMx: overrides.resolveMx ?? notImplemented("resolveMx"),
    resolveTxt: overrides.resolveTxt ?? notImplemented("resolveTxt"),
  };
}

// Skips the NS→A walk entirely — hands verifyRecord a canned AuthoritativeResolution
// directly, per PLAN-F-011 §2a "two seams, not one". A bare DnsResolver is the
// common case; the failure kinds (`ns_absent`/`ns_error`/`ns_unresolvable`) are
// passed as-is so a test can pin WHICH NS failure it simulates.
function authoritativeReturning(
  resolution: DnsResolver | AuthoritativeResolution,
): NonNullable<VerifyDeps["authoritativeResolverFor"]> {
  const resolved: AuthoritativeResolution =
    "kind" in resolution ? resolution : { kind: "resolver", resolver: resolution };
  return async () => resolved;
}

test("FIXED(F-011, step 3): an authoritative SERVFAIL is reported as indeterminate, not absent — present stays fail-closed", async () => {
  const authResolver = fakeResolver({
    resolveCname: async () => {
      throw Object.assign(new Error("servfail"), { code: "ESERVFAIL" });
    },
  });
  const result = await verifyRecord(
    { fqdn: "www.customer.com", type: "CNAME", expect: "target.example.com" },
    {
      authoritativeResolverFor: authoritativeReturning(authResolver),
      resolver: fakeResolver({ resolveCname: async () => [] }),
    },
  );
  assert.equal(result.present, false); // fail-closed (PM-007): an error path NEVER sets present:true
  assert.deepEqual(result.authoritativeFound, []);
  assert.equal(result.outcome, "indeterminate"); // was indistinguishable from "absent" pre-fix
  assert.equal(result.authoritativeError, "ESERVFAIL");
});

test("an authoritative ENOTFOUND (NXDOMAIN-class) is reported as absent, not indeterminate", async () => {
  const authResolver = fakeResolver({
    resolveCname: async () => {
      throw Object.assign(new Error("nxdomain"), { code: "ENOTFOUND" });
    },
  });
  const result = await verifyRecord(
    { fqdn: "www.customer.com", type: "CNAME", expect: "target.example.com" },
    {
      authoritativeResolverFor: authoritativeReturning(authResolver),
      resolver: fakeResolver({ resolveCname: async () => [] }),
    },
  );
  assert.equal(result.present, false);
  assert.equal(result.outcome, "absent");
  assert.equal(result.authoritativeError, undefined);
});

test("an authoritative ENODATA (name exists, type doesn't) is also reported as absent", async () => {
  const authResolver = fakeResolver({
    resolveTxt: async () => {
      throw Object.assign(new Error("nodata"), { code: "ENODATA" });
    },
  });
  const result = await verifyRecord(
    { fqdn: "customer.com", type: "TXT", expect: "dodomain-verify=abc123" },
    {
      authoritativeResolverFor: authoritativeReturning(authResolver),
      resolver: fakeResolver({ resolveTxt: async () => [] }),
    },
  );
  assert.equal(result.present, false);
  assert.equal(result.outcome, "absent");
});

test("an authoritative ETIMEOUT is indeterminate — retry, don't treat as absent", async () => {
  const authResolver = fakeResolver({
    resolveCname: async () => {
      throw Object.assign(new Error("timeout"), { code: "ETIMEOUT" });
    },
  });
  const result = await verifyRecord(
    { fqdn: "www.customer.com", type: "CNAME", expect: "target.example.com" },
    {
      authoritativeResolverFor: authoritativeReturning(authResolver),
      resolver: fakeResolver({ resolveCname: async () => [] }),
    },
  );
  assert.equal(result.present, false);
  assert.equal(result.outcome, "indeterminate");
  assert.equal(result.authoritativeError, "ETIMEOUT");
});

test("the zone's authoritative nameservers can't be resolved at all → indeterminate, not absent", async () => {
  const result = await verifyRecord(
    { fqdn: "www.customer.com", type: "CNAME", expect: "target.example.com" },
    {
      authoritativeResolverFor: authoritativeReturning({ kind: "ns_unresolvable" }),
      resolver: fakeResolver({ resolveCname: async () => [] }),
    },
  );
  assert.equal(result.present, false);
  assert.equal(result.outcome, "indeterminate");
  assert.equal(result.authoritativeError, "NS_RESOLUTION_FAILED");
  assert.equal(result.note, "could not resolve authoritative nameservers; public-only check");
});

// ─────────────────────────────────────────────────────────────────────────
// An UNREGISTERED (or misspelled) domain used to be indistinguishable from
// "our DNS check broke": resolveNs threw ENOTFOUND, the code was discarded,
// and the synthetic NS_RESOLUTION_FAILED made it outcome:"indeterminate" —
// the retry-forever bucket. The user was never told the domain doesn't exist.
// ─────────────────────────────────────────────────────────────────────────

test("an unregistered domain (apex NS NXDOMAIN + public resolver NXDOMAIN) is reported as domain_not_found, not indeterminate", async () => {
  const result = await verifyRecord(
    { fqdn: "www.nope-not-registered.com", type: "CNAME", expect: "target.example.com" },
    {
      authoritativeResolverFor: authoritativeReturning({ kind: "ns_absent", code: "ENOTFOUND" }),
      resolver: fakeResolver({
        resolveCname: async () => {
          throw Object.assign(new Error("nxdomain"), { code: "ENOTFOUND" });
        },
      }),
    },
  );
  assert.equal(result.present, false); // fail-closed is unchanged
  assert.equal(result.outcome, "domain_not_found");
  assert.equal(result.authoritativeError, "ENOTFOUND"); // the NS query's own code, no longer discarded
  assert.equal(
    result.note,
    "domain does not resolve — it may be unregistered, misspelled, or have no nameservers",
  );
});

test("a zone whose apex answers NODATA for NS, with the public resolver also finding nothing, is domain_not_found", async () => {
  const result = await verifyRecord(
    { fqdn: "acme.test", type: "TXT", expect: "dodomain-verify=abc123" },
    {
      authoritativeResolverFor: authoritativeReturning({ kind: "ns_absent", code: "ENODATA" }),
      resolver: fakeResolver({
        resolveTxt: async () => {
          throw Object.assign(new Error("nodata"), { code: "ENODATA" });
        },
      }),
    },
  );
  assert.equal(result.outcome, "domain_not_found");
  assert.equal(result.authoritativeError, "ENODATA");
});

test("an apex NS NXDOMAIN whose public-resolver check itself ERRORED stays indeterminate — one answer is not proof the domain is gone", async () => {
  const result = await verifyRecord(
    { fqdn: "www.customer.com", type: "CNAME", expect: "target.example.com" },
    {
      authoritativeResolverFor: authoritativeReturning({ kind: "ns_absent", code: "ENOTFOUND" }),
      resolver: fakeResolver({
        resolveCname: async () => {
          throw Object.assign(new Error("servfail"), { code: "ESERVFAIL" });
        },
      }),
    },
  );
  assert.equal(result.outcome, "indeterminate");
  assert.equal(result.authoritativeError, "NS_RESOLUTION_FAILED");
  assert.equal(result.publicError, "ESERVFAIL");
});

test("an NS query that ERRORED (SERVFAIL, not NXDOMAIN) stays indeterminate even when the public resolver finds nothing", async () => {
  const result = await verifyRecord(
    { fqdn: "www.customer.com", type: "CNAME", expect: "target.example.com" },
    {
      authoritativeResolverFor: authoritativeReturning({ kind: "ns_error", code: "ESERVFAIL" }),
      resolver: fakeResolver({
        resolveCname: async () => {
          throw Object.assign(new Error("nxdomain"), { code: "ENOTFOUND" });
        },
      }),
    },
  );
  assert.equal(result.outcome, "indeterminate");
  assert.equal(result.authoritativeError, "NS_RESOLUTION_FAILED");
});

// The real (non-injected) NS→A walk owns the ns_absent/ns_error split, so it
// gets its own pins through the `resolver` seam — the walk calls resolveNs on
// the PSL apex, and only an NXDOMAIN-class answer there may become
// domain_not_found.
test("the default NS walk classifies an ENOTFOUND apex NS query as domain_not_found when public DNS agrees", async () => {
  const result = await verifyRecord(
    { fqdn: "www.nope-not-registered.com", type: "CNAME", expect: "target.example.com" },
    {
      resolver: fakeResolver({
        resolveNs: async () => {
          throw Object.assign(new Error("nxdomain"), { code: "ENOTFOUND" });
        },
        resolveCname: async () => {
          throw Object.assign(new Error("nxdomain"), { code: "ENOTFOUND" });
        },
      }),
    },
  );
  assert.equal(result.outcome, "domain_not_found");
  assert.equal(result.authoritativeError, "ENOTFOUND");
});

test("the default NS walk keeps a SERVFAIL apex NS query indeterminate — a broken resolver is not a missing domain", async () => {
  const result = await verifyRecord(
    { fqdn: "www.customer.com", type: "CNAME", expect: "target.example.com" },
    {
      resolver: fakeResolver({
        resolveNs: async () => {
          throw Object.assign(new Error("servfail"), { code: "ESERVFAIL" });
        },
        resolveCname: async () => {
          throw Object.assign(new Error("nxdomain"), { code: "ENOTFOUND" });
        },
      }),
    },
  );
  assert.equal(result.outcome, "indeterminate");
  assert.equal(result.authoritativeError, "NS_RESOLUTION_FAILED");
});

test("the default NS walk reports nameservers that exist but resolve to no address as indeterminate, never domain_not_found", async () => {
  const result = await verifyRecord(
    { fqdn: "www.customer.com", type: "CNAME", expect: "target.example.com" },
    {
      resolver: fakeResolver({
        resolveNs: async () => ["ns1.customer.com", "ns2.customer.com"],
        resolve4: async () => {
          throw Object.assign(new Error("nxdomain"), { code: "ENOTFOUND" });
        },
        resolveCname: async () => {
          throw Object.assign(new Error("nxdomain"), { code: "ENOTFOUND" });
        },
      }),
    },
  );
  assert.equal(result.outcome, "indeterminate");
  assert.equal(result.authoritativeError, "NS_RESOLUTION_FAILED");
});

test("a public-side DNS error is surfaced as publicError but never affects present/outcome", async () => {
  const authResolver = fakeResolver({ resolveCname: async () => ["target.example.com"] });
  const publicResolver = fakeResolver({
    resolveCname: async () => {
      throw Object.assign(new Error("servfail"), { code: "ESERVFAIL" });
    },
  });
  const result = await verifyRecord(
    { fqdn: "www.customer.com", type: "CNAME", expect: "target.example.com" },
    { authoritativeResolverFor: authoritativeReturning(authResolver), resolver: publicResolver },
  );
  assert.equal(result.present, true); // authoritative matched — public-side trouble doesn't gate this
  assert.equal(result.outcome, "propagating");
  assert.equal(result.publicError, "ESERVFAIL");
});

test("FIXED(F-011, step 2): NS is asked for the customer's registrable domain, never the registry zone", async () => {
  const calls: string[] = [];
  const resolver = fakeResolver({
    resolveNs: async (zone) => {
      calls.push(zone);
      return [];
    },
  });
  await verifyRecord({ fqdn: "status.customer.co.uk", type: "TXT", expect: "x" }, { resolver });

  // Pre-F-011 this asked "co.uk" — the REGISTRY's own zone. It then asked
  // exactly "customer.co.uk"; since the owning-zone walk landed (2026-08-06) it
  // probes the more specific name first and floors at the registrable domain,
  // so the call list grew while the guarantee this test exists for did not
  // change: the public suffix is never queried.
  assert.ok(!calls.includes("co.uk"), "the registry's zone is never a customer's");
  assert.ok(!calls.includes("uk"));
  assert.ok(calls.includes("customer.co.uk"), "the registrable domain is the floor");
  assert.deepEqual(new Set(calls), new Set(["status.customer.co.uk", "customer.co.uk"]));
});

test("FIXED(F-011, step 4): TXT is exact-match, not substring", async () => {
  const authResolver = fakeResolver({ resolveTxt: async () => [["prefix-TOKEN-suffix"]] });
  const result = await verifyRecord(
    { fqdn: "_dodomain.customer.com", type: "TXT", expect: "TOKEN" },
    {
      authoritativeResolverFor: authoritativeReturning(authResolver),
      resolver: fakeResolver({ resolveTxt: async () => [] }),
    },
  );
  assert.equal(result.present, false); // "TOKEN" no longer matches merely because it's a substring
  assert.equal(result.outcome, "absent");
});

test("happy path: authoritative + public both match → present:true, verified", async () => {
  const cnameResolver = fakeResolver({ resolveCname: async () => ["target.example.com"] });
  const result = await verifyRecord(
    { fqdn: "www.customer.com", type: "CNAME", expect: "target.example.com" },
    { authoritativeResolverFor: authoritativeReturning(cnameResolver), resolver: cnameResolver },
  );
  assert.equal(result.present, true);
  assert.equal(result.note, "verified on authoritative and public DNS");
  assert.equal(result.outcome, "verified");
});

test("happy path: authoritative match, public not yet propagated → present:true, propagating", async () => {
  const authResolver = fakeResolver({ resolveCname: async () => ["target.example.com"] });
  const publicResolver = fakeResolver({ resolveCname: async () => [] });
  const result = await verifyRecord(
    { fqdn: "www.customer.com", type: "CNAME", expect: "target.example.com" },
    { authoritativeResolverFor: authoritativeReturning(authResolver), resolver: publicResolver },
  );
  assert.equal(result.present, true);
  assert.equal(result.note, "on authoritative DNS; public resolvers still propagating");
  assert.equal(result.outcome, "propagating");
});

// Scale foundation (2026-07-10): verifyRecord accepts bounded DNS timeout/tries
// (VerifyDeps.dnsTimeoutMs/dnsTries), applied to the real resolvers it builds so
// a black-holed nameserver can't hang the request thread. Asserting the socket
// timeout itself would need a slow/black-holed server (a flaky network test), so
// this only pins that the new config knobs are accepted and INERT on the
// verification logic — an injected resolver still owns its own timing, and the
// outcome is identical with or without the knobs set.
test("dnsTimeoutMs/dnsTries are accepted and do not alter the verification outcome (injected resolver owns timing)", async () => {
  const cnameResolver = fakeResolver({ resolveCname: async () => ["target.example.com"] });
  const rec: ExpectedRecord = {
    type: "CNAME",
    fqdn: "www.customer.com",
    expect: "target.example.com",
  };
  const withKnobs = await verifyRecord(rec, {
    authoritativeResolverFor: authoritativeReturning(cnameResolver),
    resolver: cnameResolver,
    dnsTimeoutMs: 1234,
    dnsTries: 3,
  });
  const withoutKnobs = await verifyRecord(rec, {
    authoritativeResolverFor: authoritativeReturning(cnameResolver),
    resolver: cnameResolver,
  });
  assert.deepEqual(withKnobs, withoutKnobs);
  assert.equal(withKnobs.outcome, "verified");
});

// ─────────────────────────────────────────────────────────────────────────
// BLOCKER E: verification must ask the zone that OWNS the record.
//
// Live 2026-08-06 — the first real Domain Connect apply ever written to a
// provider-managed zone. The TXT was demonstrably in place on all four
// authoritative nameservers and on three public resolvers, and DoDomain still
// reported `absent` five times running. verify.ts resolved
// `apexOf("_dodomain-challenge.dc.mrneon.online")` = mrneon.online, whose NS
// are Cloudflare's — but dc.mrneon.online is a DELEGATED subzone served by
// as207960. Querying the apex's nameservers DIRECTLY (non-recursively) for a
// name below the delegation cut returns a referral, which c-ares surfaces as
// ENOTFOUND, and verify read that as "the record isn't there".
//
//   apexOf(fqdn) = mrneon.online -> doug/riya.ns.cloudflare.com -> ENOTFOUND
//   nearest cut  = dc.mrneon.online -> ns1..ns4.as207960.net -> the TXT
//
// Same class as the start route's apex pre-flight: every customer on a
// delegated subzone could never verify — tier-3 manual included, since every
// path runs this same verify.
// ─────────────────────────────────────────────────────────────────────────

const GLAUCA_TXT = "dodomain-verify=glaucae2e20260806";
const CHALLENGE: ExpectedRecord = {
  fqdn: "_dodomain-challenge.dc.mrneon.online",
  type: "TXT",
  expect: GLAUCA_TXT,
};

/** The live delegation, as probed: only these two names own an NS RRset. */
const LIVE_NS: Record<string, string[]> = {
  "dc.mrneon.online": ["ns1.as207960.net", "ns2.as207960.net"],
  "mrneon.online": ["doug.ns.cloudflare.com", "riya.ns.cloudflare.com"],
};

function nxdomain() {
  return Object.assign(new Error("nxdomain"), { code: "ENOTFOUND" });
}

/**
 * Models the live zones. `nsAsked` records every name the zone walk queried NS
 * for; `zonesAsked` records every zone whose authoritative nameservers verify
 * actually went on to interrogate.
 */
function liveDelegationDeps(nsMap: Record<string, string[]> = LIVE_NS) {
  const nsAsked: string[] = [];
  const zonesAsked: string[] = [];
  const deps: VerifyDeps = {
    resolver: fakeResolver({
      resolveNs: async (host: string) => {
        nsAsked.push(host);
        const ns = nsMap[host];
        if (!ns) throw nxdomain();
        return ns;
      },
      // Public recursive resolvers all saw the record (8.8.8.8, 9.9.9.9, 1.1.1.1).
      resolveTxt: async () => [[GLAUCA_TXT]],
    }),
    authoritativeResolverFor: async (zone: string) => {
      zonesAsked.push(zone);
      if (zone === "dc.mrneon.online") {
        // as207960 is authoritative here and serves the record.
        return {
          kind: "resolver",
          resolver: fakeResolver({ resolveTxt: async () => [[GLAUCA_TXT]] }),
        };
      }
      // Cloudflare holds mrneon.online but NOT the delegated child: a direct
      // query for a name under the cut yields a referral -> ENOTFOUND.
      return {
        kind: "resolver",
        resolver: fakeResolver({
          resolveTxt: async () => {
            throw nxdomain();
          },
        }),
      };
    },
  };
  return { deps, nsAsked, zonesAsked };
}

test("a record inside a DELEGATED SUBZONE verifies against that subzone's nameservers, not the registrable apex's", async () => {
  const { deps, zonesAsked } = liveDelegationDeps();
  const result = await verifyRecord(CHALLENGE, deps);

  assert.deepEqual(zonesAsked, ["dc.mrneon.online"], "the apex's nameservers must never be asked");
  assert.equal(result.present, true);
  assert.equal(result.outcome, "verified");
  assert.deepEqual(result.authoritativeFound, [GLAUCA_TXT]);
});

test("the zone walk stops at the delegation cut and never queries the public suffix", async () => {
  const { deps, nsAsked } = liveDelegationDeps();
  await verifyRecord(CHALLENGE, deps);

  assert.deepEqual(nsAsked, ["_dodomain-challenge.dc.mrneon.online", "dc.mrneon.online"]);
  assert.ok(
    !nsAsked.includes("online"),
    "the public suffix is the registry's zone, never a customer's",
  );
  assert.ok(
    !nsAsked.includes("mrneon.online"),
    "the walk stops the moment a name owns an NS RRset",
  );
});

test("a record with NO delegated subzone still verifies against the registrable apex — unchanged behaviour", async () => {
  const { deps, zonesAsked } = liveDelegationDeps({
    "feastables.com": ["ns1.example.net", "ns2.example.net"],
  });
  const result = await verifyRecord(
    { fqdn: "_dodomain-challenge.feastables.com", type: "TXT", expect: GLAUCA_TXT },
    {
      ...deps,
      authoritativeResolverFor: async (zone: string) => {
        zonesAsked.push(zone);
        return {
          kind: "resolver",
          resolver: fakeResolver({ resolveTxt: async () => [[GLAUCA_TXT]] }),
        };
      },
    },
  );

  assert.deepEqual(zonesAsked, ["feastables.com"], "floors at the apex exactly as apexOf did");
  assert.equal(result.outcome, "verified");
});

test("a domain whose nameservers do not exist still reports domain_not_found, not a broken walk", async () => {
  // The walk floors at the apex and finds nothing; the apex NS query then
  // answers NXDOMAIN and the public resolver agrees — the two independent
  // answers that distinguish an unregistered domain from our check breaking.
  const zonesAsked: string[] = [];
  const result = await verifyRecord(
    { fqdn: "_dodomain-challenge.nosuchdomain-dodomain.com", type: "TXT", expect: GLAUCA_TXT },
    {
      resolver: fakeResolver({
        resolveNs: async () => {
          throw nxdomain();
        },
        resolveTxt: async () => {
          throw nxdomain();
        },
      }),
      authoritativeResolverFor: async (zone: string) => {
        zonesAsked.push(zone);
        return { kind: "ns_absent", code: "ENOTFOUND" };
      },
    },
  );

  assert.deepEqual(zonesAsked, ["nosuchdomain-dodomain.com"]);
  assert.equal(result.outcome, "domain_not_found");
});

test("verifyRecords pays the shared part of the walk ONCE for records in the same zone", async () => {
  // A session verifies all its records in one run. Each record still gets its
  // own honest walk (a deeper delegation under a sibling name must not be
  // skipped), but the NS lookups they share cost exactly one query.
  const { deps, nsAsked, zonesAsked } = liveDelegationDeps();
  const results = await verifyRecords(
    [CHALLENGE, { fqdn: "www.dc.mrneon.online", type: "TXT", expect: GLAUCA_TXT }],
    deps,
  );

  assert.equal(results.length, 2);
  assert.ok(results.every((r) => r.outcome === "verified"));
  assert.equal(
    nsAsked.filter((h) => h === "dc.mrneon.online").length,
    1,
    "the delegation cut both records share is resolved once, not once per record",
  );
  assert.ok(!nsAsked.includes("mrneon.online"), "still never climbs to the apex");
  assert.deepEqual(zonesAsked, ["dc.mrneon.online", "dc.mrneon.online"]);
});

test("verifyRecords still routes each record to its OWN zone when a run spans several", async () => {
  const { deps, zonesAsked } = liveDelegationDeps({
    "dc.mrneon.online": ["ns1.as207960.net"],
    "other.example": ["ns1.other.example"],
  });
  await verifyRecords(
    [CHALLENGE, { fqdn: "www.other.example", type: "TXT", expect: GLAUCA_TXT }],
    deps,
  );

  assert.deepEqual(zonesAsked, ["dc.mrneon.online", "other.example"]);
});

test("verifyRecords with a caller-supplied zone skips the walk entirely", async () => {
  const { deps, nsAsked } = liveDelegationDeps();
  const results = await verifyRecords([CHALLENGE], { ...deps, zone: "dc.mrneon.online" });

  assert.equal(results[0]?.outcome, "verified");
  assert.deepEqual(nsAsked, [], "a pre-resolved zone costs no DNS at all");
});
