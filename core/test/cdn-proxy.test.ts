// The CDN-proxy classifier and its DNS observation — no network: every lookup
// goes through a fake resolver (the verify.ts DnsResolver seam), and the zone is
// handed in so no zone walk runs either.
//
// The production case these pin (2026-09-25): status.getuptimely.com is
// orange-clouded at Cloudflare, so its own nameservers answer A 172.67.195.20 /
// 104.21.44.47 and no CNAME at all, while the site serves 200. The re-check
// read that as a deleted CNAME and kept the connection `broken` for six weeks.

import assert from "node:assert/strict";
import { test } from "node:test";

import { classifyCdnProxy, detectCdnProxy } from "../src/cdn-proxy.ts";
import {
  CDN_PROXY_PROVIDER_LABELS,
  CDN_PROXY_PROVIDERS,
  CDN_PROXY_RANGES,
  type CdnProxyRangeSnapshot,
} from "../src/cdn-proxy-ranges.ts";
import type { DnsResolver } from "../src/verify.ts";

test("the Uptimely status host's real edge addresses (IPv4) classify as proxied by Cloudflare", () => {
  assert.equal(classifyCdnProxy(["172.67.195.20", "104.21.44.47"]), "cloudflare");
});

test("Cloudflare IPv6 edge addresses classify as proxied, in compressed and fully spelled forms", () => {
  assert.equal(classifyCdnProxy(["2606:4700:3030::6815:2c2f"]), "cloudflare");
  assert.equal(classifyCdnProxy(["2606:4700:3030:0000:0000:0000:6815:2c2f"]), "cloudflare");
  // 2a06:98c0::/29 — the one range whose prefix is not a group boundary.
  assert.equal(classifyCdnProxy(["2a06:98c7:ffff::1"]), "cloudflare");
  assert.equal(classifyCdnProxy(["2a06:98c8::1"]), null, "just past the /29 is outside it");
});

test("a mixed A + AAAA answer that is entirely Cloudflare edge classifies as proxied", () => {
  assert.equal(classifyCdnProxy(["104.21.44.47", "2606:4700:3030::ac43:c314"]), "cloudflare");
});

test("an ordinary origin address is not a CDN proxy", () => {
  assert.equal(classifyCdnProxy(["203.0.113.10"]), null);
  assert.equal(classifyCdnProxy(["2001:db8::1"]), null);
});

test("one address outside every proxy range means the name is not (only) behind a proxy", () => {
  assert.equal(classifyCdnProxy(["172.67.195.20", "203.0.113.10"]), null);
});

test("an empty answer is absent, never proxied", () => {
  assert.equal(classifyCdnProxy([]), null);
});

test("a non-address answer (a hostname, garbage) matches no range", () => {
  assert.equal(classifyCdnProxy(["app.getuptimely.com"]), null);
  assert.equal(classifyCdnProxy(["104.21.44"]), null);
  assert.equal(classifyCdnProxy(["2606:4700::1::2"]), null);
});

test("range boundaries are exact: the first and last address of a /13 are inside, one past is not", () => {
  // 104.16.0.0/13 spans 104.16.0.0 – 104.23.255.255.
  assert.equal(classifyCdnProxy(["104.16.0.0"]), "cloudflare");
  assert.equal(classifyCdnProxy(["104.23.255.255"]), "cloudflare");
  assert.equal(classifyCdnProxy(["104.15.255.255"]), null);
});

test("an IPv4 address never matches an IPv6 range, even with an equal numeric value", () => {
  const onlyV6: Record<"cloudflare", CdnProxyRangeSnapshot> = {
    cloudflare: { ...CDN_PROXY_RANGES.cloudflare, ipv4: [], ipv6: ["::/0"] },
  };
  assert.equal(classifyCdnProxy(["10.0.0.1"], onlyV6), null);
  assert.equal(classifyCdnProxy(["::a00:1"], onlyV6), "cloudflare");
});

test("a malformed range in the snapshot throws loudly instead of silently matching nothing", () => {
  const broken: Record<"cloudflare", CdnProxyRangeSnapshot> = {
    cloudflare: { ...CDN_PROXY_RANGES.cloudflare, ipv4: ["104.16.0.0/33"] },
  };
  assert.throws(() => classifyCdnProxy(["104.16.0.1"], broken), /malformed CIDR/);
});

test("every committed snapshot range parses, and every provider is labelled for humans", () => {
  // classifyCdnProxy parses the whole snapshot on each call, so one call over
  // the real snapshot is the parse check for all of it.
  assert.doesNotThrow(() => classifyCdnProxy(["198.51.100.1"]));
  for (const provider of CDN_PROXY_PROVIDERS) {
    assert.ok(CDN_PROXY_RANGES[provider].ipv4.length > 0, `${provider} has IPv4 ranges`);
    assert.ok(CDN_PROXY_RANGES[provider].ipv6.length > 0, `${provider} has IPv6 ranges`);
    assert.match(CDN_PROXY_RANGES[provider].fetchedOn, /^\d{4}-\d{2}-\d{2}$/);
    assert.ok(CDN_PROXY_PROVIDER_LABELS[provider].length > 0);
  }
});

// ── detectCdnProxy: the observation over authoritative DNS ──────────────────

// Mock announcement (house rule): a fake DnsResolver. Only A and AAAA are
// stubbed; any other method throws, so an unexpected lookup fails the test.
function fakeAuthoritative(answers: {
  a?: string[] | { code: string };
  aaaa?: string[] | { code: string };
}): DnsResolver {
  const answer = (value: string[] | { code: string } | undefined) => async () => {
    if (value === undefined) throw Object.assign(new Error("no data"), { code: "ENODATA" });
    if (!Array.isArray(value)) throw Object.assign(new Error("dns error"), value);
    return value;
  };
  const unexpected = (name: string) => async () => {
    throw new Error(`fake authoritative resolver: ${name} was not expected`);
  };
  return {
    resolveNs: unexpected("resolveNs"),
    resolve4: answer(answers.a),
    resolve6: answer(answers.aaaa),
    resolveCname: unexpected("resolveCname"),
    resolveMx: unexpected("resolveMx"),
    resolveTxt: unexpected("resolveTxt"),
    resolveCaa: unexpected("resolveCaa"),
  };
}

function depsFor(resolver: DnsResolver) {
  return {
    zone: "getuptimely.com",
    resolver,
    authoritativeResolverFor: async () => ({ kind: "resolver" as const, resolver }),
  };
}

test("detectCdnProxy reports a proxied name with the provider and the edge addresses it saw", async () => {
  const observation = await detectCdnProxy(
    "status.getuptimely.com",
    depsFor(fakeAuthoritative({ a: ["172.67.195.20", "104.21.44.47"] })),
  );
  assert.deepEqual(observation, {
    kind: "proxied",
    provider: "cloudflare",
    addresses: ["172.67.195.20", "104.21.44.47"],
  });
});

test("detectCdnProxy reports a name with no addresses at all as not proxied", async () => {
  const observation = await detectCdnProxy("gone.getuptimely.com", depsFor(fakeAuthoritative({})));
  assert.deepEqual(observation, { kind: "not_proxied", addresses: [] });
});

test("detectCdnProxy reports a name pointed at an ordinary origin as not proxied", async () => {
  const observation = await detectCdnProxy(
    "moved.getuptimely.com",
    depsFor(fakeAuthoritative({ a: ["203.0.113.10"], aaaa: ["2001:db8::1"] })),
  );
  assert.deepEqual(observation, {
    kind: "not_proxied",
    addresses: ["203.0.113.10", "2001:db8::1"],
  });
});

test("detectCdnProxy never guesses when a lookup fails — a SERVFAIL is unknown, not 'not proxied'", async () => {
  const observation = await detectCdnProxy(
    "status.getuptimely.com",
    depsFor(fakeAuthoritative({ a: { code: "ESERVFAIL" } })),
  );
  assert.deepEqual(observation, { kind: "unknown", code: "ESERVFAIL" });
});

test("detectCdnProxy is unknown when the zone's own nameservers cannot be reached", async () => {
  const resolver = fakeAuthoritative({ a: ["172.67.195.20"] });
  const observation = await detectCdnProxy("status.getuptimely.com", {
    zone: "getuptimely.com",
    resolver,
    authoritativeResolverFor: async () => ({ kind: "ns_error" as const, code: "ETIMEOUT" }),
  });
  assert.deepEqual(observation, { kind: "unknown", code: "ETIMEOUT" });
});
