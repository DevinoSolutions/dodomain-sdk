// A zone's nameservers come from its PARENT's delegation first (T-10301), so a
// recursive resolver still caching the pre-move NS set cannot pick the wrong
// provider (detection) or pin read-back to the wrong servers (verify). Every
// case runs on injected seams: no DNS, no sockets.

import { test } from "node:test";
import assert from "node:assert/strict";
import { NODATA, NOTFOUND } from "node:dns";

import { Resolver } from "node:dns/promises";

import { detectProvider } from "../src/detect.ts";
import {
  resolveZoneAuthority,
  type AuthoritativeResolution,
  type DnsResolver,
} from "../src/verify.ts";
import { zoneNameServers, type NsTrace } from "../src/zone-walk.ts";

// The 2026-10-29 evidence: dodomaindemo.xyz moved Vercel -> Porkbun at 11:22Z;
// the web container's resolver kept answering Vercel (NS TTL 86400).
const STALE_VERCEL = ["ns1.vercel-dns.com", "ns2.vercel-dns.com"];
const CURRENT_PORKBUN = ["curitiba.ns.porkbun.com", "fortaleza.ns.porkbun.com"];

/** The servers the default authoritative resolver was pinned to (a real node:dns Resolver, never queried here). */
function pinnedServers(auth: AuthoritativeResolution): string[] {
  assert.equal(auth.kind, "resolver");
  if (auth.kind !== "resolver") return [];
  assert.ok(
    auth.resolver instanceof Resolver,
    "the default authoritative resolver is a node:dns Resolver",
  );
  return auth.resolver.getServers();
}

const noDomainConnect = async (): Promise<never> => {
  throw new Error("no _domainconnect record");
};

test("detection picks the provider the parent delegates to when the recursive resolver still caches the old one", async () => {
  const traces: NsTrace[] = [];
  const match = await detectProvider("dodomaindemo.xyz", {
    resolveNs: async () => STALE_VERCEL,
    resolveCname: async () => [],
    parentNs: async (zone) => {
      assert.equal(zone, "dodomaindemo.xyz");
      return CURRENT_PORKBUN;
    },
    onNsTrace: (t) => traces.push(t),
    discover: noDomainConnect,
  });
  assert.equal(match.provider, "porkbun");
  assert.equal(match.label, "Porkbun");
  assert.deepEqual(match.nameServers, CURRENT_PORKBUN);
  assert.deepEqual(traces, [
    {
      event: "dns.ns.recursive_stale",
      zone: "dodomaindemo.xyz",
      parent: CURRENT_PORKBUN,
      recursive: STALE_VERCEL,
    },
  ]);
});

test("when the parent lookup fails, detection falls back to the recursive answer and reports the fallback with its code", async () => {
  const traces: NsTrace[] = [];
  const match = await detectProvider("dodomaindemo.xyz", {
    resolveNs: async () => STALE_VERCEL,
    resolveCname: async () => [],
    parentNs: async () => {
      throw Object.assign(new Error("no parent server answered"), { code: "ETIMEOUT" });
    },
    onNsTrace: (t) => traces.push(t),
    discover: noDomainConnect,
  });
  assert.equal(match.provider, "vercel");
  assert.deepEqual(match.nameServers, STALE_VERCEL);
  assert.equal(traces.length, 1);
  assert.deepEqual(traces[0], {
    event: "dns.ns.parent_fallback",
    zone: "dodomaindemo.xyz",
    parentError: "ETIMEOUT",
    parentMessage: "no parent server answered",
    recursive: STALE_VERCEL,
  });
});

test("a parent and recursive view that agree report nothing", async () => {
  const traces: NsTrace[] = [];
  const result = await zoneNameServers("dodomaindemo.xyz", {
    resolveNs: async () => ["Curitiba.NS.Porkbun.com.", "fortaleza.ns.porkbun.com"],
    parentNs: async () => [...CURRENT_PORKBUN].reverse(),
    onNsTrace: (t) => traces.push(t),
  });
  assert.equal(result.source, "parent");
  assert.deepEqual(new Set(result.nameServers), new Set(CURRENT_PORKBUN));
  assert.deepEqual(traces, []);
});

test("the parent's answer still wins when the recursive lookup itself failed, and the disagreement is reported", async () => {
  const traces: NsTrace[] = [];
  const result = await zoneNameServers("fresh.xyz", {
    resolveNs: async () => {
      // a brand-new registration the recursive resolver negative-cached
      throw Object.assign(new Error(NOTFOUND), { code: NOTFOUND });
    },
    parentNs: async () => CURRENT_PORKBUN,
    onNsTrace: (t) => traces.push(t),
  });
  assert.deepEqual(result, { nameServers: CURRENT_PORKBUN, source: "parent" });
  assert.deepEqual(traces[0]?.event, "dns.ns.recursive_stale");
});

test("when neither view yields nameservers the RECURSIVE error is thrown, so NXDOMAIN keeps reading as no-such-domain", async () => {
  const traces: NsTrace[] = [];
  await assert.rejects(
    zoneNameServers("nothere.xyz", {
      resolveNs: async () => {
        throw Object.assign(new Error(NOTFOUND), { code: NOTFOUND });
      },
      parentNs: async () => {
        throw Object.assign(new Error("parent NXDOMAIN"), { code: NOTFOUND });
      },
      onNsTrace: (t) => traces.push(t),
    }),
    (e: NodeJS.ErrnoException) => e.code === NOTFOUND,
  );
  assert.equal(traces[0]?.event, "dns.ns.parent_fallback");
});

test("read-back pins record queries to the parent-delegated nameservers, not the stale recursive set", async () => {
  // Vercel's servers on 192.0.2.x, Porkbun's on 198.51.100.x (RFC 5737). The
  // pinned resolver is only CONSTRUCTED here; no record query is sent.
  const addresses: Record<string, string> = {
    "ns1.vercel-dns.com": "192.0.2.1",
    "ns2.vercel-dns.com": "192.0.2.2",
    "curitiba.ns.porkbun.com": "198.51.100.1",
    "fortaleza.ns.porkbun.com": "198.51.100.2",
  };
  const fail = async (): Promise<never> => {
    throw Object.assign(new Error("unexpected lookup"), { code: "EUNEXPECTED" });
  };
  const resolver: DnsResolver = {
    resolveNs: async (host) => {
      if (host === "dodomaindemo.xyz") return STALE_VERCEL;
      throw Object.assign(new Error(NODATA), { code: NODATA });
    },
    resolve4: async (host) => [addresses[host] ?? "203.0.113.1"],
    resolve6: fail,
    resolveCname: async () => [],
    resolveMx: fail,
    resolveTxt: fail,
    resolveCaa: fail,
  };
  const traces: NsTrace[] = [];
  const authority = await resolveZoneAuthority("_dodomain-challenge.dodomaindemo.xyz", {
    resolver,
    parentNs: async () => CURRENT_PORKBUN,
    onNsTrace: (t) => traces.push(t),
  });
  assert.equal(authority.zone, "dodomaindemo.xyz");
  assert.deepEqual(pinnedServers(authority.authoritative), ["198.51.100.1", "198.51.100.2"]);
  assert.equal(traces[0]?.event, "dns.ns.recursive_stale");
});

test("an injected resolver without a parent seam keeps read-back on the recursive NS and opens no parent lookup", async () => {
  const resolver: DnsResolver = {
    resolveNs: async () => STALE_VERCEL,
    resolve4: async (host) => [host === "ns1.vercel-dns.com" ? "192.0.2.1" : "192.0.2.2"],
    resolve6: async () => [],
    resolveCname: async () => [],
    resolveMx: async () => [],
    resolveTxt: async () => [],
    resolveCaa: async () => [],
  };
  const authority = await resolveZoneAuthority("dodomaindemo.xyz", {
    resolver,
    onNsTrace: () => assert.fail("no parent view, so nothing to report"),
  });
  assert.deepEqual(pinnedServers(authority.authoritative), ["192.0.2.1", "192.0.2.2"]);
});
