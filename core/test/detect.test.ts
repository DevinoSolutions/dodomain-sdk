// Characterization tests for the tier router (detect.ts). Every case drives the
// router purely through the injected DetectDeps seam — no DNS, no network — so the
// current NS → provider → tier mapping is pinned deterministically. These lock the
// behavior BEFORE any later refactor touches detect.ts (green-suite rule).

import { test } from "node:test";
import assert from "node:assert/strict";

import { detectProvider, type DetectDeps } from "../src/detect.ts";

// resolveNs fake returning a fixed NS set; optionally records the zone it was asked for.
function nsReturning(ns: string[], calls?: string[]): NonNullable<DetectDeps["resolveNs"]> {
  return async (zone: string) => {
    calls?.push(zone);
    return ns;
  };
}

// discover fake that resolves to a Domain Connect provider.
function discoverReturning(
  providerId: string,
  providerName: string,
): NonNullable<DetectDeps["discover"]> {
  return async (domain: string) => ({
    domain,
    providerHost: "dc.example",
    settings: {
      providerId,
      providerName,
      urlSyncUX: "https://sync.example",
      urlAPI: "https://api.example",
    },
  });
}

// discover fake that always throws (domain is not a Domain Connect provider).
const discoverThrows: NonNullable<DetectDeps["discover"]> = async () => {
  throw new Error("no _domainconnect record");
};

test("Cloudflare NS → tier 1 OAuth, high confidence", async () => {
  const m = await detectProvider("shop.example.com", {
    resolveNs: nsReturning(["ana.ns.cloudflare.com", "bob.ns.cloudflare.com"]),
    discover: discoverThrows,
  });
  assert.equal(m.provider, "cloudflare");
  assert.equal(m.method, "oauth");
  assert.equal(m.tier, 1);
  assert.equal(m.confidence, "high");
});

// Tier 1 means "we have a one-click connector for this provider", and the only
// connector that exists is Cloudflare's. DigitalOcean and DNSimple used to
// claim tier 1 on the strength of their APIs being OAuth-capable, which routed
// their users into the connect page's hardcoded-Cloudflare tier-1 branch and
// burned the session at Cloudflare's zone lookup. These three tests pin the
// honest routing: recognized provider, guided manual flow, no false promise.
test("DigitalOcean NS → tier 3 guided (recognized, but DoDomain has no DigitalOcean connector)", async () => {
  const m = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["ns1.digitalocean.com"]),
    discover: discoverThrows,
  });
  assert.equal(m.provider, "digitalocean");
  assert.equal(m.method, "guided");
  assert.equal(m.tier, 3);
});

test("DNSimple NS → tier 3 guided (recognized, but DoDomain has no DNSimple connector)", async () => {
  const m = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["ns1.dnsimple.com"]),
    discover: discoverThrows,
  });
  assert.equal(m.provider, "dnsimple");
  assert.equal(m.method, "guided");
  assert.equal(m.tier, 3);
});

test("Cloudflare is the ONLY provider mapping that may claim tier 1 (the one shipped connector)", async () => {
  for (const ns of [
    "ns1.digitalocean.com",
    "ns1.dnsimple.com",
    "ns2.dnsimple-edge.net",
    "ns01.domaincontrol.com",
    "ns1.dnsowl.com",
    "dns1.registrar-servers.com",
    "ns-1.awsdns-01.org",
  ]) {
    const m = await detectProvider("x.example.com", {
      resolveNs: nsReturning([ns]),
      discover: discoverThrows,
    });
    assert.notEqual(m.tier, 1, `${ns} must not route to the Cloudflare-only tier-1 branch`);
    assert.notEqual(m.method, "oauth", `${ns} must not claim an OAuth connector`);
  }
});

test("GoDaddy NS → tier 2 Domain Connect", async () => {
  const m = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["ns01.domaincontrol.com"]),
    discover: discoverThrows,
  });
  assert.equal(m.provider, "godaddy");
  assert.equal(m.method, "domain-connect");
  assert.equal(m.tier, 2);
});

test("IONOS NS → tier 2 Domain Connect", async () => {
  const m = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["ns1071.ui-dns.com"]),
    discover: discoverThrows,
  });
  assert.equal(m.provider, "ionos");
  assert.equal(m.tier, 2);
});

test("Vercel NS → tier 2 Domain Connect", async () => {
  const m = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["ns1.vercel-dns.com"]),
    discover: discoverThrows,
  });
  assert.equal(m.provider, "vercel");
  assert.equal(m.tier, 2);
});

test("Namecheap NS → tier 3 guided", async () => {
  const m = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["dns1.registrar-servers.com"]),
    discover: discoverThrows,
  });
  assert.equal(m.provider, "namecheap");
  assert.equal(m.method, "guided");
  assert.equal(m.tier, 3);
});

test("Route 53 NS → tier 3 guided", async () => {
  const m = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["ns-1.awsdns-01.org"]),
    discover: discoverThrows,
  });
  assert.equal(m.provider, "route53");
  assert.equal(m.tier, 3);
});

test("Squarespace NS → tier 3 guided", async () => {
  const m = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["ns1.squarespacedns.com"]),
    discover: discoverThrows,
  });
  assert.equal(m.provider, "squarespace");
  assert.equal(m.tier, 3);
});

test("Hostinger NS → tier 3 guided", async () => {
  const m = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["ns1.hostinger.com"]),
    discover: discoverThrows,
  });
  assert.equal(m.provider, "hostinger");
  assert.equal(m.tier, 3);
});

test("Cloudflare NS wins over a successful Domain Connect discovery (NS precedence)", async () => {
  const m = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["ana.ns.cloudflare.com"]),
    // DC discovery succeeds and says GoDaddy, but the NS match (Cloudflare/tier 1) wins.
    discover: discoverReturning("godaddy", "GoDaddy"),
  });
  assert.equal(m.provider, "cloudflare");
  assert.equal(m.tier, 1);
  // The DC signal is still attached to the result for downstream use.
  assert.deepEqual(m.domainConnect, { providerId: "godaddy", providerName: "GoDaddy" });
});

test("no NS match + Domain Connect resolves → tier 2, medium confidence, from DC", async () => {
  const m = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["ns1.some-unknown-registrar.net"]),
    discover: discoverReturning("acme-dns", "Acme DNS"),
  });
  assert.equal(m.provider, "acme-dns");
  assert.equal(m.label, "Acme DNS");
  assert.equal(m.method, "domain-connect");
  assert.equal(m.tier, 2);
  assert.equal(m.confidence, "medium");
});

test("no NS match + Domain Connect fails → unknown, tier 3, low confidence", async () => {
  const m = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["ns1.some-unknown-registrar.net"]),
    discover: discoverThrows,
  });
  assert.equal(m.provider, "unknown");
  assert.equal(m.method, "guided");
  assert.equal(m.tier, 3);
  assert.equal(m.confidence, "low");
});

test("NS lookup failure is swallowed to [] → falls back to unknown when DC also fails", async () => {
  const m = await detectProvider("x.example.com", {
    resolveNs: async () => {
      throw new Error("ENOTFOUND");
    },
    discover: discoverThrows,
  });
  assert.equal(m.provider, "unknown");
  assert.equal(m.tier, 3);
  assert.deepEqual(m.nameServers, []);
});

// Zone resolution. These pinned "resolveNs is queried for the registrable apex,
// not the full host" when detection was apex-only. Detection now walks for the
// nearest DELEGATION CUT and settles on the apex when nothing below it is
// delegated, so what they pin is restated as: with no subzone delegated (the
// stub answers NS for nothing), detection settles on the registrable apex and
// never queries the public suffix above it. The F-011 property — a multi-label
// public suffix must never be mistaken for the customer's zone — is unchanged
// and is now asserted directly on the settled zone.

test("no delegated subzone: detection settles on the registrable apex, and never queries above it", async () => {
  const calls: string[] = [];
  const m = await detectProvider("a.b.example.com", {
    resolveNs: nsReturning([], calls),
    discover: discoverThrows,
  });
  assert.equal(m.zone, "example.com");
  assert.equal(calls.at(-1), "example.com", "the apex is the last name queried");
  assert.ok(!calls.includes("com"), "the public suffix is never a zone candidate");
});

// F-011: detect.ts's own private apexOf (the naive last-two-labels guess) was
// replaced by the shared PSL-backed packages/core/src/apex.ts, which is still
// the FLOOR of the zone walk — these cases cover the multi-label public
// suffixes the naive guess mis-zoned.

test("F-011: a .co.uk customer domain settles on the registrable domain, never the registry zone", async () => {
  const calls: string[] = [];
  const m = await detectProvider("status.customer.co.uk", {
    resolveNs: nsReturning([], calls),
    discover: discoverThrows,
  });
  assert.equal(m.zone, "customer.co.uk");
  assert.ok(!calls.includes("co.uk"), "co.uk is the REGISTRY's zone, never a customer's");
});

test("F-011: a .com.au customer domain settles on the registrable domain, never the registry zone", async () => {
  const calls: string[] = [];
  const m = await detectProvider("shop.example.com.au", {
    resolveNs: nsReturning([], calls),
    discover: discoverThrows,
  });
  assert.equal(m.zone, "example.com.au");
  assert.ok(!calls.includes("com.au"));
});

// ── tier routing on the OWNING zone (delegated subzones) ───────────────────
//
// Live shape probed 2026-08-06 via 1.1.1.1: mrneon.online sits on Cloudflare
// nameservers, while dc.mrneon.online is delegated to ns1..ns4.as207960.net
// (Glauca Digital), which serves both of our Domain Connect templates.
// Cloudflare cannot write a record in a zone it does not host, so routing a
// host under that subzone to the Cloudflare OAuth flow is WRONG, not merely
// suboptimal.

const MRNEON_NS: Record<string, string[]> = {
  "dc.mrneon.online": ["ns1.as207960.net", "ns2.as207960.net"],
  "mrneon.online": ["doug.ns.cloudflare.com", "riya.ns.cloudflare.com"],
};

function mrneonNs(calls?: string[]): NonNullable<DetectDeps["resolveNs"]> {
  return async (name: string) => {
    calls?.push(name);
    const ns = MRNEON_NS[name];
    if (!ns) throw new Error(`ENODATA ${name}`);
    return ns;
  };
}

test("a host under a delegated subzone routes on THAT zone's NS, not the Cloudflare apex's", async () => {
  const discovered: string[] = [];
  const m = await detectProvider("status.dc.mrneon.online", {
    resolveNs: mrneonNs(),
    discover: async (zone: string) => {
      discovered.push(zone);
      return discoverReturning("glauca", "Glauca Digital")(zone);
    },
  });

  assert.equal(m.zone, "dc.mrneon.online", "the delegated zone owns the records");
  assert.deepEqual(m.nameServers, ["ns1.as207960.net", "ns2.as207960.net"]);
  assert.deepEqual(discovered, ["dc.mrneon.online"], "discovery runs on the owning zone only");
  assert.equal(m.tier, 2);
  assert.equal(m.method, "domain-connect");
  assert.equal(m.provider, "glauca");
  assert.notEqual(m.provider, "cloudflare");
});

test("a tier-2 match carries the discovered settings so callers need not re-fetch them", async () => {
  // The readiness probe in apps/web reuses this instead of repeating the
  // TXT + settings chain — measured at 987ms against Glauca, which is what
  // pushed the probe past its budget and hid the one-click CTA (E2E 2026-08-06).
  const m = await detectProvider("status.dc.mrneon.online", {
    resolveNs: mrneonNs(),
    discover: discoverReturning("glauca", "Glauca Digital"),
  });

  assert.equal(m.tier, 2);
  assert.equal(m.domainConnectSettings?.urlAPI, "https://api.example");
  assert.equal(m.domainConnectSettings?.urlSyncUX, "https://sync.example");
  // The wire-facing summary keeps its exact shape — this field is extra, not a
  // replacement (schemas.ts zDetectSessionResponse pins `domainConnect`).
  assert.deepEqual(m.domainConnect, { providerId: "glauca", providerName: "Glauca Digital" });
});

test("a match with no Domain Connect discovery carries no settings to reuse", async () => {
  const m = await detectProvider("status.dc.mrneon.online", {
    resolveNs: mrneonNs(),
    discover: discoverThrows,
  });
  assert.equal(m.domainConnectSettings, undefined);
});

test("the apex's own NS still decide when nothing below the apex is delegated", async () => {
  const calls: string[] = [];
  const m = await detectProvider("www.mrneon.online", {
    resolveNs: mrneonNs(calls),
    discover: discoverThrows,
  });

  assert.equal(m.zone, "mrneon.online");
  assert.equal(m.provider, "cloudflare");
  assert.equal(m.tier, 1);
  assert.deepEqual(calls, ["www.mrneon.online", "mrneon.online"]);
});

test("a session ON the delegated zone apex resolves to that zone itself", async () => {
  const m = await detectProvider("dc.mrneon.online", {
    resolveNs: mrneonNs(),
    discover: discoverReturning("glauca", "Glauca Digital"),
  });
  assert.equal(m.zone, "dc.mrneon.online");
  assert.equal(m.tier, 2);
});

test("a delegated subzone with an unknown provider and no DC falls to tier 3 — never to the apex's provider", async () => {
  // The apex is Cloudflare, but Cloudflare does not host dc.mrneon.online, so
  // borrowing its tier-1 OAuth path would dead-end. Guided manual is correct.
  const m = await detectProvider("status.dc.mrneon.online", {
    resolveNs: mrneonNs(),
    discover: discoverThrows,
  });
  assert.equal(m.zone, "dc.mrneon.online");
  assert.equal(m.provider, "unknown");
  assert.equal(m.tier, 3);
  assert.equal(m.method, "guided");
});

// —— Entri-manual-parity batch (2026-07): pin each NS suffix added in this
// pass, same style as the cases above. Appended rows must not change any
// mapping pinned earlier in this file.

test("Wix NS (wixdns.net) → tier 3 guided", async () => {
  const m = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["ns0.wixdns.net", "ns1.wixdns.net"]),
    discover: discoverThrows,
  });
  assert.equal(m.provider, "wix");
  assert.equal(m.method, "guided");
  assert.equal(m.tier, 3);
});

test("Porkbun NS → tier 3 guided", async () => {
  const m = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["curitiba.ns.porkbun.com", "fortaleza.ns.porkbun.com"]),
    discover: discoverThrows,
  });
  assert.equal(m.provider, "porkbun");
  assert.equal(m.tier, 3);
});

test("Name.com NS (incl. hashed variants) → tier 3 guided", async () => {
  const m = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["ns1.name.com", "ns2.name.com"]),
    discover: discoverThrows,
  });
  assert.equal(m.provider, "namecom");
  assert.equal(m.tier, 3);
  const hashed = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["ns2nsy.name.com"]),
    discover: discoverThrows,
  });
  assert.equal(hashed.provider, "namecom");
});

test("OVH NS → tier 3 guided", async () => {
  const m = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["dns10.ovh.net", "ns10.ovh.net"]),
    discover: discoverThrows,
  });
  assert.equal(m.provider, "ovh");
  assert.equal(m.tier, 3);
});

test("Gandi LiveDNS NS → tier 3 guided", async () => {
  const m = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["ns-154-a.gandi.net", "ns-232-b.gandi.net"]),
    discover: discoverThrows,
  });
  assert.equal(m.provider, "gandi");
  assert.equal(m.tier, 3);
});

test("one.com NS → tier 3 guided", async () => {
  const m = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["ns01.one.com", "ns02.one.com"]),
    discover: discoverThrows,
  });
  assert.equal(m.provider, "onecom");
  assert.equal(m.tier, 3);
});

test("STRATO NS (rzone.de) → tier 3 guided", async () => {
  const m = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["docks14.rzone.de", "shades09.rzone.de"]),
    discover: discoverThrows,
  });
  assert.equal(m.provider, "strato");
  assert.equal(m.tier, 3);
});

test("Bluehost NS → tier 3 guided", async () => {
  const m = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["ns1.bluehost.com", "ns2.bluehost.com"]),
    discover: discoverThrows,
  });
  assert.equal(m.provider, "bluehost");
  assert.equal(m.tier, 3);
});

test("HostGator NS (per-server nsNNNN) → tier 3 guided", async () => {
  const m = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["ns1234.hostgator.com"]),
    discover: discoverThrows,
  });
  assert.equal(m.provider, "hostgator");
  assert.equal(m.tier, 3);
});

test("DreamHost NS → tier 3 guided", async () => {
  const m = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["ns1.dreamhost.com", "ns2.dreamhost.com"]),
    discover: discoverThrows,
  });
  assert.equal(m.provider, "dreamhost");
  assert.equal(m.tier, 3);
});

test("NameSilo default NS (dnsowl.com) → tier 2 Domain Connect, provider namesilo", async () => {
  const m = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["ns1.dnsowl.com", "ns2.dnsowl.com"]),
    discover: discoverThrows,
  });
  assert.equal(m.provider, "namesilo");
  assert.equal(m.method, "domain-connect");
  assert.equal(m.tier, 2);
});

test("DNSimple edge NS (dnsimple-edge.*) → provider dnsimple, guided — same routing as dnsimple.com", async () => {
  const m = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["ns2.dnsimple-edge.net", "ns3.dnsimple-edge.io"]),
    discover: discoverThrows,
  });
  assert.equal(m.provider, "dnsimple");
  assert.equal(m.method, "guided");
  assert.equal(m.tier, 3);
});

test("dot-anchoring: hostnames merely ending in name.com / one.com stay unknown", async () => {
  const m = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["ns1.myname.com", "ns1.someone.com"]),
    discover: discoverThrows,
  });
  assert.equal(m.provider, "unknown");
  assert.equal(m.tier, 3);
});
