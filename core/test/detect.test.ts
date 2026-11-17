// Characterization tests for the tier router (detect.ts). Every case drives the
// router purely through the injected DetectDeps seam — no DNS, no network — so the
// current NS → provider → tier mapping is pinned deterministically. These lock the
// behavior BEFORE any later refactor touches detect.ts (green-suite rule).

import { test } from "node:test";
import assert from "node:assert/strict";
import { Resolver } from "node:dns/promises";

import {
  detectProvider,
  detectionFromStoredLabel,
  dnsProviderForNameServers,
  type DetectDeps,
} from "../src/detect.ts";

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

test("an alias's recursive NS answer cannot select its target's provider or discovery zone", async () => {
  const discovered: string[] = [];
  const result = await detectProvider("www.delegated.example.com", {
    resolveNs: async (host) =>
      host === "www.delegated.example.com" ? ["ana.ns.cloudflare.com"] : ["ns01.domaincontrol.com"],
    resolveCname: async (host) => (host === "www.delegated.example.com" ? ["target.net"] : []),
    discover: async (zone) => {
      discovered.push(zone);
      return discoverReturning("godaddy", "GoDaddy")(zone);
    },
  });
  assert.equal(result.zone, "delegated.example.com");
  assert.equal(result.provider, "godaddy");
  assert.equal(result.tier, 2);
  assert.deepEqual(result.nameServers, ["ns01.domaincontrol.com"]);
  assert.deepEqual(discovered, ["delegated.example.com"]);
});

test("an inconclusive CNAME lookup keeps the cut, so detection still answers as it did before the alias check", async () => {
  const discovered: string[] = [];
  const result = await detectProvider("www.example.com", {
    resolveNs: nsReturning(["ana.ns.cloudflare.com"]),
    resolveCname: async () => {
      throw Object.assign(new Error("alias lookup failed"), { code: "ESERVFAIL" });
    },
    discover: async (zone) => {
      discovered.push(zone);
      return discoverReturning("godaddy", "GoDaddy")(zone);
    },
  });
  assert.equal(result.zone, "www.example.com");
  assert.deepEqual(discovered, ["www.example.com"]);
});

test("detect with injected NS and discovery but no CNAME never opens a DNS query", async (t) => {
  const realNs = t.mock.method(Resolver.prototype, "resolveNs", async () => {
    throw new Error("unexpected real NS query");
  });
  const realCname = t.mock.method(Resolver.prototype, "resolveCname", async () => {
    throw new Error("unexpected real CNAME query");
  });
  const result = await detectProvider("www.example.com", {
    resolveNs: nsReturning(["ana.ns.cloudflare.com"]),
    discover: discoverThrows,
  });
  assert.equal(result.zone, "www.example.com");
  assert.equal(result.provider, "cloudflare");
  assert.equal(realNs.mock.callCount(), 0);
  assert.equal(realCname.mock.callCount(), 0);
});

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

// Real Hostinger customer zones do not use hostinger-named NS: 0-360.info sits
// on ns1/ns2.dns-parking.com and the lapsed 0-5feet.com on
// ns1/ns2.dns-expired.com (both resolved live 2026-10-22); dns1.hostinger.com
// serves Hostinger's own zones (hostinger.au, .be, .ch). The fake
// ns1.hostinger.com this test used to pin matched no customer anywhere.
for (const ns of [
  ["ns1.dns-parking.com", "ns2.dns-parking.com"],
  ["ns1.dns-expired.com", "ns2.dns-expired.com"],
  ["dns1.hostinger.com", "dns2.hostinger.com"],
]) {
  test(`Hostinger NS ${ns[0]} → tier 3 guided`, async () => {
    const m = await detectProvider("x.example.com", {
      resolveNs: nsReturning(ns),
      discover: discoverThrows,
    });
    assert.equal(m.provider, "hostinger");
    assert.equal(m.tier, 3);
  });
}

// ns-cloud-*.googledomains.com is shared by Google Cloud DNS and the
// ex-Google-Domains zones Squarespace now runs. Zones resolved live 2026-10-22:
// 0-9.dev answers Squarespace's Domain Connect (providerId squarespace.com),
// kubernetes.io (a Cloud DNS zone) answers none.
const GOOGLE_NS = [
  "ns-cloud-a1.googledomains.com",
  "ns-cloud-a2.googledomains.com",
  "ns-cloud-a3.googledomains.com",
  "ns-cloud-a4.googledomains.com",
];

test("googledomains.com NS with Squarespace's Domain Connect → Squarespace", async () => {
  const m = await detectProvider("0-9.dev", {
    resolveNs: nsReturning(GOOGLE_NS),
    discover: discoverReturning("squarespace.com", "Squarespace"),
  });
  assert.equal(m.provider, "squarespace");
  assert.equal(m.label, "Squarespace");
  assert.equal(m.tier, 3, "Squarespace serves none of our templates: guided");
  assert.equal(m.confidence, "high");
});

test("googledomains.com NS without Domain Connect → Google Cloud DNS, not Squarespace", async () => {
  const m = await detectProvider("kubernetes.io", {
    resolveNs: nsReturning(GOOGLE_NS),
    discover: discoverThrows,
  });
  assert.equal(m.provider, "googleclouddns");
  assert.equal(m.label, "Google Cloud DNS");
  assert.equal(m.tier, 3);
});

test("googledomains.com NS with another provider's Domain Connect stays Google Cloud DNS", async () => {
  const m = await detectProvider("x.example.com", {
    resolveNs: nsReturning(GOOGLE_NS),
    discover: discoverReturning("acme-dns", "Acme DNS"),
  });
  assert.equal(m.provider, "googleclouddns");
});

test("the DNS-only answer for googledomains.com NS names both Google Cloud DNS and Squarespace", () => {
  // The public DNS tools make no Domain Connect request, so they cannot split
  // the shared ns-cloud-* set and must not pretend to.
  const hit = dnsProviderForNameServers(GOOGLE_NS.map((ns) => `${ns}.`));
  assert.equal(hit?.provider, "googleclouddns");
  assert.equal(hit?.label, "Google Cloud DNS or Squarespace");
  assert.equal(dnsProviderForNameServers(["ns1.dns-parking.com."])?.label, "Hostinger");
});

test("a wpengine-named NS no longer routes to the WordPress.com guide", async () => {
  // WP Engine runs no customer nameservers (ns1.wpengine.com hosts no zones,
  // shared-DNS lookup 2026-10-22); the old `\bwpengine` alternative claimed it.
  const wp = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["ns1.wpengine.com"]),
    discover: discoverThrows,
  });
  assert.equal(wp.provider, "unknown");
  const wpcom = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["ns1.wordpress.com", "ns2.wordpress.com"]),
    discover: discoverThrows,
  });
  assert.equal(wpcom.provider, "wordpress");
});

// T-6545 batch: each NS set is the one a real customer zone answered on
// 2026-10-22 (zone named per row), sampled from a shared-DNS lookup.
const NEW_GUIDED: Array<{ zone: string; ns: string[]; provider: string }> = [
  {
    zone: "0omph.org",
    ns: ["ns41.worldnic.com", "ns42.worldnic.com"],
    provider: "networksolutions",
  },
  {
    zone: "000y.de",
    ns: ["helium.ns.hetzner.de", "hydrogen.ns.hetzner.com", "oxygen.ns.hetzner.com"],
    provider: "hetzner",
  },
  {
    zone: "hetzner.com",
    ns: ["ns.second-ns.com", "ns1.your-server.de", "ns3.second-ns.de"],
    provider: "hetzner",
  },
  {
    zone: "hetzner.cloud",
    ns: ["ns1.first-ns.de", "robotns2.second-ns.de", "robotns3.second-ns.com"],
    provider: "hetzner",
  },
  { zone: "0-1-1.com", ns: ["ns1.dyna-ns.net", "ns2.dyna-ns.net"], provider: "dynadot" },
  {
    zone: "0-16.com",
    ns: ["launch1.spaceship.net", "launch2.spaceship.net"],
    provider: "spaceship",
  },
  {
    zone: "1000beats.ch",
    ns: [
      "ns1-01.azure-dns.com",
      "ns2-01.azure-dns.net",
      "ns3-01.azure-dns.org",
      "ns4-01.azure-dns.info",
    ],
    provider: "azure",
  },
  {
    zone: "0065.sg",
    ns: ["ns1.linode.com", "ns2.linode.com", "ns5.linode.com"],
    provider: "linode",
  },
  {
    zone: "0-oo-0.com",
    ns: ["dns1.name-services.com", "dns5.name-services.com"],
    provider: "enom",
  },
];

for (const row of NEW_GUIDED) {
  test(`${row.provider} NS (${row.zone}) → tier 3 guided`, async () => {
    const m = await detectProvider(row.zone, {
      resolveNs: nsReturning(row.ns),
      discover: discoverThrows,
    });
    assert.equal(m.provider, row.provider);
    assert.equal(m.tier, 3);
    assert.equal(m.confidence, "high");
  });
}

// Netlify DNS and NS1's own customers share dnsN.p0N.nsone.net (jamstack.org
// p01 is Netlify's, smashingmagazine.com p06 is plain NS1; 2026-10-23).
test("an NS1-only zone is named Netlify DNS / NS1 and takes the guided path", async () => {
  const m = await detectProvider("jamstack.org", {
    resolveNs: nsReturning([
      "dns1.p01.nsone.net",
      "dns2.p01.nsone.net",
      "dns3.p01.nsone.net",
      "dns4.p01.nsone.net",
    ]),
    discover: discoverThrows,
  });
  assert.equal(m.provider, "netlify");
  assert.equal(m.label, "Netlify DNS / NS1");
  assert.equal(m.tier, 3);
});

test("a zone pairing NS1 with Squarespace's or Azure's NS is named for that host, not NS1", async () => {
  const sq = await detectProvider("squarespace.com", {
    resolveNs: nsReturning(["dns1.p06.nsone.net", "ns01.squarespacedns.com"]),
    discover: discoverThrows,
  });
  assert.equal(sq.provider, "squarespace");
  const az = await detectProvider("linkedin.com", {
    resolveNs: nsReturning(["dns1.p09.nsone.net", "ns1-42.azure-dns.com"]),
    discover: discoverThrows,
  });
  assert.equal(az.provider, "azure");
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

test("OVH Canada NS (dnsNN.ovh.ca + nsNN.ovh.ca) → OVHcloud, tier 3 guided, never unknown", async () => {
  // Observed live 2026-11-03 on oc.mrneon.online, a free OVH Canada zone.
  const m = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["dns10.ovh.ca", "ns10.ovh.ca"]),
    discover: discoverThrows,
  });
  assert.equal(m.provider, "ovh");
  assert.equal(m.label, "OVHcloud");
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

test("Hover NS → tier 3 guided", async () => {
  const m = await detectProvider("x.example.com", {
    resolveNs: nsReturning(["ns1.hover.com", "ns2.hover.com"]),
    discover: discoverThrows,
  });
  assert.equal(m.provider, "hover");
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

// T-6553: the session row keeps only label + tier; detectionFromStoredLabel
// rebuilds the rest. Pinned as a ROUND TRIP through every detectProvider
// branch, so a change to either side that breaks the inverse fails here.
test("detectionFromStoredLabel rebuilds provider, method and confidence from the stored label + tier for every detection branch", async () => {
  const cases = [
    { ns: ["ada.ns.cloudflare.com"], discover: discoverThrows },
    { ns: ["ns01.domaincontrol.com"], discover: discoverThrows },
    { ns: ["dns1.registrar-servers.com"], discover: discoverThrows },
    { ns: ["ns1.as207960.net"], discover: discoverReturning("glauca.digital", "Glauca HexDNS") },
    { ns: ["ns1.as207960.net"], discover: discoverThrows },
  ];
  for (const c of cases) {
    const m = await detectProvider("x.example.com", {
      resolveNs: nsReturning(c.ns),
      discover: c.discover,
    });
    const rebuilt = detectionFromStoredLabel(m.label, m.tier);
    assert.deepEqual(
      {
        label: rebuilt.label,
        tier: rebuilt.tier,
        method: rebuilt.method,
        confidence: rebuilt.confidence,
      },
      { label: m.label, tier: m.tier, method: m.method, confidence: m.confidence },
      `round trip for ${c.ns.join(",")}`,
    );
    // The provider id survives for every nameserver match; a Domain
    // Connect-only id was never stored and honestly reads "unknown".
    assert.equal(rebuilt.provider, m.confidence === "high" ? m.provider : "unknown");
  }
});
