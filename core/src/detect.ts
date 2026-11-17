// Provider detection: which DNS provider hosts a domain, and therefore which
// tier DoDomain can use. Combines authoritative NS lookup + NS-pattern mapping
// + Domain Connect discovery (PLAN §2.5/§5). Returns a confidence + suggested tier.
//
// Everything here keys off the zone that will OWN the records — the nearest
// delegation cut at or below the queried host, floored at the registrable apex
// (zone-walk.ts). Routing on the apex instead is wrong, not merely imprecise:
// for a host under a subzone delegated away from the apex's provider, that
// provider cannot write the record at all, so "tier 1, use its OAuth flow"
// sends the user down a path that cannot succeed.

import { discover, type DiscoveryResult } from "./discovery.ts";
import type { DomainConnectProviderSettings } from "./domain-connect-types.ts";
import { nearestZoneCut, type ZoneWalkDeps } from "./zone-walk.ts";

export type Tier = 1 | 2 | 3;

export interface ProviderMatch {
  /** canonical provider id, e.g. "cloudflare" */
  provider: string;
  /** human label, e.g. "Cloudflare" */
  label: string;
  /** 1 = OAuth (Cloudflare), 2 = Domain Connect, 3 = guided manual */
  tier: Tier;
  method: "oauth" | "domain-connect" | "guided";
  confidence: "high" | "medium" | "low";
  /**
   * The zone that OWNS records at the queried host: the nearest delegation cut,
   * or the registrable apex when nothing below it is delegated (the common
   * case). Every field above was decided against THIS zone, and it is also the
   * zone the user must open at their provider — provider DNS dashboards are
   * per zone, so this is what the guide and the connect UI display.
   */
  zone: string;
  /** The owning zone's nameservers (lowercased); `[]` when the lookup failed. */
  nameServers: string[];
  /** present when Domain Connect discovery succeeded */
  domainConnect?: { providerId: string; providerName: string };
  /**
   * The full settings JSON behind `domainConnect`, so a caller that needs the
   * provider's endpoints does not re-run the TXT + settings chain detection
   * just paid for (987 ms measured against Glauca on 2026-08-06 — two thirds of
   * the readiness probe's entire budget, and the reason the one-click CTA kept
   * failing to render on a provider that serves both templates).
   *
   * Deliberately NOT part of any wire response: the detect/check API exposes
   * `domainConnect` only (zDetectSessionResponse in schemas.ts), and widening
   * that would be a contract change for integrators. This field is internal
   * plumbing between detection and the readiness probe.
   */
  domainConnectSettings?: DomainConnectProviderSettings;
}

interface NsProvider {
  provider: string;
  label: string;
  method: ProviderMatch["method"];
}

// NS suffix → provider. Ordered; first match wins.
const NS_MAP: Array<
  NsProvider & {
    re: RegExp;
    /**
     * For a nameserver set two providers share: the Domain Connect providerId
     * discovery returns for the zone picks the provider instead of the row's
     * default. Keyed by `settings.providerId`.
     */
    byDomainConnect?: Record<string, NsProvider>;
    /**
     * Label for a DNS-only answer (`dnsProviderForNameServers`, no Domain
     * Connect lookup) when the NS set alone is ambiguous.
     */
    nsOnlyLabel?: string;
  }
> = [
  { re: /\bcloudflare\.com$/i, provider: "cloudflare", label: "Cloudflare", method: "oauth" },
  { re: /\bdomaincontrol\.com$/i, provider: "godaddy", label: "GoDaddy", method: "domain-connect" },
  {
    re: /(\bui-dns\.|\bionos|1and1|\bui-dns\b)/i,
    provider: "ionos",
    label: "IONOS",
    method: "domain-connect",
  },
  { re: /\bvercel-dns\.com$/i, provider: "vercel", label: "Vercel", method: "domain-connect" },
  // WordPress.com only. WP Engine is a different host and runs no customer
  // nameservers: ns1.wpengine.com and ns1.wpenginepowered.com host no zones
  // (shared-DNS lookup, 2026-10-22) and wpengine.com itself sits on
  // Cloudflare, so a WP Engine site's records live wherever its NS point. The
  // old `\bwpengine` alternative sent any such NS to the WordPress.com guide.
  {
    re: /\bwordpress\.com$/i,
    provider: "wordpress",
    label: "WordPress.com",
    method: "domain-connect",
  },
  { re: /\bnamesilo/i, provider: "namesilo", label: "NameSilo", method: "domain-connect" },
  {
    re: /\bregistrar-servers\.com$|\bnamecheap/i,
    provider: "namecheap",
    label: "Namecheap",
    method: "guided",
  },
  {
    re: /\bawsdns-|\bamazonaws\.com$/i,
    provider: "route53",
    label: "AWS Route 53",
    method: "guided",
  },
  // Squarespace's own NS are ns0N.squarespacedns.com (paired with NS1's
  // dnsN.p0N.nsone.net; this row precedes the NS1 row at the end, so it wins).
  { re: /\bsquarespace/i, provider: "squarespace", label: "Squarespace", method: "guided" },
  // ns-cloud-[a-e][1-4].googledomains.com is Google Cloud DNS AND the set
  // ex-Google-Domains zones kept when Squarespace took them over — the same
  // names, so NS alone cannot tell them apart. Squarespace publishes
  // `_domainconnect` on those zones (providerId squarespace.com: 8 of 10
  // sampled 2026-10-19; 0-9.dev and 0-cve.com re-checked 2026-10-22); Cloud
  // DNS publishes nothing (kubernetes.io, tensorflow.org, 2026-10-22). The
  // Cloud DNS guide points ex-Google-Domains owners whose zone dropped the TXT
  // at Squarespace.
  {
    re: /\.googledomains\.com$/i,
    provider: "googleclouddns",
    label: "Google Cloud DNS",
    method: "guided",
    nsOnlyLabel: "Google Cloud DNS or Squarespace",
    byDomainConnect: {
      "squarespace.com": { provider: "squarespace", label: "Squarespace", method: "guided" },
    },
  },
  // Hostinger's customer zones sit on ns1/ns2.dns-parking.com, and on
  // ns1/ns2.dns-expired.com once the domain lapses (those NS addresses are in
  // Hostinger's AS47583) — probed 2026-10-22. dns1/dns2.hostinger.com serve
  // only Hostinger's own zones (hostinger.au, .be, .ch), kept regardless.
  {
    re: /(?:^|\.)(?:hostinger\.com|dns-parking\.com|dns-expired\.com)$/i,
    provider: "hostinger",
    label: "Hostinger",
    method: "guided",
  },
  // Own-API integrations are deployment settings: DigitalOcean stays guided
  // here and web's own-api-one-click table layers on its configured offer.
  // DNSimple has no connector and keeps the guided fallback.
  {
    re: /^ns[123]\.digitalocean\.com$/i,
    provider: "digitalocean",
    label: "DigitalOcean",
    method: "guided",
  },
  { re: /\bdnsimple\.com$/i, provider: "dnsimple", label: "DNSimple", method: "guided" },
  // —— Entri-manual-parity batch (2026-07). Appended so no row above can be
  // shadowed (first match wins); existing mappings unchanged. Suffixes verified
  // against provider docs / live NS lookups. All guided (tier 3) except
  // dnsowl.com, which is NameSilo's default customer-NS brand (Domain
  // Connect-capable, tier 2, same routing as the namesilo row above).
  // dnsimple-edge.* is DNSimple's newer edge NS set and tracks the
  // dnsimple.com row above — guided, for the same no-connector reason.
  { re: /\bdnsowl\.com$/i, provider: "namesilo", label: "NameSilo", method: "domain-connect" },
  {
    re: /\bdnsimple-edge\.(?:com|net|io|org)$/i,
    provider: "dnsimple",
    label: "DNSimple",
    method: "guided",
  },
  { re: /\bwixdns\.net$/i, provider: "wix", label: "Wix", method: "guided" },
  { re: /\bporkbun\.com$/i, provider: "porkbun", label: "Porkbun", method: "guided" },
  // Dot-anchored: "name.com"/"one.com" also occur merely as the tail of longer
  // hostnames (myname.com, someone.com); requiring the leading dot pins these
  // to true subdomains of the provider's own zone (ns1.name.com, ns01.one.com).
  { re: /\.name\.com$/i, provider: "namecom", label: "Name.com", method: "guided" },
  { re: /\.one\.com$/i, provider: "onecom", label: "one.com", method: "guided" },
  // OVH Europe zones sit on dnsNN.ovh.net + nsNN.ovh.net, OVH Canada zones on
  // dnsNN.ovh.ca + nsNN.ovh.ca (oc.mrneon.online, resolved live 2026-11-03).
  { re: /\bovh\.(?:net|ca)$/i, provider: "ovh", label: "OVHcloud", method: "guided" },
  { re: /\bgandi\.net$/i, provider: "gandi", label: "Gandi", method: "guided" },
  { re: /\brzone\.de$/i, provider: "strato", label: "STRATO", method: "guided" },
  { re: /\bbluehost\.com$/i, provider: "bluehost", label: "Bluehost", method: "guided" },
  { re: /\bhostgator\.com$/i, provider: "hostgator", label: "HostGator", method: "guided" },
  { re: /\bdreamhost\.com$/i, provider: "dreamhost", label: "DreamHost", method: "guided" },
  // Stage 9 WS-G (2026-09-05): Hover's customer NS are ns1/ns2.hover.com;
  // guided, with its own guides.ts entry. No API, no Domain Connect.
  { re: /\bhover\.com$/i, provider: "hover", label: "Hover", method: "guided" },
  // —— T-6545 batch (2026-10-22). Every suffix below was checked against real
  // customer zones (sampled from a shared-DNS lookup, NS re-resolved live that
  // day; detect.test.ts names them). All guided. Network Solutions, Dynadot
  // and eNom use the dedicated guides T-5809 added under the same keys; the
  // rest show the generic steps under the right provider name.
  {
    re: /\bworldnic\.com$/i,
    provider: "networksolutions",
    label: "Network Solutions",
    method: "guided",
  },
  // Hetzner has two DNS consoles: DNS Console zones sit on
  // {helium,hydrogen,oxygen}.ns.hetzner.{de,com} (000y.de); Robot/konsoleH
  // zones on ns1.your-server.de + ns.second-ns.com + ns3.second-ns.de
  // (hetzner.com, hetzner.de) or ns1.first-ns.de + robotns2.second-ns.de +
  // robotns3.second-ns.com (hetzner.cloud). All resolved live 2026-10-23.
  {
    re: /\.ns\.hetzner\.(?:com|de)$|\byour-server\.de$|\b(?:first|second)-ns\.(?:com|de)$/i,
    provider: "hetzner",
    label: "Hetzner",
    method: "guided",
  },
  { re: /\bdyna-ns\.net$/i, provider: "dynadot", label: "Dynadot", method: "guided" },
  {
    re: /\blaunch\d+\.spaceship\.(?:net|com)$/i,
    provider: "spaceship",
    label: "Spaceship",
    method: "guided",
  },
  {
    re: /\.azure-dns\.(?:com|net|org|info)$/i,
    provider: "azure",
    label: "Azure DNS",
    method: "guided",
  },
  { re: /\bns\d+\.linode\.com$/i, provider: "linode", label: "Linode (Akamai)", method: "guided" },
  // eNom's default nameservers (registrar-servers.com is Namecheap's, above).
  { re: /\bname-services\.com$/i, provider: "enom", label: "eNom", method: "guided" },
  // Netlify DNS zones sit on dnsN.p0N.nsone.net (jamstack.org p01, 11ty.dev
  // p03; SOA hostmaster domains+netlify.netlify.com), the same names NS1's own
  // managed-DNS customers get (smashingmagazine.com p06, SOA
  // hostmaster.nsone.net), resolved live 2026-10-23. NS alone cannot split
  // them, so the label names both. LAST on purpose: a zone that pairs NS1 with
  // another host's NS (squarespace.com + squarespacedns.com, linkedin.com +
  // azure-dns) matches that host's row first. netlifydns.com serves only
  // Netlify's own zones.
  {
    re: /\bdns\d+\.p\d+\.nsone\.net$/i,
    provider: "netlify",
    label: "Netlify DNS / NS1",
    method: "guided",
  },
];

// `"domain-connect": 2` routes the NS_MAP rows above with
// method:"domain-connect" (GoDaddy, IONOS, Vercel, WordPress.com, NameSilo)
// to tier 2. The tier-2 APPLY path is wired in apps/web behind
// DODOMAIN_DOMAIN_CONNECT_ENABLED (2026-07-11 build — the
// /domain-connect/{start,callback} routes drive recipes.ts + applyUrl.ts);
// the connect page shows the one-click CTA only when the detect route's
// fail-closed domainConnectReady probe also confirms the provider onboarded
// our template — until then tier 2 still renders the manual-records fallback.
// This routing is pinned by packages/core/test/detect.test.ts
// (GoDaddy/IONOS/Vercel → tier 2) and must not change here. See README
// "Status & limitations".
const TIER_BY_METHOD: Record<ProviderMatch["method"], Tier> = {
  oauth: 1,
  "domain-connect": 2,
  guided: 3,
};

/**
 * Optional dependency-injection seam, mirroring `DiscoveryDeps` in discovery.ts:
 * the two network-touching calls — authoritative NS lookup and Domain Connect
 * discovery — default to the real implementations and can be overridden so the
 * tier router is exercised deterministically without DNS/network in tests.
 */
export interface DetectDeps {
  resolveNs?: (hostname: string) => Promise<string[]>;
  resolveCname?: (hostname: string) => Promise<string[]>;
  /** The owning zone's NS as its parent delegates them (zone-walk.ts
   * zoneNameServers decides between this and resolveNs; T-10301). */
  parentNs?: ZoneWalkDeps["parentNs"];
  onNsTrace?: ZoneWalkDeps["onNsTrace"];
  discover?: (domain: string) => Promise<DiscoveryResult>;
}

/** DNS-only provider identification for public diagnostics. Reuses the same
 * NS mapping as full detection without making Domain Connect HTTP requests. */
export function dnsProviderForNameServers(
  nameServers: string[],
): Pick<ProviderMatch, "provider" | "label" | "method"> | null {
  const hit = nsRowFor(nameServers);
  return hit
    ? { provider: hit.provider, label: hit.nsOnlyLabel ?? hit.label, method: hit.method }
    : null;
}

/** The first NS_MAP row any of the zone's nameservers matches (trailing dot ignored). */
function nsRowFor(nameServers: string[]): (typeof NS_MAP)[number] | undefined {
  return NS_MAP.find((m) => nameServers.some((ns) => m.re.test(ns.replace(/\.$/, ""))));
}

/** TIER_BY_METHOD inverted: the method each tier is routed from. */
const METHOD_BY_TIER: Record<Tier, ProviderMatch["method"]> = {
  1: "oauth",
  2: "domain-connect",
  3: "guided",
};

/**
 * The provider fields of a PAST detection, rebuilt from the only two the
 * session row keeps: `ProviderMatch.label` and `ProviderMatch.tier` (the
 * canonical provider id is deliberately not stored — schema.prisma's
 * `detectedDnsProviderLabel`). The inverse of detectProvider's three branches:
 *
 *   - a label naming an NS_MAP row that routes to the same tier came from the
 *     nameserver match: that row's id and method, confidence "high";
 *   - any other tier-2 label came from Domain Connect discovery alone
 *     (confidence "medium"). Its id was the discovered DC providerId, which
 *     was never persisted, so it reads "unknown" — the honest answer, and the
 *     one publicGuideFor already maps to the generic guide, exactly as it does
 *     for every discovered providerId without a dedicated guide;
 *   - anything else is the unknown fallback, confidence "low".
 *
 * Used where a fresh detection must not be allowed to overwrite a stored one
 * (apps/web lib/session-redetection.ts) and the response still has to describe
 * the stored detection.
 */
export function detectionFromStoredLabel(
  label: string,
  tier: Tier,
): Pick<ProviderMatch, "provider" | "label" | "tier" | "method" | "confidence"> {
  const row = NS_MAP.find((m) => m.label === label && TIER_BY_METHOD[m.method] === tier);
  if (row) return { provider: row.provider, label, tier, method: row.method, confidence: "high" };
  return {
    provider: "unknown",
    label,
    tier,
    method: METHOD_BY_TIER[tier],
    confidence: tier === 2 ? "medium" : "low",
  };
}

export async function detectProvider(
  domain: string,
  deps: DetectDeps = {},
): Promise<ProviderMatch> {
  const discoverFn = deps.discover ?? discover;
  // ONE walk decides everything: the zone that owns the records, and its NS —
  // the parent's delegation when it can be read, so a customer who just moved
  // nameservers is not shown the provider a stale resolver still caches.
  // `nameServers` is [] when the lookup fails, exactly as the previous
  // apex-only lookup's catch produced.
  const { zone, nameServers } = await nearestZoneCut(domain, {
    ...(deps.resolveNs ? { resolveNs: deps.resolveNs } : {}),
    ...(deps.resolveCname ? { resolveCname: deps.resolveCname } : {}),
    ...(deps.parentNs ? { parentNs: deps.parentNs } : {}),
    ...(deps.onNsTrace ? { onNsTrace: deps.onNsTrace } : {}),
  });

  // Domain Connect discovery runs in parallel-ish; it's the strongest Tier-2
  // signal. It runs against the OWNING zone — the walk already found it, and
  // a parent zone's Domain Connect endpoint cannot apply records here.
  let dc: ProviderMatch["domainConnect"];
  let dcSettings: DomainConnectProviderSettings | undefined;
  try {
    const res = await discoverFn(zone);
    if (res?.settings?.providerId) {
      dc = { providerId: res.settings.providerId, providerName: res.settings.providerName };
      dcSettings = res.settings;
    }
  } catch {
    /* not a DC provider, or no _domainconnect record */
  }

  const row = nsRowFor(nameServers);
  const hit = (dc && row?.byDomainConnect?.[dc.providerId]) ?? row;

  if (hit) {
    // If NS says Cloudflare — the one provider DoDomain has an OAuth connector
    // for, and therefore the only `method:"oauth"` row left — that wins (Tier 1)
    // even over DC.
    return {
      provider: hit.provider,
      label: hit.label,
      method: hit.method,
      tier: TIER_BY_METHOD[hit.method],
      confidence: "high",
      zone,
      nameServers,
      domainConnect: dc,
      domainConnectSettings: dcSettings,
    };
  }

  // No NS match but Domain Connect discovery worked → Tier 2 by DC.
  if (dc) {
    return {
      provider: dc.providerId,
      label: dc.providerName,
      method: "domain-connect",
      tier: 2,
      confidence: "medium",
      zone,
      nameServers,
      domainConnect: dc,
      domainConnectSettings: dcSettings,
    };
  }

  // Unknown → guided manual (universal fallback).
  return {
    provider: "unknown",
    label: "your DNS provider",
    method: "guided",
    tier: 3,
    confidence: "low",
    zone,
    nameServers,
  };
}
