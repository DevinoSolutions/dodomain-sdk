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
import type { DcSettings } from "./types.ts";
import { nearestZoneCut } from "./zone-walk.ts";

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
  domainConnectSettings?: DcSettings;
}

// NS suffix → provider. Ordered; first match wins.
const NS_MAP: Array<{
  re: RegExp;
  provider: string;
  label: string;
  method: ProviderMatch["method"];
}> = [
  { re: /\bcloudflare\.com$/i, provider: "cloudflare", label: "Cloudflare", method: "oauth" },
  { re: /\bdomaincontrol\.com$/i, provider: "godaddy", label: "GoDaddy", method: "domain-connect" },
  {
    re: /(\bui-dns\.|\bionos|1and1|\bui-dns\b)/i,
    provider: "ionos",
    label: "IONOS",
    method: "domain-connect",
  },
  { re: /\bvercel-dns\.com$/i, provider: "vercel", label: "Vercel", method: "domain-connect" },
  {
    re: /\bwordpress\.com$|\bwpengine/i,
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
  {
    re: /\bsquarespace|\bgoogledomains\.com$/i,
    provider: "squarespace",
    label: "Squarespace",
    method: "guided",
  },
  {
    re: /\bhostinger|\bhostinger\.com$/i,
    provider: "hostinger",
    label: "Hostinger",
    method: "guided",
  },
  // DigitalOcean and DNSimple both publish an OAuth-capable DNS API, but
  // DoDomain has NO connector behind either one: `method:"oauth"` here used to
  // route them to tier 1, and the connect page's tier-1 branch is hardcoded
  // Cloudflare (apps/web/src/app/connect/[token]/connect-flow.tsx) — so a
  // DigitalOcean-hosted domain was offered "One-click connect with Cloudflare",
  // sent to Cloudflare's consent screen, and died at resolveZoneId with the
  // session marked failed and a false `connection.failed` webhook fired at the
  // integrator. Routing them `guided` is the honest answer: both keep their
  // provider guides (guides.ts) and the manual records+verify path, which is
  // the flow that actually works for them today.
  // TODO(scope): real DigitalOcean / DNSimple OAuth connectors are unbuilt —
  // when one lands, flip that provider's row back to `method:"oauth"` TOGETHER
  // with a tier-1 UI branch for it (the tier-1 branch renders Cloudflare only,
  // and is guarded on provider === "cloudflare" precisely so a premature flip
  // here degrades to manual instead of misrouting).
  {
    re: /\bdigitalocean\.com$/i,
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
  { re: /\bovh\.net$/i, provider: "ovh", label: "OVHcloud", method: "guided" },
  { re: /\bgandi\.net$/i, provider: "gandi", label: "Gandi", method: "guided" },
  { re: /\brzone\.de$/i, provider: "strato", label: "STRATO", method: "guided" },
  { re: /\bbluehost\.com$/i, provider: "bluehost", label: "Bluehost", method: "guided" },
  { re: /\bhostgator\.com$/i, provider: "hostgator", label: "HostGator", method: "guided" },
  { re: /\bdreamhost\.com$/i, provider: "dreamhost", label: "DreamHost", method: "guided" },
];

// `"domain-connect": 2` routes the NS_MAP rows above with
// method:"domain-connect" (GoDaddy, IONOS, Vercel, WordPress.com, NameSilo)
// to tier 2. The tier-2 APPLY path is wired in apps/web behind
// DODOMAIN_TIER2_DC_ENABLED (2026-07-11 build — the
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
  discover?: (domain: string) => Promise<DiscoveryResult>;
}

export async function detectProvider(
  domain: string,
  deps: DetectDeps = {},
): Promise<ProviderMatch> {
  const discoverFn = deps.discover ?? discover;
  // ONE walk decides everything: the zone that owns the records, and its NS.
  // `nameServers` is [] when the lookup fails, exactly as the previous
  // apex-only lookup's catch produced.
  const { zone, nameServers } = await nearestZoneCut(
    domain,
    deps.resolveNs ? { resolveNs: deps.resolveNs } : {},
  );

  // Domain Connect discovery runs in parallel-ish; it's the strongest Tier-2
  // signal. It runs against the OWNING zone — the walk already found it, and
  // a parent zone's Domain Connect endpoint cannot apply records here.
  let dc: ProviderMatch["domainConnect"];
  let dcSettings: DcSettings | undefined;
  try {
    const res = await discoverFn(zone);
    if (res?.settings?.providerId) {
      dc = { providerId: res.settings.providerId, providerName: res.settings.providerName };
      dcSettings = res.settings;
    }
  } catch {
    /* not a DC provider, or no _domainconnect record */
  }

  const hit = NS_MAP.find((m) => nameServers.some((ns) => m.re.test(ns)));

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
