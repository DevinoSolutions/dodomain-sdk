// Which OVHcloud region a zone belongs to: client-safe (no `node:` imports),
// so the hosted connect page's offer gate (apps/web lib/ovh-offer.ts) and the
// server's adapter (ovh.ts, which re-exports this) decide it identically.

/**
 * An OVH account lives in exactly one region and an application key signs only
 * for its own region (spike 2026-10-30). The US region (api.us.ovhcloud.com,
 * OVH US LLC) is left out on purpose: US anonymous carts have no standalone
 * DNS-zone product, and no nameserver pattern routes a zone to it.
 */
export const OVH_REGIONS = ["ca", "eu"] as const;
export type OvhRegion = (typeof OVH_REGIONS)[number];

/**
 * Which OVH region a zone's nameservers put it in, or null. Observed live: an
 * OVH Canada zone is served by dnsNN.ovh.ca + nsNN.ovh.ca (oc.mrneon.online,
 * 2026-11-03); OVH Europe zones by dnsNN.ovh.net + nsNN.ovh.net. Every
 * nameserver must agree; a mixed or partly foreign set is not routed.
 * TODO(T-6776): the spike read that older CA accounts may also sit on
 * .ovh.net; such a zone routes to EU and its consent fails at OVH's login,
 * landing on the guided steps. Revisit once an EU key exists.
 */
export function ovhRegionForNameServers(nameServers: readonly string[]): OvhRegion | null {
  const names = nameServers.map((ns) => ns.trim().toLowerCase().replace(/\.$/, ""));
  if (names.length === 0) return null;
  if (names.every((ns) => ns.endsWith(".ovh.ca"))) return "ca";
  if (names.every((ns) => ns.endsWith(".ovh.net"))) return "eu";
  return null;
}
