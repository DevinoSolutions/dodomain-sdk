// THE one home for "which addresses belong to a CDN that proxies web traffic".
//
// A CDN proxy in front of a zone (Cloudflare's orange cloud) REPLACES the value
// of a proxied A/AAAA/CNAME with the CDN's own edge addresses — and flattens a
// proxied CNAME into address records — so a name can serve its site perfectly
// while DoDomain's re-check sees "expected CNAME missing". Telling that apart
// from a genuinely deleted record needs to know whose addresses the name now
// answers with. This file is that knowledge, as a COMMITTED SNAPSHOT:
//
//   - it is never fetched at request time — the re-check runs every five
//     minutes over every connection, and a monitor whose verdict depends on a
//     third-party HTTP fetch succeeding is a monitor that flips on the day that
//     fetch fails;
//   - it is refreshed by `node scripts/ci/cdn-proxy-ranges-watch.mjs --write`
//     (rewrites the GENERATED block below from the published lists), and the
//     nightly `.github/workflows/cdn-proxy-ranges-watch.yml` runs the same
//     script in check mode, going red and opening an issue the moment a
//     published list drifts from this snapshot.
//
// Pure data, ZERO imports: client-safe, so the dashboard reads the provider
// labels through the `@dodomain/core/cdn-proxy-ranges` subpath and the watch
// script imports it without resolving the rest of core. The classifier that
// reads it lives in cdn-proxy.ts. Everything between the GENERATED markers is
// rewritten by the refresh script — change the script, not the block.

/** Every CDN whose proxy DoDomain recognises. Mirrors the Prisma `CdnProxyProvider` enum. */
export const CDN_PROXY_PROVIDERS = ["cloudflare"] as const;

export type CdnProxyProvider = (typeof CDN_PROXY_PROVIDERS)[number];

/** How a provider is named to a human ("Proxied by Cloudflare"). */
export const CDN_PROXY_PROVIDER_LABELS: Record<CdnProxyProvider, string> = {
  cloudflare: "Cloudflare",
};

/** One provider's published proxy ranges, as of `fetchedOn`. */
export interface CdnProxyRangeSnapshot {
  /** UTC date (YYYY-MM-DD) the lists below were fetched from `sources`. */
  fetchedOn: string;
  /** The published plain-text lists (one CIDR per line) the snapshot mirrors. */
  sources: { ipv4: string; ipv6: string };
  ipv4: readonly string[];
  ipv6: readonly string[];
}

// GENERATED:BEGIN cdn-proxy-ranges
export const CDN_PROXY_RANGES: Record<CdnProxyProvider, CdnProxyRangeSnapshot> = {
  cloudflare: {
    fetchedOn: "2026-09-25",
    sources: {
      ipv4: "https://www.cloudflare.com/ips-v4",
      ipv6: "https://www.cloudflare.com/ips-v6",
    },
    ipv4: [
      "173.245.48.0/20",
      "103.21.244.0/22",
      "103.22.200.0/22",
      "103.31.4.0/22",
      "141.101.64.0/18",
      "108.162.192.0/18",
      "190.93.240.0/20",
      "188.114.96.0/20",
      "197.234.240.0/22",
      "198.41.128.0/17",
      "162.158.0.0/15",
      "104.16.0.0/13",
      "104.24.0.0/14",
      "172.64.0.0/13",
      "131.0.72.0/22",
    ],
    ipv6: [
      "2400:cb00::/32",
      "2606:4700::/32",
      "2803:f800::/32",
      "2405:b500::/32",
      "2405:8100::/32",
      "2a06:98c0::/29",
      "2c0f:f248::/32",
    ],
  },
};
// GENERATED:END cdn-proxy-ranges
