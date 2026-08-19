// Which DNS zone actually OWNS the records for a host?
//
// The answer is not "the registrable apex". A zone ends where a delegation
// begins, so records at `status.dc.customer.com` live in whichever zone most
// specifically encloses that name — `dc.customer.com` when it has been
// delegated to its own nameservers, `customer.com` otherwise. Everything that
// depends on "who will write this record" has to key off that zone:
//
//   - tier routing: the NS that decide tier 1 are the OWNING zone's, not the
//     apex's. A Cloudflare apex cannot write records in a subzone delegated
//     away from it, so routing such a host to the Cloudflare OAuth flow is
//     wrong, not merely suboptimal.
//   - Domain Connect: the spec's Root Domain is "a registered domain (e.g.
//     example.com or example.co.uk), or to a delegated zone in DNS", discovery
//     "must work on the root domain (zone) only. Bear in mind that zones can be
//     delegated to other users", and the apply call's `domain` is "the root
//     domain (the registered domain or delegated zone)".
//   - the manual guide + the `zone` we show the user: provider DNS dashboards
//     are per zone, and the zone they must open is the delegated one.
//
// Live case this was built from (probed 2026-08-06 via 1.1.1.1):
//   mrneon.online     NS doug/riya.ns.cloudflare.com
//   dc.mrneon.online  NS ns1..ns4.as207960.net       <- a real delegation cut
//   status.dc.mrneon.online  NXDOMAIN (no cut of its own)
// Records for status.dc.mrneon.online are owned by dc.mrneon.online at Glauca;
// Cloudflare neither hosts that zone nor serves our Domain Connect templates.
//
// A zone cut is exactly a name that owns an NS RRset, which is why the walk
// tests NS rather than trusting any protocol-level probe. Domain Connect makes
// that non-optional: the spec expressly lets a provider answer the
// `_domainconnect` query for any name it likes ("the DNS Provider must simply
// respond to the DNS query for the _domainconnect TXT record with the
// appropriate data. How this is implemented is up to the DNS Provider"), so a
// TXT answer alone can never establish that a name is a zone.

import { resolveNs } from "node:dns/promises";

import { apexOf } from "./apex.ts";

/** Hard bound on one walk: a hostname may carry up to 127 labels and every
 * candidate costs a DNS round trip. The registrable apex is ALWAYS the last
 * candidate even when the cap truncates, so a deep hostname can never lose the
 * apex lookup this walk replaced. */
const MAX_ZONE_CANDIDATES = 8;

function normalizeFqdn(fqdn: string): string {
  return fqdn.trim().replace(/\.$/, "").toLowerCase();
}

/** Candidate zones for a host, most specific first, ending at the registrable
 * apex — `apexOf` (PSL) is the FLOOR: above it lies the public suffix, i.e. the
 * registry's own zone, never a customer's. */
function zoneCandidates(host: string): string[] {
  const floor = apexOf(host);
  const chain: string[] = [];
  for (let candidate = host; ;) {
    chain.push(candidate);
    if (candidate === floor) break;
    const dot = candidate.indexOf(".");
    // Termination guard: `floor` is a suffix of `host` for every tldts result,
    // so this only fires on a caller passing something that isn't.
    if (dot < 0) break;
    candidate = candidate.slice(dot + 1);
  }
  return chain.length <= MAX_ZONE_CANDIDATES
    ? chain
    : [...chain.slice(0, MAX_ZONE_CANDIDATES - 1), floor];
}

export interface ZoneWalkDeps {
  /** Authoritative NS lookup; defaults to node:dns. Injected in tests so the
   * walk runs offline. A DNS query opens no socket to a stranger-chosen host,
   * so this needs no SSRF guard (unlike the discovery fetch). */
  resolveNs?: (host: string) => Promise<string[]>;
}

export interface ZoneCut {
  /** The zone whose authoritative servers own records at the queried host. */
  zone: string;
  /** That zone's NS names, lowercased — `[]` when the lookup failed. */
  nameServers: string[];
}

async function nsOf(
  name: string,
  resolve: NonNullable<ZoneWalkDeps["resolveNs"]>,
): Promise<string[]> {
  try {
    return (await resolve(name)).map((n) => n.toLowerCase());
  } catch {
    // NODATA/NXDOMAIN: the name owns no NS RRset, so it is not a zone cut.
    // A genuine resolver failure lands here too and is treated the same way —
    // the walk then falls through to the apex, i.e. the pre-walk behaviour.
    return [];
  }
}

/**
 * The nearest enclosing zone cut for `fqdn`, with that zone's nameservers.
 *
 * Walks candidates most-specific-first and stops at the first name that owns
 * an NS RRset. The registrable apex is the floor and is returned whenever no
 * delegated subzone is found — a registered domain is always a zone — so a
 * host with no delegation resolves to exactly the apex the apex-only lookup
 * used, nameservers included (`[]` when DNS fails, as before).
 */
export async function nearestZoneCut(fqdn: string, deps: ZoneWalkDeps = {}): Promise<ZoneCut> {
  const resolve = deps.resolveNs ?? resolveNs;
  const candidates = zoneCandidates(normalizeFqdn(fqdn));
  const floor = candidates[candidates.length - 1]!;

  for (const candidate of candidates.slice(0, -1)) {
    const nameServers = await nsOf(candidate, resolve);
    if (nameServers.length > 0) return { zone: candidate, nameServers };
  }
  return { zone: floor, nameServers: await nsOf(floor, resolve) };
}
