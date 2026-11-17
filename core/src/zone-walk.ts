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

import { apexOf } from "./apex.ts";
import { NODATA, NOTFOUND } from "node:dns";
import { sharedBoundedResolver } from "./dns-defaults.ts";
import { parentDelegatedNs, type DelegationDeps } from "./ns-delegation.ts";

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
  /** Distinguishes an owned NS RRset from a recursive NS answer reached through
   * a CNAME. Inject alongside resolveNs when the fixture includes aliases. An
   * injected resolveNs without this seam is treated as an already-owned NS
   * lookup; it never silently opens a real DNS socket. */
  resolveCname?: (host: string) => Promise<string[]>;
  /** Authoritative NS lookup; defaults to the BOUNDED node:dns resolver
   * (dns-defaults.ts). Injected in tests so the walk runs offline. A DNS query
   * opens no socket to a stranger-chosen host, so this needs no SSRF guard
   * (unlike the discovery fetch) — but it does need a deadline: this walk asks
   * one candidate at a time, so on node's unbounded default a single
   * black-holed delegation cost ~30 s per candidate and the whole walk far more
   * than any caller was prepared to wait (dns-defaults.ts's header). */
  resolveNs?: (host: string) => Promise<string[]>;
  /** The owning zone's NS as its PARENT delegates them (ns-delegation.ts).
   * Default: the real parent lookup, but ONLY when `resolveNs` is not injected
   * either, so a fixture that pins NS answers never opens a socket. */
  parentNs?: ZoneNsDeps["parentNs"];
  /** Where a parent/recursive disagreement or a parent-lookup fallback is reported. Default: reportNsTrace. */
  onNsTrace?: ZoneNsDeps["onNsTrace"];
}

export interface ZoneCut {
  /** The zone whose authoritative servers own records at the queried host. */
  zone: string;
  /** That zone's NS names, lowercased — `[]` when the lookup failed. */
  nameServers: string[];
  /** Which view `nameServers` came from (zoneNameServers below). */
  nameServerSource: NsSource;
}

// ——— a zone's nameservers: the ONE place they are decided (T-10301) ———
//
// Detection (which provider, which one-click) and read-back (verify.ts pins
// record queries to these servers) both take a zone's NS from here. The
// parent's delegation wins: a recursive resolver may hold the old NS set for
// the whole NS TTL (24 h is common) after a customer moves nameservers, and on
// 2026-10-29 the web container's resolver did exactly that for dodomaindemo.xyz
// (ns-delegation.ts's header). The recursive answer stays as the fallback for
// when the parent cannot be asked, and that fallback is always REPORTED.

export type NsSource = "parent" | "recursive";

/** One reportable event from zoneNameServers: the parent and the recursive view disagreed, or the parent could not be used. */
export type NsTrace =
  | {
      event: "dns.ns.recursive_stale";
      zone: string;
      parent: string[];
      recursive: string[] | { error: string };
    }
  | {
      event: "dns.ns.parent_fallback";
      zone: string;
      parentError: string;
      parentMessage: string;
      recursive: string[] | { error: string };
    };

export interface ZoneNsDeps {
  /** Recursive NS lookup: the fallback view. */
  resolveNs: (host: string) => Promise<string[]>;
  /** Parent-delegation NS lookup. Undefined = recursive only (an offline fixture). */
  parentNs?: (zone: string) => Promise<string[]>;
  onNsTrace?: (trace: NsTrace) => void;
}

/** Default NS-trace sink: one structured warn line (core has no logger and
 * takes no config; a caller with one injects `onNsTrace`). */
function reportNsTrace(trace: NsTrace): void {
  console.warn(JSON.stringify({ level: "warn", ...trace }));
}

type Settled<T> = { ok: true; value: T } | { ok: false; error: unknown };

function settle<T>(p: Promise<T>): Promise<Settled<T>> {
  return p.then(
    (value) => ({ ok: true as const, value }),
    (error: unknown) => ({ ok: false as const, error }),
  );
}

function errorCode(error: unknown): string {
  return (error as NodeJS.ErrnoException)?.code ?? "UNKNOWN";
}

function lowered(ns: string[]): string[] {
  return ns.map((n) => n.replace(/\.$/, "").toLowerCase());
}

function sameSet(a: string[], b: string[]): boolean {
  const x = new Set(a);
  const y = new Set(b);
  return x.size === y.size && [...x].every((n) => y.has(n));
}

/** Parent view first, recursive as the reported fallback; throws the recursive
 * error only when neither view produced nameservers. */
async function reconcileNs(
  zone: string,
  recursive: Settled<string[]>,
  parent: Settled<string[]> | undefined,
  onNsTrace: (trace: NsTrace) => void,
): Promise<{ nameServers: string[]; source: NsSource }> {
  const recursiveView = recursive.ok
    ? lowered(recursive.value)
    : { error: errorCode(recursive.error) };
  if (parent) {
    if (parent.ok && parent.value.length > 0) {
      const delegated = lowered(parent.value);
      if (Array.isArray(recursiveView) ? !sameSet(delegated, recursiveView) : true) {
        onNsTrace({
          event: "dns.ns.recursive_stale",
          zone,
          parent: delegated,
          recursive: recursiveView,
        });
      }
      return { nameServers: delegated, source: "parent" };
    }
    onNsTrace({
      event: "dns.ns.parent_fallback",
      zone,
      parentError: parent.ok ? "EEMPTY" : errorCode(parent.error),
      parentMessage: parent.ok
        ? "parent returned no nameservers"
        : String((parent.error as Error)?.message ?? parent.error),
      recursive: recursiveView,
    });
  }
  if (!recursive.ok) throw recursive.error;
  return { nameServers: lowered(recursive.value), source: "recursive" };
}

/**
 * `zone`'s nameservers, lowercased: the parent's delegation when it can be
 * read, else the recursive resolver's answer (reported through `onNsTrace`).
 * Throws the RECURSIVE lookup's error when neither view yields nameservers, so
 * a caller that classifies NXDOMAIN/NODATA (verify.ts) keeps doing so.
 */
export async function zoneNameServers(
  zone: string,
  deps: ZoneNsDeps,
): Promise<{ nameServers: string[]; source: NsSource }> {
  const [recursive, parent] = await Promise.all([
    settle(deps.resolveNs(zone)),
    deps.parentNs ? settle(deps.parentNs(zone)) : Promise.resolve(undefined),
  ]);
  return reconcileNs(zone, recursive, parent, deps.onNsTrace ?? reportNsTrace);
}

/** The real parent lookup, or none when the caller pinned NS answers offline. */
export function defaultParentNs(
  injectedResolver: boolean,
  bounds: Pick<DelegationDeps, "dnsTimeoutMs" | "dnsTries"> = {},
): ZoneNsDeps["parentNs"] {
  return injectedResolver ? undefined : (zone: string) => parentDelegatedNs(zone, bounds);
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
  const resolve = deps.resolveNs ?? ((host: string) => sharedBoundedResolver().resolveNs(host));
  const resolveCname =
    deps.resolveCname ??
    (deps.resolveNs ? undefined : (host: string) => sharedBoundedResolver().resolveCname(host));
  const parentNs = deps.parentNs ?? defaultParentNs(deps.resolveNs !== undefined);
  const onNsTrace = deps.onNsTrace ?? reportNsTrace;
  const candidates = zoneCandidates(normalizeFqdn(fqdn));
  const floor = candidates[candidates.length - 1]!;

  // The walk FINDS the zone through the recursive view (a cut is a name owning
  // NS); the found zone's NS are then settled by zoneNameServers' rule, parent
  // first. A stale cache can still hide a brand-new subzone delegation from the
  // walk; it can no longer hide where an existing zone's NS now point.
  const cut = async (zone: string, recursive: Settled<string[]>): Promise<ZoneCut> => {
    const parent = parentNs ? await settle(parentNs(zone)) : undefined;
    try {
      const { nameServers, source } = await reconcileNs(zone, recursive, parent, onNsTrace);
      return { zone, nameServers, nameServerSource: source };
    } catch {
      // Neither view produced nameservers. The walk never throws (a flaky NS
      // query must not fail a paid verify or detect); a parent failure was
      // already reported by reconcileNs, and `[]` is the documented
      // lookup-failed value every caller handles.
      return { zone, nameServers: [], nameServerSource: "recursive" };
    }
  };

  for (const candidate of candidates.slice(0, -1)) {
    const nameServers = await nsOf(candidate, resolve);
    if (nameServers.length > 0) {
      if (resolveCname) {
        let aliases: string[];
        try {
          aliases = await resolveCname(candidate);
        } catch (error) {
          // NOTFOUND/NODATA: no alias. Any other failure (timeout, SERVFAIL)
          // is inconclusive and keeps the cut, exactly as before this check
          // existed: like nsOf, the walk never throws on a resolver failure,
          // so a flaky CNAME query cannot fail a paid verify or detect.
          const code = (error as NodeJS.ErrnoException).code;
          if (code !== NOTFOUND && code !== NODATA) {
            return cut(candidate, { ok: true, value: nameServers });
          }
          aliases = [];
        }
        // Recursive resolvers follow CNAMEs for NS queries. Their positive
        // answer describes the target's zone, not a delegation at this name.
        if (aliases.length > 0) continue;
      }
      return cut(candidate, { ok: true, value: nameServers });
    }
  }
  return cut(floor, await settle(resolve(floor)));
}
