// Authoritative-DNS verification.
//
// A successful redirect/callback is NOT proof that records were applied. After the
// flow returns, we verify the expected records against the *authoritative*
// nameservers (resolved fresh, bypassing recursive caches), and separately against
// a public resolver for propagation UX.

import { NODATA, NOTFOUND } from "node:dns";
import { Resolver } from "node:dns/promises";
import { recordValueMatches } from "./record-capabilities.ts";
import type { ExpectedRecord, VerificationResult } from "./types.ts";
import { nearestZoneCut } from "./zone-walk.ts";

// Bounded DNS query defaults applied to BOTH resolvers built below (the public
// recursive resolver AND the authoritative-NS-pinned one). Without a cap, a
// black-holed nameserver hangs the request thread on c-ares' generous defaults
// (seconds per try × tries) — an unbounded stall on a hostile/broken zone. 5s ×
// 2 tries bounds a single verifyRecord's worst case. These are DEFAULTS,
// overridable per call via VerifyDeps: packages/core takes config as ARGUMENTS,
// never reading process.env (scripts/check-core-config-bans.sh).
const DEFAULT_DNS_TIMEOUT_MS = 5000;
const DEFAULT_DNS_TRIES = 2;

/**
 * The subset of `node:dns/promises` verify.ts needs, as an injectable seam —
 * mirrors `DiscoveryDeps` (discovery.ts) / `DetectDeps` (detect.ts): the
 * repo's one way to make DNS-touching code testable offline (F-011). Both
 * the "public" resolver AND the resolver used inside the authoritative NS→A
 * walk are this shape, so a fake can drive either path deterministically —
 * no network call in a core unit test (a network call in a core unit test
 * would hang CI; that is the enforcing check for this convention).
 */
export interface DnsResolver {
  resolveNs(host: string): Promise<string[]>;
  resolve4(host: string): Promise<string[]>;
  resolve6(host: string): Promise<string[]>;
  resolveCname(host: string): Promise<string[]>;
  resolveMx(host: string): Promise<Array<{ exchange: string; priority: number }>>;
  resolveTxt(host: string): Promise<string[][]>;
}

// Builds the "public" recursive resolver — a node:dns/promises Resolver bound to
// the system's configured nameservers (identical servers to the bare
// dns/promises free functions this replaced) PLUS a bounded per-query
// timeout/tries so a stalled server can't hang the request. Constructed only
// when no `deps.resolver` is injected, so unit tests (which always inject a
// fake) never open a real DNS channel. The promises Resolver structurally
// satisfies DnsResolver (all resolve* methods return promises), so it is
// returned directly — same as the authoritative resolver below.
function makeBoundedResolver(timeoutMs: number, tries: number): DnsResolver {
  return new Resolver({ timeout: timeoutMs, tries });
}

/**
 * Why the zone's authoritative resolver could (or couldn't) be built. This
 * used to be a bare `DnsResolver | null`, which threw the reason away: an apex
 * NS query answering NXDOMAIN ("this domain isn't registered") was
 * indistinguishable from the NS query itself breaking ("we couldn't check
 * right now"), so a user who typo'd their domain was told "we'll retry"
 * forever. verifyRecord() below reads `ns_absent` — corroborated by the public
 * resolver also finding nothing — to answer `domain_not_found` instead.
 */
export type AuthoritativeResolution =
  /** the zone's nameservers were resolved; record queries go straight to them. */
  | { kind: "resolver"; resolver: DnsResolver }
  /**
   * the apex NS query was ANSWERED and the zone has no nameservers: NXDOMAIN /
   * NODATA, or an empty answer (some resolvers return one instead of throwing,
   * which is the NODATA condition by another name). `code` is the `node:dns`
   * error code that said so.
   */
  | { kind: "ns_absent"; code: string }
  /** the apex NS query itself failed (SERVFAIL/timeout/refused/…) — we learned nothing. */
  | { kind: "ns_error"; code: string }
  /** nameservers exist by name, but none of them resolved to an address. */
  | { kind: "ns_unresolvable" };

// Resolve `zone`'s authoritative nameservers (via the injected `resolver`, so
// tests can pin the NS→A walk deterministically), then build a DnsResolver
// pinned to those nameservers' own IPs — bypassing recursive-resolver caches.
// The pinned resolver carries the SAME bounded timeout/tries as the public one
// (a black-holed authoritative NS is the primary stall vector this closes).
async function authoritativeResolverFor(
  zone: string,
  resolver: DnsResolver,
  timeoutMs: number,
  tries: number,
): Promise<AuthoritativeResolution> {
  let ns: string[];
  try {
    ns = await resolver.resolveNs(zone);
  } catch (e) {
    // Same classification as lookup() below: ENOTFOUND/ENODATA is an ANSWER
    // ("no nameservers here"), anything else is the query failing.
    const code = (e as NodeJS.ErrnoException)?.code ?? "UNKNOWN";
    return code === NOTFOUND || code === NODATA
      ? { kind: "ns_absent", code }
      : { kind: "ns_error", code };
  }
  if (!ns.length) return { kind: "ns_absent", code: NODATA };
  const ips: string[] = [];
  for (const host of ns.slice(0, 3)) {
    try {
      const a = await resolver.resolve4(host);
      if (a[0]) ips.push(a[0]);
    } catch {
      // One unresolvable NS name doesn't sink the zone — the others may still
      // answer. "None of them resolved" is reported as ns_unresolvable below,
      // so the failure never disappears silently.
    }
  }
  if (!ips.length) return { kind: "ns_unresolvable" };
  const r = new Resolver({ timeout: timeoutMs, tries });
  r.setServers(ips);
  return { kind: "resolver", resolver: r };
}

export interface VerifyDeps {
  /** the "public" recursive resolver. default: a bounded node:dns/promises Resolver. */
  resolver?: DnsResolver;
  /** builds a resolver pinned to a zone's authoritative NS. default: authoritativeResolverFor() above. */
  authoritativeResolverFor?: (
    zone: string,
    resolver: DnsResolver,
  ) => Promise<AuthoritativeResolution>;
  /**
   * DNS query timeout (ms) applied to BOTH default resolvers so a black-holed
   * nameserver can't hang the request thread. Default 5000. Ignored for an
   * injected `resolver`/`authoritativeResolverFor` (an injected resolver owns
   * its own timing).
   */
  dnsTimeoutMs?: number;
  /** DNS retry count before giving up on a nameserver (both default resolvers). Default 2. */
  dnsTries?: number;
  /**
   * The zone whose authoritative nameservers to interrogate, when the caller
   * already resolved it. `verifyRecords` below sets this once per distinct zone
   * so a multi-record run pays the walk once; omit it and each call resolves
   * its own owning zone.
   */
  zone?: string;
}

/**
 * The zone that OWNS `fqdn` — the nearest delegation cut, floored at the
 * registrable apex (zone-walk.ts).
 *
 * This is NOT `apexOf(fqdn)`, and the difference is the whole bug. Verification
 * queries a zone's nameservers DIRECTLY, bypassing recursive caches — that is
 * the point of it. A direct query is not a recursive one: ask the apex's
 * nameservers for a name that lives in a subzone delegated away from them and
 * they answer with a referral, which c-ares surfaces as ENOTFOUND, which read
 * as "the record is absent". Live on 2026-08-06 a TXT that was demonstrably
 * present on all four of the delegated zone's nameservers and on three public
 * resolvers was reported absent five times running, because
 * `apexOf("_dodomain-challenge.dc.mrneon.online")` is mrneon.online (Cloudflare)
 * while the record lives in dc.mrneon.online (as207960).
 *
 * The walk floors at the registrable apex, so a host with no delegated subzone
 * resolves to exactly the zone `apexOf` returned — unchanged behaviour,
 * including the apex-NXDOMAIN path that reports `domain_not_found`.
 */
async function owningZoneOf(fqdn: string, resolver: DnsResolver): Promise<string> {
  const { zone } = await nearestZoneCut(fqdn, {
    resolveNs: (host) => resolver.resolveNs(host),
  });
  return zone;
}

// F-011: a lookup either finds records, finds the authoritative resolver
// genuinely has none (absent), or the check itself failed (error) — the
// three used to collapse into a single `[]`, making a SERVFAIL/timeout
// indistinguishable from a real absence. `NS_RESOLUTION_FAILED` is not a
// `node:dns` error code — it is a synthetic marker verifyRecord() uses below
// for "the zone's authoritative nameservers themselves could not be
// resolved" (a distinct failure mode from a DNS error answering the
// *record* query). Both fold into outcome:"indeterminate" — an
// unconfirmable check must never read as "absent" (PLAN-F-011 §2c).
type LookupOutcome =
  { kind: "records"; records: string[] } | { kind: "absent" } | { kind: "error"; code: string };

const NS_RESOLUTION_FAILED = "NS_RESOLUTION_FAILED";

// MX answers are encoded as "${priority} ${exchange}" here so a resolver's
// per-record priority is preserved through to matches() below (which splits the
// pair back apart and compares BOTH fields via record-capabilities.ts's shared
// recordValueMatches) — a record applied with the wrong preference no longer
// "verifies" (F-002 hop 2: the old code mapped MX answers to `exchange` alone,
// silently dropping `priority`). The encoded string is also what surfaces in
// VerificationResult.authoritativeFound/publicFound for logs + the verify route.
async function lookup(
  resolver: DnsResolver,
  fqdn: string,
  type: ExpectedRecord["type"],
): Promise<LookupOutcome> {
  try {
    let records: string[];
    if (type === "CNAME") records = await resolver.resolveCname(fqdn);
    else if (type === "A") records = await resolver.resolve4(fqdn);
    else if (type === "AAAA") records = await resolver.resolve6(fqdn);
    else if (type === "MX") {
      const mx = await resolver.resolveMx(fqdn);
      records = mx.map((m) => `${m.priority} ${m.exchange}`);
    } else {
      // TXT
      const txt = await resolver.resolveTxt(fqdn);
      records = txt.map((parts) => parts.join(""));
    }
    return { kind: "records", records };
  } catch (e) {
    // Classify by DNS error code instead of collapsing every failure to
    // `[]`: ENOTFOUND/ENODATA mean the resolver authoritatively answered
    // "no such record" (absent); anything else (SERVFAIL/timeout/refused/…)
    // means the check itself is indeterminate, not a confirmed absence.
    const code = (e as NodeJS.ErrnoException)?.code ?? "UNKNOWN";
    if (code === NOTFOUND || code === NODATA) return { kind: "absent" };
    return { kind: "error", code };
  }
}

/**
 * Exported for a deterministic unit test (test/verify.test.ts) — no DNS/network.
 * Delegates the value comparison to record-capabilities.ts's recordValueMatches
 * (the ONE home for record-value normalization — TXT exact/case-sensitive,
 * host-like trailing-dot+case-insensitive, MX exchange+priority) so this DNS
 * path and the tier-1 Cloudflare apply path can never drift (D-001).
 */
export function matches(found: string[], rec: ExpectedRecord): boolean {
  return found.some((f) => {
    if (rec.type === "MX") {
      // `found` MX entries are encoded "priority exchange" (see lookup()); split
      // them back so the shared matcher gets the exchange + numeric priority as
      // separate inputs. A session with NO expected priority (legacy, pre-F-002
      // guard) compares the exchange alone — recordValueMatches handles that when
      // expectedPriority is undefined.
      const m = /^(\d+)\s+(.*)$/.exec(f);
      const actualPriority = m ? Number(m[1]) : undefined;
      const actualExchange = m ? m[2]! : f;
      return recordValueMatches("MX", rec.expect, actualExchange, {
        expectedPriority: rec.priority,
        actualPriority,
      });
    }
    return recordValueMatches(rec.type, rec.expect, f);
  });
}

export async function verifyRecord(
  rec: ExpectedRecord,
  deps: VerifyDeps = {},
): Promise<VerificationResult> {
  const timeoutMs = deps.dnsTimeoutMs ?? DEFAULT_DNS_TIMEOUT_MS;
  const tries = deps.dnsTries ?? DEFAULT_DNS_TRIES;
  const resolver = deps.resolver ?? makeBoundedResolver(timeoutMs, tries);
  const buildAuthoritative =
    deps.authoritativeResolverFor ??
    ((zone, r) => authoritativeResolverFor(zone, r, timeoutMs, tries));
  const zone = deps.zone ?? (await owningZoneOf(rec.fqdn, resolver));
  const auth = await buildAuthoritative(zone, resolver);

  // Anything but a built resolver means the zone's own nameservers were never
  // reached, so the record check couldn't run — grouped with a genuine lookup
  // error (both are "the check itself failed", not "the record is absent").
  // NS_RESOLUTION_FAILED stays the reported code for every such case; the
  // apex-NXDOMAIN one keeps its real DNS code separately (nsAbsentCode) for
  // the domain_not_found branch below.
  const authOutcome: LookupOutcome =
    auth.kind === "resolver"
      ? await lookup(auth.resolver, rec.fqdn, rec.type)
      : { kind: "error", code: NS_RESOLUTION_FAILED };
  const nsAbsentCode = auth.kind === "ns_absent" ? auth.code : undefined;
  const publicOutcome = await lookup(resolver, rec.fqdn, rec.type);

  const authoritativeFound = authOutcome.kind === "records" ? authOutcome.records : [];
  const publicFound = publicOutcome.kind === "records" ? publicOutcome.records : [];

  // FAIL-CLOSED (PM-007): `present` is true ONLY on an actual authoritative
  // match. matches() against an empty `authoritativeFound` is always false,
  // so the error path and the absent path both leave present:false
  // identically — an indeterminate lookup can NEVER set present:true.
  // `outcome` below is what tells the two apart.
  const onAuth = matches(authoritativeFound, rec);
  const onPublic = matches(publicFound, rec);

  const publicError = publicOutcome.kind === "error" ? publicOutcome.code : undefined;

  let outcome: VerificationResult["outcome"];
  let note: string;
  let authoritativeError: string | undefined;

  if (onAuth && onPublic) {
    outcome = "verified";
    note = "verified on authoritative and public DNS";
  } else if (onAuth && !onPublic) {
    outcome = "propagating";
    note = "on authoritative DNS; public resolvers still propagating";
  } else if (authOutcome.kind === "error") {
    // The domain itself doesn't exist: the apex NS query ANSWERED "no
    // nameservers" AND the public recursive resolver also answered "no such
    // record". Two independent NXDOMAIN-class answers are the discriminator
    // between an unregistered/misspelled domain and our own check breaking —
    // without it this fell into "indeterminate" and the caller retried a
    // domain that can never resolve. A single answer is not enough: if the
    // public side errored or (impossibly) found records, we don't know, so
    // the honest indeterminate below still applies.
    if (nsAbsentCode !== undefined && publicOutcome.kind === "absent") {
      outcome = "domain_not_found";
      authoritativeError = nsAbsentCode;
      note = "domain does not resolve — it may be unregistered, misspelled, or have no nameservers";
    } else {
      outcome = "indeterminate";
      authoritativeError = authOutcome.code;
      note =
        authOutcome.code === NS_RESOLUTION_FAILED
          ? "could not resolve authoritative nameservers; public-only check"
          : `authoritative DNS check failed (${authOutcome.code}); could not confirm — retry`;
    }
  } else {
    outcome = "absent";
    note = "not found on authoritative DNS yet";
  }

  return {
    fqdn: rec.fqdn,
    type: rec.type,
    present: onAuth,
    authoritativeFound,
    publicFound,
    note,
    outcome,
    ...(authoritativeError !== undefined ? { authoritativeError } : {}),
    ...(publicError !== undefined ? { publicError } : {}),
  };
}

/**
 * Verify every record of one session in a single run.
 *
 * The reason this exists rather than a bare `Promise.all(recs.map(verifyRecord))`:
 * resolving which zone owns a record is a DNS walk, and a session's records
 * almost always share one zone, so the walks overlap almost entirely.
 *
 * The overlap is removed by memoising the NS lookups for the run, NOT by
 * reusing a zone across records. "fqdn2 ends with `.<zone we already found>`,
 * so it lives there too" is unsound: a deeper delegation between that zone and
 * fqdn2 would be silently skipped, which is the exact class of bug this whole
 * change fixes. Every record therefore still gets its own honest walk; the
 * shared part of it is answered from cache and costs no DNS.
 *
 * Each result is byte-identical to calling `verifyRecord` on the record alone.
 */
export async function verifyRecords(
  recs: ExpectedRecord[],
  deps: VerifyDeps = {},
): Promise<VerificationResult[]> {
  if (deps.zone !== undefined) return Promise.all(recs.map((r) => verifyRecord(r, deps)));

  const timeoutMs = deps.dnsTimeoutMs ?? DEFAULT_DNS_TIMEOUT_MS;
  const tries = deps.dnsTries ?? DEFAULT_DNS_TRIES;
  const resolver = deps.resolver ?? makeBoundedResolver(timeoutMs, tries);

  // The promise is cached synchronously, so concurrent walks asking for the
  // same name share one in-flight query instead of racing two. Delegated
  // explicitly rather than spread: `resolver` may be a node:dns Resolver class
  // instance, whose methods live on the prototype and would not survive `...`.
  const nsCache = new Map<string, Promise<string[]>>();
  const walkResolver: DnsResolver = {
    resolveNs: (host) => {
      let pending = nsCache.get(host);
      if (!pending) {
        pending = resolver.resolveNs(host);
        nsCache.set(host, pending);
      }
      return pending;
    },
    resolve4: (host) => resolver.resolve4(host),
    resolve6: (host) => resolver.resolve6(host),
    resolveCname: (host) => resolver.resolveCname(host),
    resolveMx: (host) => resolver.resolveMx(host),
    resolveTxt: (host) => resolver.resolveTxt(host),
  };

  const zones = await Promise.all(recs.map((rec) => owningZoneOf(rec.fqdn, walkResolver)));
  return Promise.all(
    recs.map((rec, i) => verifyRecord(rec, { ...deps, resolver, zone: zones[i]! })),
  );
}
