// DNS lookup / propagation check — the engine behind the public DNS-lookup tool
// (dodomain.io/tools/dns-lookup, OPPORTUNITIES Tier-1 #1).
//
// One name + one record type, read from FOUR places: the zone's own
// authoritative nameservers (through verify.ts's resolveZoneAuthority — the
// same walk, pin and timeouts record verification uses) and three public
// recursive resolvers. "Propagated" means every view that answered agrees with
// the authoritative one; the tool never says "propagated" on the strength of a
// public resolver alone, because a public resolver can only tell you what it
// has cached, and the authoritative answer is the thing being propagated.
//
// HONESTY: a resolver whose lookup did not complete is reported as `error`
// with its code — it is never counted as agreeing, and never as disagreeing.
// `consistent` is null when the authoritative view itself is unavailable,
// because there is nothing to be consistent WITH.
//
// Framework-free: the public resolvers are built through `publicResolverFor`
// (default: a bounded node:dns/promises Resolver pinned to one address) so a
// unit test never opens a socket.

import { Resolver } from "node:dns/promises";
import type { RecordType } from "./record-capabilities.ts";
import {
  lookupRecordAnswers,
  resolveZoneAuthority,
  type DnsResolver,
  type VerifyDeps,
} from "./verify.ts";

/** The public recursive resolvers the tool asks, in display order. Anycast addresses; stable for a decade. */
export const PUBLIC_RESOLVERS = [
  { name: "Cloudflare", address: "1.1.1.1" },
  { name: "Google", address: "8.8.8.8" },
  { name: "Quad9", address: "9.9.9.9" },
] as const;

const DEFAULT_DNS_TIMEOUT_MS = 5000;
const DEFAULT_DNS_TRIES = 2;

export interface DnsLookupDeps extends VerifyDeps {
  /** Builds the resolver for one public address (default: a bounded Resolver pinned to it). */
  publicResolverFor?: (address: string) => DnsResolver;
}

export interface ResolverView {
  /** "authoritative", or the public resolver's display name. */
  resolver: string;
  /** The address asked, or null for the authoritative view (its addresses are the zone's own NS). */
  address: string | null;
  /** `answers` = records came back; `absent` = the resolver answered "no such record"; `error` = the lookup did not complete. */
  outcome: "answers" | "absent" | "error";
  /** Verbatim answers (MX as `"priority exchange"`), empty unless `answers`. */
  answers: string[];
  /** The `node:dns` error code behind `error`. */
  error?: string;
}

export interface DnsLookupResult {
  fqdn: string;
  type: RecordType;
  /** The zone that owns the name — the nearest delegation cut, floored at the registrable apex. */
  zone: string;
  authoritative: ResolverView;
  public: ResolverView[];
  /**
   * true  = every view that completed agrees with the authoritative answer set;
   * false = at least one completed public view differs (propagation in flight, or a stale cache);
   * null  = the authoritative view is unavailable, so agreement cannot be judged.
   */
  consistent: boolean | null;
}

function canonicalAnswerSet(answers: string[]): string {
  return [...new Set(answers.map((a) => a.trim().replace(/\.$/, "").toLowerCase()))]
    .sort()
    .join("\n");
}

async function view(
  resolverName: string,
  address: string | null,
  resolver: DnsResolver,
  fqdn: string,
  type: RecordType,
): Promise<ResolverView> {
  const outcome = await lookupRecordAnswers(resolver, fqdn, type);
  if (outcome.kind === "records") {
    return {
      resolver: resolverName,
      address,
      outcome: outcome.records.length === 0 ? "absent" : "answers",
      answers: outcome.records,
    };
  }
  if (outcome.kind === "absent")
    return { resolver: resolverName, address, outcome: "absent", answers: [] };
  return { resolver: resolverName, address, outcome: "error", answers: [], error: outcome.code };
}

/**
 * Read `type` records at `fqdn` from the authoritative nameservers and every
 * PUBLIC_RESOLVERS entry, concurrently, and judge whether they agree.
 */
export async function lookupRecordAcrossResolvers(
  fqdn: string,
  type: RecordType,
  deps: DnsLookupDeps = {},
): Promise<DnsLookupResult> {
  const name = fqdn.trim().replace(/\.$/, "").toLowerCase();
  const timeoutMs = deps.dnsTimeoutMs ?? DEFAULT_DNS_TIMEOUT_MS;
  const tries = deps.dnsTries ?? DEFAULT_DNS_TRIES;
  const publicResolverFor =
    deps.publicResolverFor ??
    ((address: string): DnsResolver => {
      const r = new Resolver({ timeout: timeoutMs, tries });
      r.setServers([address]);
      return r;
    });

  const authorityPromise = resolveZoneAuthority(name, deps).then(
    async ({ zone, authoritative }): Promise<{ zone: string; view: ResolverView }> => {
      if (authoritative.kind !== "resolver") {
        return {
          zone,
          view: {
            resolver: "authoritative",
            address: null,
            outcome: "error",
            answers: [],
            error:
              authoritative.kind === "ns_unresolvable" ? "NS_UNRESOLVABLE" : authoritative.code,
          },
        };
      }
      return { zone, view: await view("authoritative", null, authoritative.resolver, name, type) };
    },
  );
  const publicPromises = PUBLIC_RESOLVERS.map((r) =>
    view(r.name, r.address, publicResolverFor(r.address), name, type),
  );

  const [authority, ...publicViews] = await Promise.all([authorityPromise, ...publicPromises]);

  let consistent: boolean | null = null;
  if (authority.view.outcome !== "error") {
    const reference = canonicalAnswerSet(authority.view.answers);
    consistent = publicViews
      .filter((v) => v.outcome !== "error")
      .every((v) => canonicalAnswerSet(v.answers) === reference);
  }

  return {
    fqdn: name,
    type,
    zone: authority.zone,
    authoritative: authority.view,
    public: publicViews,
    consistent,
  };
}
