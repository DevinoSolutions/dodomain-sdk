// "Is this name answering with a CDN proxy's edge addresses?" — the classifier
// over the vendored ranges in cdn-proxy-ranges.ts, and the one DNS observation
// that feeds it.
//
// Why it exists: record-capabilities.ts `isProxyableRecordType` has always
// documented that a CDN proxy REPLACES a proxied A/AAAA/CNAME with the edge's
// own addresses (and flattens a proxied CNAME away entirely), "and neither is a
// propagation delay". Until 2026-09-25 that knowledge only fed a "set it to DNS
// only" hint in the connect flow, while the post-connect re-check
// (apps/web/src/worker/jobs/connection-recheck.ts) read a flattened CNAME as a
// deleted one: status.getuptimely.com — orange-clouded, serving 200 — sat
// `broken` from 2026-08-14 on, and its integrator was sent connection.failed
// for a domain that worked.
//
// The classifier is pure (addresses in, provider out; CIDR math on bigints) so
// it is tested without a network. This module is server-side all the same —
// it imports verify.ts, and with it node:dns; a client needing only the
// provider labels reads `@dodomain/core/cdn-proxy-ranges`. The
// observation (`detectCdnProxy`) reads A + AAAA from the zone's AUTHORITATIVE
// nameservers through verify.ts's own seams — the same zone walk, NS→A pin and
// bounded resolvers record verification uses (dns-defaults.ts), so a black-holed
// nameserver costs this lookup exactly what it costs a verify, and a test
// injects the same fake resolver it already injects there.

import {
  CDN_PROXY_PROVIDERS,
  CDN_PROXY_RANGES,
  type CdnProxyProvider,
  type CdnProxyRangeSnapshot,
} from "./cdn-proxy-ranges.ts";
import { lookupRecordAnswers, resolveZoneAuthority, type VerifyDeps } from "./verify.ts";

type IpFamily = 4 | 6;

interface ParsedAddress {
  family: IpFamily;
  value: bigint;
}

interface ParsedCidr extends ParsedAddress {
  prefix: number;
}

const FAMILY_BITS: Record<IpFamily, number> = { 4: 32, 6: 128 };

function parseIpv4(text: string): bigint | null {
  const parts = text.split(".");
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = (value << 8n) | BigInt(octet);
  }
  return value;
}

function parseHexGroups(text: string): bigint[] | null {
  if (text === "") return [];
  const groups: bigint[] = [];
  const parts = text.split(":");
  for (const [index, part] of parts.entries()) {
    // An embedded dotted quad (`::ffff:192.0.2.1`) may only be the LAST part,
    // and stands for two 16-bit groups.
    if (index === parts.length - 1 && part.includes(".")) {
      const v4 = parseIpv4(part);
      if (v4 === null) return null;
      groups.push(v4 >> 16n, v4 & 0xffffn);
      continue;
    }
    if (!/^[0-9a-f]{1,4}$/i.test(part)) return null;
    groups.push(BigInt(`0x${part}`));
  }
  return groups;
}

function parseIpv6(text: string): bigint | null {
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const head = parseHexGroups(halves[0]!);
  const tail = halves.length === 2 ? parseHexGroups(halves[1]!) : [];
  if (head === null || tail === null) return null;
  const present = head.length + tail.length;
  // Without `::` the address must spell all eight groups; with it, `::` must
  // stand for at least one zero group.
  if (halves.length === 1 ? present !== 8 : present > 7) return null;
  const groups = [...head, ...Array<bigint>(8 - present).fill(0n), ...tail];
  return groups.reduce((acc, group) => (acc << 16n) | group, 0n);
}

/** Parse a literal IPv4/IPv6 address; null for anything else (a hostname, garbage). */
function parseAddress(text: string): ParsedAddress | null {
  const trimmed = text.trim();
  if (trimmed.includes(":")) {
    const value = parseIpv6(trimmed);
    return value === null ? null : { family: 6, value };
  }
  const value = parseIpv4(trimmed);
  return value === null ? null : { family: 4, value };
}

/**
 * Parse `address/prefix`. THROWS on anything malformed: the only CIDRs this
 * module reads are the committed snapshot (or a test's), and a snapshot entry
 * that silently matched nothing would quietly send proxied connections back to
 * `broken` — the exact defect this module exists to close.
 */
function parseCidr(cidr: string): ParsedCidr {
  const [address, prefixText, extra] = cidr.split("/");
  const parsed = address === undefined ? null : parseAddress(address);
  const prefix = Number(prefixText);
  if (
    parsed === null ||
    extra !== undefined ||
    prefixText === undefined ||
    !/^\d{1,3}$/.test(prefixText) ||
    prefix > FAMILY_BITS[parsed.family]
  ) {
    throw new Error(`cdn-proxy: malformed CIDR in the proxy range snapshot: "${cidr}"`);
  }
  return { ...parsed, prefix };
}

function cidrContains(cidr: ParsedCidr, address: ParsedAddress): boolean {
  if (cidr.family !== address.family) return false;
  const shift = BigInt(FAMILY_BITS[cidr.family] - cidr.prefix);
  return cidr.value >> shift === address.value >> shift;
}

/**
 * Which CDN proxy, if any, a name's observed address answers belong to.
 *
 * Returns a provider only when EVERY address is inside that provider's
 * published ranges: one address outside them means at least part of the
 * traffic goes somewhere we can see, so "hidden behind a proxy" is not an
 * honest reading. An empty answer is `null` — a name with no addresses is not
 * proxied, it is absent. A non-literal answer (a hostname) matches nothing.
 *
 * `ranges` defaults to the committed snapshot; tests pass their own. Every
 * range is parsed on every call (a couple of dozen CIDRs — negligible beside
 * the DNS round trip that produced `addresses`), so a malformed snapshot entry
 * throws here rather than silently matching nothing.
 */
export function classifyCdnProxy(
  addresses: readonly string[],
  ranges: Record<CdnProxyProvider, CdnProxyRangeSnapshot> = CDN_PROXY_RANGES,
): CdnProxyProvider | null {
  if (addresses.length === 0) return null;
  const parsed = addresses.map(parseAddress);
  for (const provider of CDN_PROXY_PROVIDERS) {
    const snapshot = ranges[provider];
    const cidrs = [...snapshot.ipv4, ...snapshot.ipv6].map(parseCidr);
    const allInside = parsed.every(
      (address) => address !== null && cidrs.some((cidr) => cidrContains(cidr, address)),
    );
    if (allInside) return provider;
  }
  return null;
}

/**
 * What one name's authoritative A + AAAA answers say about a proxy in front of it.
 *   - "proxied": every address is a known CDN edge (`classifyCdnProxy`).
 *   - "not_proxied": the lookups completed and the name is NOT (only) behind a
 *     known proxy — including answering no addresses at all.
 *   - "unknown": a lookup did not complete (DNS error, or the zone's own
 *     nameservers could not be reached) — we learned nothing, and a caller
 *     must not read it as either of the above.
 */
export type CdnProxyObservation =
  | { kind: "proxied"; provider: CdnProxyProvider; addresses: string[] }
  | { kind: "not_proxied"; addresses: string[] }
  | { kind: "unknown"; code: string };

export interface CdnProxyDetectDeps extends VerifyDeps {
  /** The proxy ranges to classify against. Default: the committed snapshot. */
  ranges?: Record<CdnProxyProvider, CdnProxyRangeSnapshot>;
}

/**
 * Observe whether `fqdn` currently answers from a CDN proxy, asking the zone's
 * authoritative nameservers for its A and AAAA records.
 *
 * Authoritative, not the public resolver, for the same reason verification is:
 * a proxied name's edge addresses are what its own nameservers publish, and a
 * recursive cache can still hold the pre-proxy answer.
 */
export async function detectCdnProxy(
  fqdn: string,
  deps: CdnProxyDetectDeps = {},
): Promise<CdnProxyObservation> {
  const { authoritative } = await resolveZoneAuthority(fqdn, deps);
  if (authoritative.kind !== "resolver") {
    return {
      kind: "unknown",
      code: authoritative.kind === "ns_unresolvable" ? "NS_UNRESOLVABLE" : authoritative.code,
    };
  }
  const [v4, v6] = await Promise.all([
    lookupRecordAnswers(authoritative.resolver, fqdn, "A"),
    lookupRecordAnswers(authoritative.resolver, fqdn, "AAAA"),
  ]);
  if (v4.kind === "error") return { kind: "unknown", code: v4.code };
  if (v6.kind === "error") return { kind: "unknown", code: v6.code };
  const addresses = [
    ...(v4.kind === "records" ? v4.records : []),
    ...(v6.kind === "records" ? v6.records : []),
  ];
  const provider = classifyCdnProxy(addresses, deps.ranges);
  return provider === null
    ? { kind: "not_proxied", addresses }
    : { kind: "proxied", provider, addresses };
}
