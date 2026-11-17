// Read-only diagnostics built on the same authoritative/public lookups,
// provider map, apex rules and proxy evidence as the connect engine.
import { apexOf } from "./apex.ts";
import { classifyCdnProxy } from "./cdn-proxy.ts";
import { dnsProviderForNameServers } from "./detect.ts";
import { boundedResolver, CNAME_CHAIN_MAX_DEPTH } from "./dns-defaults.ts";
import {
  lookupRecordAcrossResolvers,
  type DnsLookupDeps,
  type DnsLookupResult,
} from "./dns-lookup.ts";
import { guideFor } from "./guides.ts";
import {
  canonicalDnsAnswer,
  isProxyableRecordType,
  recordAnswerMatches,
  type LookupRecordType,
  type RecordType,
} from "./record-capabilities.ts";
import { diffExpectedRecord } from "./record-diff.ts";
import { PUBLIC_DNS_DIFF_MAX_RECORDS } from "./schemas.ts";
import { lookupRecordAnswers } from "./verify.ts";

export interface CnameChainResult {
  name: string;
  chain: Array<{ name: string; target: string; apex: boolean }>;
  terminalName: string;
  outcome: "complete" | "loop" | "depth_limit" | "error";
  maxDepth: number;
  apexCname: boolean;
  flattening: "suspected" | "not_observed" | "unknown";
  addresses: string[];
  proxyProvider: string | null;
  error?: string;
}

function normalizeName(name: string): string {
  return name.trim().replace(/\.$/, "").toLowerCase();
}

/** A finite chain of at most ten CNAME queries. Each hop resolves its own zone:
 * carrying the first hop's zone across a cross-provider alias would be wrong. */
export async function followCnameChain(
  name: string,
  deps: DnsLookupDeps = {},
): Promise<CnameChainResult> {
  const result: CnameChainResult = {
    name: normalizeName(name),
    chain: [],
    terminalName: normalizeName(name),
    outcome: "complete",
    maxDepth: CNAME_CHAIN_MAX_DEPTH,
    apexCname: false,
    flattening: "not_observed",
    addresses: [],
    proxyProvider: null,
  };
  const seen = new Set<string>();
  for (let depth = 0; depth < CNAME_CHAIN_MAX_DEPTH; depth += 1) {
    const current = result.terminalName;
    seen.add(current);
    const lookup = await lookupRecordAcrossResolvers(current, "CNAME", deps);
    if (lookup.authoritative.outcome === "error") {
      result.outcome = "error";
      result.error = lookup.authoritative.error ?? "UNKNOWN";
      result.flattening = "unknown";
      return result;
    }
    const target = lookup.authoritative.answers[0];
    if (!target) {
      const [v4, v6] = await Promise.all([
        lookupRecordAcrossResolvers(current, "A", deps),
        lookupRecordAcrossResolvers(current, "AAAA", deps),
      ]);
      if (v4.authoritative.outcome === "error" || v6.authoritative.outcome === "error") {
        result.outcome = "error";
        result.error = v4.authoritative.error ?? v6.authoritative.error ?? "UNKNOWN";
        result.flattening = "unknown";
      } else {
        result.addresses = [...v4.authoritative.answers, ...v6.authoritative.answers];
        result.proxyProvider = classifyCdnProxy(result.addresses);
        // DNS cannot reveal an ALIAS or a proxy's hidden origin. Address
        // answers without a CNAME at the terminal apex/proxy are evidence
        // consistent with flattening, never proof of a hidden CNAME.
        if (
          result.addresses.length > 0 &&
          (current === apexOf(current) ||
            (lookup.authoritative.outcome === "absent" && current === lookup.zone) ||
            result.proxyProvider !== null)
        ) {
          result.flattening = "suspected";
        }
      }
      return result;
    }
    // A recursive NS answer may follow this CNAME; lookup.zone equality alone
    // therefore is not apex evidence. Flag only the PSL registrable apex.
    // TODO(scope): a visible CNAME at a delegated apex needs independent NS
    // ownership proof. Absent-CNAME delegated apices are handled below by the
    // alias-aware zone walk plus authoritative absence evidence.
    const apex = current === apexOf(current);
    const normalizedTarget = normalizeName(target);
    result.chain.push({ name: current, target: normalizedTarget, apex });
    result.apexCname ||= apex;
    result.terminalName = normalizedTarget;
    if (seen.has(normalizedTarget)) {
      result.outcome = "loop";
      return result;
    }
  }
  result.outcome = "depth_limit";
  return result;
}

export interface VerifyDiagnoserInput {
  name: string;
  target: string;
  type?: RecordType;
}

export interface VerifyDiagnoserResult {
  name: string;
  target: string;
  type: RecordType;
  zone: string;
  provider: { id: string; label: string; fixUrl: string };
  reason:
    | "verified"
    | "propagation"
    | "wrong_host"
    | "trailing_dot"
    | "proxied"
    | "apex"
    | "wrong_target"
    | "absent"
    | "indeterminate";
  message: string;
  fixUrl: string;
  lookup: DnsLookupResult;
  wrongHost: string | null;
  proxyProvider: string | null;
}

/** Evidence, not guessed causes: only name wrong_host after observing the
 * expected value at an alternate host, and never call a DNS error absence. */
export async function diagnoseVerification(
  input: VerifyDiagnoserInput,
  deps: DnsLookupDeps = {},
): Promise<VerifyDiagnoserResult> {
  const name = normalizeName(input.name);
  const type = input.type ?? "CNAME";
  const lookup = await lookupRecordAcrossResolvers(name, type, deps);
  deps.signal?.throwIfAborted();
  const resolver = deps.resolver ?? boundedResolver(deps.dnsTimeoutMs, deps.dnsTries);
  const ns = await lookupRecordAnswers(resolver, lookup.zone, "NS");
  deps.signal?.throwIfAborted();
  const provider = dnsProviderForNameServers(ns.kind === "records" ? ns.records : []);
  const guide = guideFor(provider?.provider ?? "unknown");
  const fixUrl =
    guide.provider === "unknown"
      ? "/docs/guides/dns-providers"
      : `/docs/guides/dns-providers/${guide.provider}`;
  const result: VerifyDiagnoserResult = {
    name,
    target: input.target,
    type,
    zone: lookup.zone,
    provider: { id: guide.provider, label: guide.label, fixUrl },
    reason: "absent",
    message:
      "The expected record is absent at this host on authoritative DNS. Add it at the exact host shown.",
    fixUrl,
    lookup,
    wrongHost: null,
    proxyProvider: null,
  };
  if (lookup.authoritative.outcome === "error") {
    return {
      ...result,
      reason: "indeterminate",
      message:
        "Authoritative DNS did not answer successfully; a failed lookup cannot identify a verification problem.",
    };
  }
  const expected = { fqdn: name, type, expect: input.target };
  const diff = diffExpectedRecord(expected, lookup.authoritative.answers);
  if (diff.reason === "match") {
    const completed = lookup.public.filter((view) => view.outcome !== "error");
    if (
      completed.some(
        (view) => !view.answers.some((answer) => recordAnswerMatches(type, input.target, answer)),
      )
    ) {
      return {
        ...result,
        reason: "propagation",
        fixUrl: "/guides/dns-propagation-times",
        message:
          "The target is correct on authoritative DNS, but at least one public resolver still serves a different answer. Recheck after its cache expires.",
      };
    }
    if (completed.length !== lookup.public.length) {
      return {
        ...result,
        reason: "indeterminate",
        message:
          "Authoritative DNS matches, but a public resolver failed. Propagation could not be fully checked.",
      };
    }
    return {
      ...result,
      reason: "verified",
      message: "The expected target matches on authoritative DNS and all three public resolvers.",
    };
  }
  if (diff.reason === "trailing_dot_differs") {
    return {
      ...result,
      reason: "trailing_dot",
      message:
        "The published TXT value has a different trailing dot. TXT verification tokens are exact; copy the target verbatim. A trailing dot on a CNAME target is valid.",
    };
  }
  if (
    type === "CNAME" &&
    lookup.authoritative.answers.some((answer) =>
      recordAnswerMatches(
        "CNAME",
        `${canonicalDnsAnswer("CNAME", input.target)}.${lookup.zone}`,
        answer,
      ),
    )
  ) {
    return {
      ...result,
      reason: "trailing_dot",
      message: `The published CNAME target has ${lookup.zone} appended to the expected target. The provider may have treated it as relative; enter the full target using the provider's trailing-dot convention. A trailing dot on the correct target is valid.`,
    };
  }
  if (isProxyableRecordType(type)) {
    const [v4, v6] = await Promise.all([
      type === "A" ? lookup : lookupRecordAcrossResolvers(name, "A", deps),
      type === "AAAA" ? lookup : lookupRecordAcrossResolvers(name, "AAAA", deps),
    ]);
    if (v4.authoritative.outcome !== "error" && v6.authoritative.outcome !== "error") {
      result.proxyProvider = classifyCdnProxy([
        ...v4.authoritative.answers,
        ...v6.authoritative.answers,
      ]);
      if (result.proxyProvider)
        return {
          ...result,
          reason: "proxied",
          message:
            "The name answers only from known CDN proxy edges. The proxy hides the origin target; use DNS-only mode to verify the underlying record.",
        };
    }
  }
  // Two common, testable mistakes: full host entered into an auto-appending
  // provider panel, or a subdomain's target entered at the zone apex.
  const candidates = [
    ...new Set([`${name}.${lookup.zone}`, ...(name === lookup.zone ? [] : [lookup.zone])]),
  ].filter((candidate) => candidate.length <= 253);
  for (const candidate of candidates) {
    const alternate = await lookupRecordAcrossResolvers(candidate, type, deps);
    if (
      alternate.authoritative.outcome !== "error" &&
      alternate.authoritative.answers.some((answer) =>
        recordAnswerMatches(type, input.target, answer),
      )
    ) {
      return {
        ...result,
        reason: "wrong_host",
        wrongHost: candidate,
        message: `The expected target was found at ${candidate}, but not at ${name}. Correct the provider's host/name field.`,
      };
    }
  }
  if (
    type === "CNAME" &&
    (name === apexOf(name) || (lookup.authoritative.outcome === "absent" && name === lookup.zone))
  ) {
    return {
      ...result,
      reason: "apex",
      message:
        "This is a zone apex and the expected CNAME is not published. Standard CNAME records cannot coexist with the apex NS/SOA records; use a supported ALIAS/flattening setup or a subdomain. Flattening hides the CNAME target from DNS verification.",
    };
  }
  if (diff.reason !== "nothing_published") {
    return {
      ...result,
      reason: "wrong_target",
      message:
        "Authoritative DNS contains a different target at this host. Replace or correct the value; waiting for propagation will not change the authoritative record.",
    };
  }
  return result;
}

export interface DnsSnapshotRecord {
  name: string;
  type: LookupRecordType;
  value: string;
  ttl: number | null;
}
export interface DnsExpectedRecord {
  name: string;
  type: LookupRecordType;
  value: string;
  ttl?: number;
}
export interface DnsDiffResult {
  expected: DnsExpectedRecord[];
  snapshots: DnsLookupResult[];
  changes: Array<{
    name: string;
    type: LookupRecordType;
    kind: "added" | "removed" | "changed" | "ttl_only";
    expected: DnsSnapshotRecord | null;
    actual: DnsSnapshotRecord | null;
  }>;
  unchanged: number;
  ttlUnavailable: number;
  complete: boolean;
}

/** Compare only the supplied name/type pairs, not an undiscoverable whole
 * zone. One lookup per distinct pair, at most 25; nothing is stored. */
export async function compareDnsSnapshot(
  expected: DnsExpectedRecord[],
  deps: DnsLookupDeps = {},
): Promise<DnsDiffResult> {
  if (expected.length === 0 || expected.length > PUBLIC_DNS_DIFF_MAX_RECORDS)
    throw new RangeError(
      `Expected DNS records must contain between 1 and ${PUBLIC_DNS_DIFF_MAX_RECORDS} rows.`,
    );
  const groups = new Map<string, DnsExpectedRecord[]>();
  for (const record of expected) {
    const normalized = { ...record, name: normalizeName(record.name) };
    const key = `${normalized.name}\0${record.type}`;
    const group = groups.get(key) ?? [];
    if (
      !group.some(
        (item) =>
          canonicalDnsAnswer(record.type, item.value) ===
            canonicalDnsAnswer(record.type, record.value) && item.ttl === record.ttl,
      )
    )
      group.push(normalized);
    groups.set(key, group);
  }
  const result: DnsDiffResult = {
    expected: [...groups.values()].flat(),
    snapshots: [],
    changes: [],
    unchanged: 0,
    ttlUnavailable: 0,
    complete: true,
  };
  // Sequential groups bound simultaneous sockets on anonymous requests.
  for (const group of groups.values()) {
    const first = group[0]!;
    const snapshot = await lookupRecordAcrossResolvers(first.name, first.type, deps);
    result.snapshots.push(snapshot);
    if (snapshot.authoritative.outcome === "error") {
      result.complete = false;
      continue;
    }
    const actual = snapshot.authoritative.answers.map((value, index): DnsSnapshotRecord => ({
      name: first.name,
      type: first.type,
      value,
      ttl: snapshot.authoritative.records?.[index]?.ttl ?? null,
    }));
    const missing: DnsSnapshotRecord[] = [];
    for (const record of group) {
      const row: DnsSnapshotRecord = { ...record, ttl: record.ttl ?? null };
      const index = actual.findIndex(
        (item) =>
          canonicalDnsAnswer(row.type, item.value) === canonicalDnsAnswer(row.type, row.value),
      );
      if (index < 0) {
        missing.push(row);
        continue;
      }
      const found = actual.splice(index, 1)[0]!;
      if (row.ttl !== null && found.ttl === null) result.ttlUnavailable += 1;
      if (row.ttl !== null && found.ttl !== null && row.ttl !== found.ttl) {
        result.changes.push({
          name: row.name,
          type: row.type,
          kind: "ttl_only",
          expected: row,
          actual: found,
        });
      } else result.unchanged += 1;
    }
    // Pair unmatched values deterministically; residual values are additions
    // or removals relative to the pasted expected set.
    missing.sort((a, b) => a.value.localeCompare(b.value));
    actual.sort((a, b) => a.value.localeCompare(b.value));
    for (const row of missing) {
      const found = actual.shift() ?? null;
      result.changes.push({
        name: row.name,
        type: row.type,
        kind: found ? "changed" : "removed",
        expected: row,
        actual: found,
      });
    }
    for (const row of actual)
      result.changes.push({
        name: row.name,
        type: row.type,
        kind: "added",
        expected: null,
        actual: row,
      });
  }
  return result;
}
