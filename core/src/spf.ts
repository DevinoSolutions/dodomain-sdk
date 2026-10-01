// SPF (RFC 7208) checker — the engine behind the public SPF tool
// (dodomain.io/tools/spf-checker, OPPORTUNITIES Tier-1 #1).
//
// What it decides, and what it deliberately does not:
//   - Finds the domain's `v=spf1` record(s) (TXT at the apex-or-host asked for)
//     and parses every term into a mechanism / modifier with its qualifier.
//   - Counts the DNS-querying terms (include, a, mx, ptr, exists, redirect)
//     RECURSIVELY through include:/redirect= — the RFC's 10-lookup limit is the
//     single most common reason a working-looking record fails at receivers.
//   - Names structural faults a receiver will PERMERROR on: no record, more
//     than one record, an unknown term, `all` not last, a redirect alongside
//     `all` (ignored by the RFC), an include whose target has no SPF record.
//   - Flags weak policies (`+all`, `?all`, no `all` at all) and `ptr` (deprecated).
//   - Does NOT evaluate a sender IP against the record. That is what a receiver
//     does per message; a checker that pretends to know the verdict for a mail
//     it never saw would be inventing an answer.
//
// HONESTY: every DNS read can fail; a failed read is reported as `unchecked`
// on the term that needed it (and stops the count there), never folded into a
// "pass". A lookup count computed from partial data says so.
//
// Framework-free: DNS arrives through `SpfDeps.resolveTxt` (the same seam
// shape as DiscoveryDeps / DetectDeps); the default is the bounded
// node:dns/promises Resolver verify.ts uses.

import { NODATA, NOTFOUND } from "node:dns";
import { boundedResolver } from "./dns-defaults.ts";
import {
  SPF_DNS_LOOKUP_LIMIT,
  SPF_MECHANISMS,
  type SpfAnalysis,
  type SpfIssue,
  type SpfMechanismName,
  type SpfQualifier,
  type SpfTerm,
} from "./spf-types.ts";

/** How deep include:/redirect= chains are followed. The lookup limit bounds breadth; this bounds a pathological loop. */
const MAX_INCLUDE_DEPTH = 10;

export interface SpfDeps {
  /** TXT lookup; default: a bounded node:dns/promises Resolver on the system's nameservers. */
  resolveTxt?: (host: string) => Promise<string[][]>;
  dnsTimeoutMs?: number;
  dnsTries?: number;
}

/** The mechanism names that cost a DNS query (RFC 7208 §4.6.4). `redirect` is a modifier and counted separately. */
const DNS_QUERYING_MECHANISMS: ReadonlySet<SpfMechanismName> = new Set([
  "include",
  "a",
  "mx",
  "ptr",
  "exists",
]);

/** RFC 7208 §3.2 practical ceiling: a single TXT RR beyond ~450 octets tends to be truncated/refused. */
const RECORD_LENGTH_WARN = 450;

const SPF_VERSION_TAG = /^v=spf1(\s|$)/i;

function isSpfRecord(txt: string): boolean {
  return SPF_VERSION_TAG.test(txt);
}

/** Parse one SPF record body (after `v=spf1`) into terms. Pure; exported for the unit test. */
export function parseSpfTerms(record: string): SpfTerm[] {
  const body = record.replace(SPF_VERSION_TAG, "").trim();
  if (body === "") return [];
  return body.split(/\s+/).map((raw): SpfTerm => {
    const modifier = /^([a-z][a-z0-9_.-]*)=(.*)$/i.exec(raw);
    if (modifier) {
      return { kind: "modifier", name: modifier[1]!.toLowerCase(), value: modifier[2]!, raw };
    }
    const mechanism = /^([+\-~?])?([a-z0-9]+)(?:[:/](.*))?$/i.exec(raw);
    if (!mechanism) return { kind: "unknown", raw };
    const name = mechanism[2]!.toLowerCase();
    if (!(SPF_MECHANISMS as readonly string[]).includes(name)) return { kind: "unknown", raw };
    const separator = raw.charAt((mechanism[1] ?? "").length + name.length);
    const tail = mechanism[3];
    // `a/24` keeps its slash (a CIDR on the current domain); `include:x` drops the colon.
    const argument = tail === undefined ? null : separator === "/" ? `/${tail}` : tail;
    return {
      kind: "mechanism",
      qualifier: (mechanism[1] as SpfQualifier | undefined) ?? "+",
      name: name as SpfMechanismName,
      argument,
      raw,
    };
  });
}

/** The domain an `include:`/`exists:`/`a:`/`mx:` argument names (CIDR stripped); null when the argument carries only a CIDR. */
function targetDomainOf(argument: string | null): string | null {
  if (argument === null || argument.startsWith("/")) return null;
  const host = argument.split("/")[0]!.trim().replace(/\.$/, "").toLowerCase();
  return host === "" ? null : host;
}

type TxtRead =
  | { kind: "records"; records: string[] }
  | { kind: "absent" }
  | {
      kind: "error";
      code: string;
    };

async function readSpfRecords(
  domain: string,
  resolveTxt: NonNullable<SpfDeps["resolveTxt"]>,
): Promise<TxtRead> {
  try {
    const answers = await resolveTxt(domain);
    const records = answers.map((parts) => parts.join("")).filter(isSpfRecord);
    return { kind: "records", records };
  } catch (e) {
    const code = (e as NodeJS.ErrnoException)?.code ?? "UNKNOWN";
    if (code === NOTFOUND || code === NODATA) return { kind: "absent" };
    return { kind: "error", code };
  }
}

/**
 * Analyze the SPF policy published at `domain`.
 *
 * The recursive walk follows every `include:` and `redirect=` it can reach
 * within the lookup budget, so `dnsLookups` is what a receiver would actually
 * count. A term whose target could not be read leaves `complete: false` and an
 * `unchecked` issue naming it; the count is then a lower bound, and the
 * analysis says so instead of rounding it to a verdict.
 */
export async function analyzeSpf(domain: string, deps: SpfDeps = {}): Promise<SpfAnalysis> {
  const resolveTxt =
    deps.resolveTxt ??
    ((host: string) => boundedResolver(deps.dnsTimeoutMs, deps.dnsTries).resolveTxt(host));

  const name = domain.trim().replace(/\.$/, "").toLowerCase();
  const issues: SpfIssue[] = [];
  const visited: string[] = [];
  // Every domain whose record has been walked, the root included — the loop
  // guard. `visited` above is the reported include/redirect list and stays
  // root-free on purpose.
  const walked = new Set<string>([name]);
  let dnsLookups = 0;
  let complete = true;

  const read = await readSpfRecords(name, resolveTxt);
  if (read.kind === "error") {
    issues.push({
      code: "unchecked",
      severity: "info",
      domain: name,
      term: null,
      note: `The TXT lookup for ${name} did not complete (${read.code}) — nothing below is a verdict.`,
    });
    return {
      domain: name,
      records: [],
      terms: [],
      allQualifier: null,
      dnsLookups: 0,
      complete: false,
      visited,
      issues,
    };
  }
  const records = read.kind === "records" ? read.records : [];
  if (records.length === 0) {
    issues.push({
      code: "no_record",
      severity: "error",
      domain: name,
      term: null,
      note: `${name} publishes no v=spf1 record. Receivers treat mail from it as having no SPF policy, and DMARC cannot align on SPF.`,
    });
    return {
      domain: name,
      records,
      terms: [],
      allQualifier: null,
      dnsLookups: 0,
      complete: true,
      visited,
      issues,
    };
  }
  if (records.length > 1) {
    issues.push({
      code: "multiple_records",
      severity: "error",
      domain: name,
      term: null,
      note: `${name} publishes ${records.length} v=spf1 records. RFC 7208 §3.2 requires exactly one — receivers return permerror and the policy is ignored.`,
    });
  }
  const record = records[0]!;
  if (record.length > RECORD_LENGTH_WARN) {
    issues.push({
      code: "record_too_long",
      severity: "warning",
      domain: name,
      term: null,
      note: `The record is ${record.length} characters; beyond ~${RECORD_LENGTH_WARN} some resolvers truncate the TXT answer. Move mechanisms behind an include: to shorten it.`,
    });
  }

  const terms = parseSpfTerms(record);
  let allQualifier: SpfQualifier | null = null;

  // The recursive walk. Returns the `all` qualifier reached through redirect=
  // (a redirect hands the whole evaluation to the target, RFC 7208 §6.1).
  const walk = async (
    zone: string,
    zoneTerms: SpfTerm[],
    depth: number,
  ): Promise<SpfQualifier | null> => {
    let sawAll: SpfQualifier | null = null;
    let redirectTo: string | null = null;
    let afterAll = false;

    for (const term of zoneTerms) {
      if (term.kind === "unknown") {
        issues.push({
          code: "unknown_term",
          severity: "error",
          domain: zone,
          term: term.raw,
          note: `"${term.raw}" is not a valid SPF mechanism or modifier — receivers return permerror for the whole record.`,
        });
        continue;
      }
      if (term.kind === "modifier") {
        if (term.name === "redirect") redirectTo = targetDomainOf(term.value);
        continue;
      }
      if (afterAll) {
        issues.push({
          code: "terms_after_all",
          severity: "warning",
          domain: zone,
          term: term.raw,
          note: `"${term.raw}" comes after "all" and is never evaluated.`,
        });
        continue;
      }
      if (term.name === "all") {
        sawAll = term.qualifier;
        afterAll = true;
        continue;
      }
      if (term.name === "ptr") {
        issues.push({
          code: "ptr_mechanism",
          severity: "warning",
          domain: zone,
          term: term.raw,
          note: `"ptr" is deprecated (RFC 7208 §5.5): slow, unreliable, and some receivers skip it. Replace it with ip4:/ip6:/a:/mx:.`,
        });
      }
      if (DNS_QUERYING_MECHANISMS.has(term.name)) {
        dnsLookups += 1;
        if (term.name === "include") {
          const target = targetDomainOf(term.argument);
          if (target === null) {
            issues.push({
              code: "unknown_term",
              severity: "error",
              domain: zone,
              term: term.raw,
              note: `"${term.raw}" names no domain to include.`,
            });
            continue;
          }
          if (walked.has(target) || depth >= MAX_INCLUDE_DEPTH) continue;
          walked.add(target);
          visited.push(target);
          const nested = await readSpfRecords(target, resolveTxt);
          if (nested.kind === "error") {
            complete = false;
            issues.push({
              code: "unchecked",
              severity: "info",
              domain: target,
              term: term.raw,
              note: `The include target ${target} could not be read (${nested.code}); the lookup count below it is unknown.`,
            });
            continue;
          }
          const nestedRecords = nested.kind === "records" ? nested.records : [];
          if (nestedRecords.length === 0) {
            issues.push({
              code: "include_target_missing",
              severity: "error",
              domain: zone,
              term: term.raw,
              note: `${target} publishes no v=spf1 record, so "${term.raw}" makes receivers return permerror.`,
            });
            continue;
          }
          if (nestedRecords.length > 1) {
            issues.push({
              code: "multiple_records",
              severity: "error",
              domain: target,
              term: term.raw,
              note: `${target} (included from ${zone}) publishes ${nestedRecords.length} v=spf1 records — permerror at receivers.`,
            });
          }
          // An include's own `all` never decides the outer record (§5.2) — walked for its lookups only.
          await walk(target, parseSpfTerms(nestedRecords[0]!), depth + 1);
        }
      }
    }

    if (redirectTo !== null) {
      if (sawAll !== null) {
        issues.push({
          code: "redirect_ignored",
          severity: "warning",
          domain: zone,
          term: `redirect=${redirectTo}`,
          note: `"redirect=" is ignored when the record also has an "all" mechanism (RFC 7208 §6.1).`,
        });
        return sawAll;
      }
      dnsLookups += 1;
      if (walked.has(redirectTo) || depth >= MAX_INCLUDE_DEPTH) return null;
      walked.add(redirectTo);
      visited.push(redirectTo);
      const redirected = await readSpfRecords(redirectTo, resolveTxt);
      if (redirected.kind === "error") {
        complete = false;
        issues.push({
          code: "unchecked",
          severity: "info",
          domain: redirectTo,
          term: `redirect=${redirectTo}`,
          note: `The redirect target ${redirectTo} could not be read (${redirected.code}).`,
        });
        return null;
      }
      const redirectedRecords = redirected.kind === "records" ? redirected.records : [];
      if (redirectedRecords.length === 0) {
        issues.push({
          code: "include_target_missing",
          severity: "error",
          domain: zone,
          term: `redirect=${redirectTo}`,
          note: `${redirectTo} publishes no v=spf1 record, so the redirect makes receivers return permerror.`,
        });
        return null;
      }
      return walk(redirectTo, parseSpfTerms(redirectedRecords[0]!), depth + 1);
    }
    return sawAll;
  };

  allQualifier = await walk(name, terms, 0);

  if (allQualifier === null) {
    issues.push({
      code: "no_all",
      severity: "warning",
      domain: name,
      term: null,
      note: `The record ends without an "all" mechanism, so any sender it does not list gets a neutral result rather than a fail. End it with "~all" or "-all".`,
    });
  } else if (allQualifier === "+") {
    issues.push({
      code: "all_pass",
      severity: "error",
      domain: name,
      term: "+all",
      note: `"+all" authorizes every host on the internet to send as ${name}. Use "~all" or "-all".`,
    });
  } else if (allQualifier === "?") {
    issues.push({
      code: "all_neutral",
      severity: "warning",
      domain: name,
      term: "?all",
      note: `"?all" makes SPF neutral for unlisted senders — no protection, and nothing for DMARC to align on. Prefer "~all" or "-all".`,
    });
  }

  if (dnsLookups > SPF_DNS_LOOKUP_LIMIT) {
    issues.push({
      code: "lookup_limit_exceeded",
      severity: "error",
      domain: name,
      term: null,
      note: `The record needs ${dnsLookups} DNS lookups; RFC 7208 allows ${SPF_DNS_LOOKUP_LIMIT}. Receivers return permerror for any sender whose check runs past the ${SPF_DNS_LOOKUP_LIMIT}th lookup; which senders that hits depends on their order in the record. Remove includes you no longer use, or replace one with the ip4:/ip6: ranges it resolves to.`,
    });
  }

  return { domain: name, records, terms, allQualifier, dnsLookups, complete, visited, issues };
}
