// Cloudflare DNS writes using the OAuth-issued access token.
//
// IMPORTANT: every call here uses the *OAuth* bearer token obtained through user
// consent — NOT an admin API key. That is the whole point of the proof: the grant
// the user approved is what authorizes the record write.

import { CF_API_BASE } from "./config.ts";
import { describeField, readField } from "./upstream-json.ts";
import {
  caaAnswer,
  recordValueMatches,
  srvAnswer,
  type RecordType,
} from "../record-capabilities.ts";

export class CfDnsError extends Error {}
export class CfZoneNotFoundError extends CfDnsError {}

interface CfEnvelope<T> {
  success: boolean;
  result: T;
  errors?: Array<{ code: number; message: string }>;
}

interface ApiInput {
  token: string;
  method: "GET" | "POST" | "DELETE" | "PATCH" | "PUT";
  path: string;
  query?: Record<string, string>;
  body?: unknown;
  fetchImpl?: typeof fetch;
}

async function cfApi<T>(input: ApiInput): Promise<CfEnvelope<T>> {
  const doFetch = input.fetchImpl ?? fetch;
  const url = new URL(CF_API_BASE + input.path);
  for (const [k, v] of Object.entries(input.query ?? {})) url.searchParams.set(k, v);
  const res = await doFetch(url.toString(), {
    method: input.method,
    headers: {
      authorization: `Bearer ${input.token}`,
      "content-type": "application/json",
      accept: "application/json",
    },
    body: input.body === undefined ? undefined : JSON.stringify(input.body),
  });
  const text = await res.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new CfDnsError(
      `Cloudflare API returned non-JSON (HTTP ${res.status}): ${text.slice(0, 200)}`,
    );
  }
  if (!res.ok || readField(json, "success") === false) {
    const rawErrors = readField(json, "errors");
    const msg =
      (Array.isArray(rawErrors) ? rawErrors : [])
        .map(
          (e: unknown) =>
            `${describeField(readField(e, "code"))}: ${describeField(readField(e, "message"))}`,
        )
        .join("; ") || `HTTP ${res.status}`;
    throw new CfDnsError(`Cloudflare API error: ${msg}`);
  }
  // Cloudflare's envelope is not validated field-by-field here: the shape of
  // `result` is per-endpoint and every caller below re-reads it defensively.
  return json as CfEnvelope<T>;
}

/**
 * Resolve the zone id for a domain (requires zone.read).
 *
 * Cloudflare zones are the *registrable* domain (e.g. `getuptimely.com`), never a
 * subdomain. So we accept a hostname and walk up the labels until we hit a zone the
 * token can see: `test.getuptimely.com` -> `getuptimely.com`.
 */
export async function resolveZoneId(
  token: string,
  domain: string,
  fetchImpl?: typeof fetch,
): Promise<string> {
  const labels = domain.split(".").filter(Boolean);
  for (let i = 0; i + 1 < labels.length; i++) {
    const candidate = labels.slice(i).join(".");
    const env = await cfApi<Array<{ id: string; name: string }>>({
      token,
      method: "GET",
      path: "/zones",
      query: { name: candidate },
      fetchImpl,
    });
    if (env.result?.[0]) return env.result[0].id;
  }
  throw new CfZoneNotFoundError(
    `no Cloudflare zone found for "${domain}". The account you approved doesn't have that domain. ` +
      `Use the root domain (e.g. getuptimely.com), or a domain that lives in the approved Cloudflare account.`,
  );
}

export interface DnsRecordInput {
  // FIX(F-002 hop 3): was "CNAME" | "TXT" | "A" — Cloudflare's DNS API writes
  // all RECORD_TYPES; the narrower union was the defect (WRITABLE in
  // cf/callback), not a Cloudflare limitation.
  type: RecordType;
  /** fully-qualified name, e.g. dodomain-poc.devino.ca */
  name: string;
  content: string;
  ttl?: number;
  proxied?: boolean;
  /** MX preference — Cloudflare REQUIRES this when type === "MX". */
  priority?: number;
  /**
   * The structured value Cloudflare models SRV and CAA with: sent INSTEAD of
   * `content` (Cloudflare's create examples send `data` alone for both).
   */
  data?: CloudflareSrvData | CloudflareCaaData;
}

/** Cloudflare's SRV `data` object (its DNS records API, type SRV). */
export interface CloudflareSrvData {
  priority: number;
  weight: number;
  port: number;
  target: string;
}

/** Cloudflare's CAA `data` object (its DNS records API, type CAA). */
export interface CloudflareCaaData {
  flags: number;
  tag: string;
  value: string;
}

/**
 * The Cloudflare write body's value fields for one session record: `data` for
 * SRV and CAA, `content` for every other type. The ONE place a session record
 * (record-capabilities.ts: SRV `value` = target, CAA `value` = property value)
 * is mapped onto Cloudflare's per-type shapes.
 */
export function cloudflareValueFields(rec: {
  type: RecordType;
  value: string;
  priority?: number;
  weight?: number;
  port?: number;
  flags?: number;
  tag?: string;
}): { content: string; data?: CloudflareSrvData | CloudflareCaaData; priority?: number } {
  if (rec.type === "SRV") {
    if (rec.priority === undefined || rec.weight === undefined || rec.port === undefined) {
      throw new Error("Cloudflare SRV write: priority, weight and port are required");
    }
    return {
      content: rec.value,
      data: { priority: rec.priority, weight: rec.weight, port: rec.port, target: rec.value },
    };
  }
  if (rec.type === "CAA") {
    if (rec.flags === undefined || rec.tag === undefined) {
      throw new Error("Cloudflare CAA write: flags and tag are required");
    }
    return { content: rec.value, data: { flags: rec.flags, tag: rec.tag, value: rec.value } };
  }
  return { content: rec.value, ...(rec.priority !== undefined ? { priority: rec.priority } : {}) };
}

/**
 * One listed Cloudflare record as the answer string record-capabilities.ts
 * compares: SRV and CAA in their composite spelling (`srvAnswer`/`caaAnswer`),
 * read from `data` when Cloudflare returns it and otherwise from `content`
 * (SRV `content` is "weight port target" with `priority` beside it; CAA
 * `content` is already `flags tag "value"`). Every other type is `content`.
 */
export function cloudflareRecordAnswer(type: string, rec: ListedRecord): string {
  if (type === "SRV") {
    const d = rec.data as Partial<CloudflareSrvData> | undefined;
    if (
      d?.priority !== undefined &&
      d.weight !== undefined &&
      d.port !== undefined &&
      d.target !== undefined
    ) {
      return srvAnswer({ priority: d.priority, weight: d.weight, port: d.port, target: d.target });
    }
    return `${rec.priority ?? ""} ${rec.content}`.trim();
  }
  if (type === "CAA") {
    const d = rec.data as Partial<CloudflareCaaData> | undefined;
    if (d?.flags !== undefined && d.tag !== undefined && d.value !== undefined) {
      return caaAnswer({ flags: d.flags, tag: d.tag, value: d.value });
    }
  }
  return rec.content;
}

export interface DnsRecord {
  id: string;
  type: string;
  name: string;
  content: string;
}

/** Create a DNS record (requires dns.write). Returns the created record. */
export async function createRecord(
  token: string,
  zoneId: string,
  rec: DnsRecordInput,
  fetchImpl?: typeof fetch,
): Promise<DnsRecord> {
  const env = await cfApi<DnsRecord>({
    token,
    method: "POST",
    path: `/zones/${zoneId}/dns_records`,
    body: {
      type: rec.type,
      name: rec.name,
      // SRV/CAA travel as Cloudflare's structured `data`, never as `content`.
      ...(rec.data !== undefined ? { data: rec.data } : { content: rec.content }),
      ttl: rec.ttl ?? 120,
      proxied: rec.proxied ?? false,
      // FIX(F-002 hop 3): forward priority when present — Cloudflare requires
      // it on MX records; the old code never sent it.
      ...(rec.priority !== undefined ? { priority: rec.priority } : {}),
    },
    fetchImpl,
  });
  return env.result;
}

/**
 * Rewrite an EXISTING record's content in place (requires dns.write).
 *
 * The only in-place write DoDomain performs: apply.ts is otherwise strictly
 * non-destructive (an existing record is left alone and reported as a conflict).
 * SPF is the documented exception — a zone may hold only one `v=spf1` record
 * (RFC 7208 §3.2), so "add our include" HAS to edit the record that is there.
 *
 * PATCH, and only `content` is sent: Cloudflare leaves every field the body
 * omits as it was, so the zone's TTL, proxied flag and comment survive an edit
 * we never asked to make. `type`/`name` travel purely as a sanity echo of the
 * record we listed.
 */
export async function updateRecordContent(
  token: string,
  zoneId: string,
  recordId: string,
  rec: { type: RecordType; name: string; content: string },
  fetchImpl?: typeof fetch,
): Promise<DnsRecord> {
  const env = await cfApi<DnsRecord>({
    token,
    method: "PATCH",
    path: `/zones/${zoneId}/dns_records/${recordId}`,
    body: { type: rec.type, name: rec.name, content: rec.content },
    fetchImpl,
  });
  return env.result;
}

/** A record as read back from Cloudflare's list endpoint — everything the apply
 * orchestrator needs to value-match against what a session requested. */
export interface ListedRecord {
  id: string;
  content: string;
  priority?: number;
  proxied?: boolean;
  /** The structured value Cloudflare returns for SRV/CAA (and other data types). */
  data?: Record<string, unknown>;
}

/**
 * List ALL records of a type at a name. A name can legitimately hold several
 * records of one type (TXT tokens, MX exchanges, round-robin A/AAAA) —
 * `findRecordId`/`verifyRecordViaApi`'s `result[0]` reads were blind to every
 * record but Cloudflare's first, which made an apex TXT verification token
 * unwritable (a pre-existing SPF record both suppressed the create and failed
 * the read-back). The apply orchestrator (apply.ts) decides off the FULL list.
 */
export async function listRecords(
  token: string,
  zoneId: string,
  type: string,
  name: string,
  fetchImpl?: typeof fetch,
): Promise<ListedRecord[]> {
  const env = await cfApi<ListedRecord[]>({
    token,
    method: "GET",
    path: `/zones/${zoneId}/dns_records`,
    query: { type, name },
    fetchImpl,
  });
  return env.result ?? [];
}

/** Find an existing record id by type+name (used for idempotent cleanup). */
export async function findRecordId(
  token: string,
  zoneId: string,
  type: string,
  name: string,
  fetchImpl?: typeof fetch,
): Promise<string | null> {
  const env = await cfApi<Array<{ id: string }>>({
    token,
    method: "GET",
    path: `/zones/${zoneId}/dns_records`,
    query: { type, name },
    fetchImpl,
  });
  return env.result?.[0]?.id ?? null;
}

/**
 * Verify a record by reading it back from Cloudflare's API — the *source of truth*.
 *
 * Why this exists (per Amin's note): on Cloudflare, proxied A/CNAME/AAAA records
 * resolve to Cloudflare's proxy IPs on public DNS, so you canNOT confirm the real
 * value with a public DNS query. Because the OAuth grant already gave us `zone.read`,
 * we read the record straight from the API instead — which works even when the record
 * is proxied. (TXT records are never proxied, so those stay publicly verifiable too.)
 */
export async function verifyRecordViaApi(
  token: string,
  zoneId: string,
  type: string,
  name: string,
  expect: string,
  /** Expected MX preference. When set, `match` also requires the read-back
   * record's own priority to equal it (a record applied with the wrong
   * preference must not match). Ignored for non-MX types. */
  expectPriority?: number,
  fetchImpl?: typeof fetch,
): Promise<{ present: boolean; match: boolean; value: string | null; proxied: boolean }> {
  // Cloudflare returns MX `content` as the exchange only, with `priority` a
  // separate top-level field — symmetric with how createRecord() writes it.
  //
  // Scan ALL records at type+name, not `result[0]` (the multi-record fix): a
  // name legitimately holds several records of one type — an apex's TXT bag
  // (SPF + site verifications + our token), multiple MX exchanges — and the
  // old first-record read reported match:false whenever OUR record wasn't the
  // one Cloudflare happened to list first. `match` is true when ANY record's
  // value matches, mirroring verify.ts's DNS-path `.some()` semantics.
  const records = await listRecords(token, zoneId, type, name, fetchImpl);
  // `expect` is the record's expected ANSWER (record-capabilities.ts
  // expectedAnswerFor): the composite for SRV/CAA, so the listed record is
  // spelled the same way before comparing.
  const matched = records.find((rec) =>
    recordValueMatches(type, expect, cloudflareRecordAnswer(type, rec), {
      expectedPriority: expectPriority,
      actualPriority: rec.priority,
    }),
  );
  const shown = matched ?? records[0];
  return {
    present: records.length > 0,
    // D-001: value-match, not raw ===. Uses the ONE shared matcher
    // (record-capabilities.ts) so this read-back path and verify.ts's
    // authoritative-DNS path normalize identically (host-like/TXT/MX-priority).
    match: Boolean(matched),
    // The matched record's value when live; otherwise the first record's value
    // so a CONFLICT notice can show what actually disagrees (null when absent).
    value: shown ? cloudflareRecordAnswer(type, shown) : null,
    proxied: Boolean(shown?.proxied),
  };
}

/** Delete a DNS record (reversibility — the test record is removed after proof). */
export async function deleteRecord(
  token: string,
  zoneId: string,
  recordId: string,
  fetchImpl?: typeof fetch,
): Promise<void> {
  await cfApi({
    token,
    method: "DELETE",
    path: `/zones/${zoneId}/dns_records/${recordId}`,
    fetchImpl,
  });
}
