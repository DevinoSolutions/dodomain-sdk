// Spaceship REST API (https://docs.spaceship.dev/), read from the published
// OpenAPI document on 2026-10-30. Base server: https://spaceship.dev/api/v1,
// authenticated by the X-API-Key + X-API-Secret header pair. The end user
// creates the key in Spaceship's API Manager with scopes they choose, pastes it
// into the hosted connect page, and this module uses it for ONE request.
//
// The credential boundary: the key and secret enter `applySpaceshipRecords` and
// leave only as two request headers to spaceship.dev. They are never returned,
// never put on an error (SpaceshipError carries a fixed stage and an HTTP status,
// nothing else, and never a cause), and never written anywhere: this file may
// not import persistence, logging or telemetry (scripts/check-spaceship-bans.sh).
import { domainToASCII } from "node:url";

import { apexOf } from "./apex.ts";
import { emailPolicyKindOf } from "./email-records.ts";
import {
  allowsCoexistingValues,
  isSpaceshipWritable,
  recordAnswerMatches,
  requiresPriority,
} from "./record-capabilities.ts";
import { fqdnFor, zoneRelativeName, zRecords, type SessionRecord } from "./records.ts";
import { z } from "./zod-runtime.ts";

export const SPACESHIP_API_ORIGIN = "https://spaceship.dev/api/v1";

/** The pasted credential, as the apply route receives it. Shape only: whether
 * Spaceship accepts it is decided by Spaceship. */
export interface SpaceshipCredentials {
  apiKey: string;
  apiSecret: string;
}

// The record write's TTL bounds, from the docs' `ttl` schema on every
// `*ResourceRecordCreateOrUpdateItem` ("minimum: 60, maximum: 3600").
const SPACESHIP_MIN_TTL = 60;
const SPACESHIP_MAX_TTL = 3600;
// GET /v1/dns/records/{domain}: `take` is required and accepts 1..500, but the
// documented 200 body caps `items` at maxItems 100, so pages are read 100 at a
// time. A zone we cannot read whole is refused (see readZone).
const SPACESHIP_PAGE_SIZE = 100;
const SPACESHIP_MAX_PAGES = 20;
const REQUEST_TIMEOUT_MS = 10_000;

/**
 * Where a Spaceship apply stopped.
 *
 * - `records`      the session's records cannot be written through this API.
 * - `credentials`  Spaceship answered 401: the key or secret is wrong or revoked.
 * - `scope`        Spaceship answered 403: the key lacks a scope a call needs.
 * - `ownership`    the domain is not in the key's Spaceship account (404 on
 *                  domain info, or a domain info naming another domain).
 * - `rate_limited` Spaceship answered 429.
 * - `read`         a read failed in transit or with a server error. Nothing was written.
 * - `unreadable`   the zone answered, but not in a shape we can read with confidence.
 * - `conflict`     existing records would be changed or contradicted, or
 *                  Spaceship's own conflict checker refused the write (422).
 * - `expired`      the session expired before the write was sent.
 * - `write`        the write failed in transit or with a server error. The zone
 *                  may have been partly updated.
 */
export type SpaceshipStage =
  | "records"
  | "credentials"
  | "scope"
  | "ownership"
  | "rate_limited"
  | "read"
  | "unreadable"
  | "conflict"
  | "expired"
  | "write";

/** Only a fixed stage and an HTTP status cross the credential boundary. No
 * response body, transport exception, header, credential or cause is ever
 * attached to this error. */
export class SpaceshipError extends Error {
  readonly stage: SpaceshipStage;
  readonly status: number | undefined;
  constructor(stage: SpaceshipStage, status?: number) {
    super(`Spaceship ${stage} failed${status === undefined ? "" : ` (HTTP ${status})`}`);
    this.name = "SpaceshipError";
    this.stage = stage;
    this.status = status;
  }
}

/** The ASCII, lower-case form of a domain, or null when it is not one. */
function parseDomain(domain: string): string | null {
  const normalized = domainToASCII(domain.trim().replace(/\.$/, "")).toLowerCase();
  return normalized && /^[a-z0-9.-]+$/.test(normalized) ? normalized : null;
}

function normalizeDomain(domain: string): string {
  const normalized = parseDomain(domain);
  if (normalized === null) throw new SpaceshipError("records");
  return normalized;
}

/** One item of `PUT /v1/dns/records/{domain}`'s `items` array. The docs'
 * discriminated item shapes: A/AAAA carry `address`, CNAME `cname`, TXT
 * `value`, MX `exchange` + `preference`; every item carries `type`, a
 * zone-relative `name` ("@" for the apex) and an optional `ttl`. */
export type SpaceshipRecordItem = { type: string; name: string; ttl?: number } & (
  | { address: string }
  | { cname: string }
  | { value: string }
  | { exchange: string; preference: number }
);

function clampTtl(ttl: number): number {
  return Math.min(SPACESHIP_MAX_TTL, Math.max(SPACESHIP_MIN_TTL, ttl));
}

/**
 * The `items` a save-records call carries for these session records, named
 * relative to `zone`. Every record is composed against the SESSION domain
 * before it is made relative to the zone, exactly as verification composes it.
 * A TTL outside Spaceship's 60..3600 window is moved to the nearest bound:
 * verification compares values, never TTLs, and refusing the whole connect over
 * a cache hint would only push the user to typing the same record by hand.
 */
export function spaceshipRecordItems(
  domain: string,
  records: SessionRecord[],
  zone = apexOf(normalizeDomain(domain)),
): SpaceshipRecordItem[] {
  const normalized = normalizeDomain(domain);
  const parsed = zRecords.min(1).safeParse(records);
  if (!parsed.success) throw new SpaceshipError("records");
  const items: SpaceshipRecordItem[] = [];
  for (const record of parsed.data) {
    if (!isSpaceshipWritable(record.type)) throw new SpaceshipError("records");
    const fqdn = domainToASCII(fqdnFor(record.host, normalized)).toLowerCase();
    if (!fqdn || (fqdn !== zone && !fqdn.endsWith(`.${zone}`))) throw new SpaceshipError("records");
    if (record.ttl !== undefined && record.ttl <= 0) throw new SpaceshipError("records");
    const name = zoneRelativeName(fqdn, zone);
    const ttl = record.ttl === undefined ? {} : { ttl: clampTtl(record.ttl) };
    const value = record.value.trim();
    if (!value) throw new SpaceshipError("records");
    if (requiresPriority(record.type)) {
      if (record.priority === undefined || record.priority < 0 || record.priority > 65535)
        throw new SpaceshipError("records");
      items.push({
        type: record.type,
        name,
        ...ttl,
        exchange: value.replace(/\.$/, ""),
        preference: record.priority,
      });
    } else if (record.type === "CNAME") {
      items.push({ type: record.type, name, ...ttl, cname: value.replace(/\.$/, "") });
    } else if (record.type === "TXT") {
      // TXT is matched case-sensitively by Spaceship ("Records are matched using
      // case-insensitive comparison, except for TXT records"), so it goes as is.
      items.push({ type: record.type, name, ...ttl, value: record.value });
    } else {
      items.push({ type: record.type, name, ...ttl, address: value });
    }
  }
  return items;
}

// GET /v1/domains/{domain} 200 body: the docs require `name`, the domain in
// ASCII (A-label) form, among many fields we do not read.
const zDomainInfo = z.object({ name: z.string() });

// GET /v1/dns/records/{domain} 200 body: `{ items: [...], total }`, each item
// `{ type, name, ttl?, group: { type } }` plus its type's value fields.
const zZonePage = z.object({
  items: z.array(z.unknown()),
  total: z.number().int().nonnegative(),
});
const zExistingItem = z.object({ type: z.string(), name: z.string() });

export interface SpaceshipExistingRecord {
  /** Zone-relative, lower-case, "@" for the apex: the form spaceshipRecordItems writes. */
  name: string;
  type: string;
  /** The value in resolver-answer form ("10 mx.example.com" for MX), or null
   * for a type whose value we never compare (it can only ever conflict by type). */
  answer: string | null;
}

/** A zone record name in the form our own record names take, or null when it
 * cannot be read with confidence. */
function existingName(raw: string, zone: string): string | null {
  const name = raw.trim().toLowerCase().replace(/\.$/, "");
  if (name === "" || name === "@" || name === zone) return "@";
  const relative = name.endsWith(`.${zone}`) ? name.slice(0, -(zone.length + 1)) : name;
  return /^(?:[a-z0-9_*-]+\.)*[a-z0-9_*-]+$/.test(relative) ? relative : null;
}

function stringField(item: Record<string, unknown>, key: string): string | null {
  const value = item[key];
  return typeof value === "string" && value.length > 0 ? value : null;
}

// TODO(scope): the zone GET's real item spelling (trailing dots, TXT quoting,
// relative vs fully qualified names) is unproven until a live read against a
// Spaceship zone; we own no Spaceship domain. Until then every plausible
// spelling is normalized here, and a name or value that still cannot be read
// refuses the apply ("unreadable", then guided setup) instead of guessing.
function normalizeExisting(item: unknown, zone: string): SpaceshipExistingRecord {
  const base = zExistingItem.safeParse(item);
  if (!base.success) throw new SpaceshipError("unreadable");
  const fields = item as Record<string, unknown>;
  const name = existingName(base.data.name, zone);
  const type = base.data.type.trim().toUpperCase();
  if (name === null || !/^[A-Z0-9]+$/.test(type)) throw new SpaceshipError("unreadable");
  let answer: string | null = null;
  if (type === "A" || type === "AAAA") answer = stringField(fields, "address");
  else if (type === "CNAME") answer = stringField(fields, "cname");
  else if (type === "TXT") answer = stringField(fields, "value");
  else if (type === "MX") {
    const exchange = stringField(fields, "exchange");
    const preference = fields.preference;
    answer =
      exchange !== null && typeof preference === "number" ? `${preference} ${exchange}` : null;
  } else return { name, type, answer: null };
  if (answer === null) throw new SpaceshipError("unreadable");
  return { name, type, answer: type === "TXT" ? answer : answer.trim() };
}

/** Every record a zone GET returned, in the form the conflict guard compares.
 * Throws `unreadable` on the first item it cannot read with confidence. */
export function normalizeSpaceshipZone(
  items: readonly unknown[],
  zone: string,
): SpaceshipExistingRecord[] {
  return items.map((item) => normalizeExisting(item, zone));
}

/** The status-to-stage reading shared by every call. A status outside the
 * credential/scope/rate classes falls to the call's own failure stage. */
function stageForStatus(status: number, otherwise: SpaceshipStage): SpaceshipStage {
  if (status === 401) return "credentials";
  if (status === 403) return "scope";
  if (status === 429) return "rate_limited";
  return otherwise;
}

const exclusive = (type: string) => type === "CNAME" || type === "ALIAS";

/** Which session records still need writing, or (by throwing a `conflict`)
 * whether writing any of them would change or contradict what the zone already
 * holds. Records already present are skipped, so Spaceship never rewrites a TTL
 * the customer set. The same rules the Cloudflare and Hostinger one-clicks
 * apply: a CNAME (or ALIAS) never shares a name with another type, A/AAAA/MX
 * never gain a second value beside a different one, and TXT coexists unless it
 * is a second, different email policy of one kind. */
export function planSpaceshipWrite(
  domain: string,
  records: SessionRecord[],
  zone: string,
  existing: ReadonlyArray<SpaceshipExistingRecord>,
): SessionRecord[] {
  const normalized = normalizeDomain(domain);
  const toWrite: SessionRecord[] = [];
  for (const record of records) {
    const name = zoneRelativeName(
      domainToASCII(fqdnFor(record.host, normalized)).toLowerCase(),
      zone,
    );
    const matches = (answer: string) =>
      recordAnswerMatches(record.type, record.value, answer, record.priority);
    const policy = record.type === "TXT" ? emailPolicyKindOf(record.value) : null;
    let alreadyPresent = false;
    for (const set of existing) {
      if (set.name !== name) continue;
      if (set.type !== record.type) {
        // ALIAS is Spaceship's apex CNAME flattening: it owns its name the
        // same way a CNAME does.
        if (exclusive(set.type) || exclusive(record.type)) throw new SpaceshipError("conflict");
        continue;
      }
      if (set.answer === null) throw new SpaceshipError("conflict");
      if (matches(set.answer)) {
        alreadyPresent = true;
        continue;
      }
      if (!allowsCoexistingValues(record.type)) throw new SpaceshipError("conflict");
      if (policy !== null && emailPolicyKindOf(set.answer) === policy)
        throw new SpaceshipError("conflict");
    }
    if (!alreadyPresent) toWrite.push(record);
  }
  return toWrite;
}

/** What the apply did: how many records it sent (0 when every one was already
 * present), or the fixed-stage error it stopped on. Never throws. */
export type SpaceshipApplyOutcome =
  { ok: true; written: number } | { ok: false; error: SpaceshipError };

/**
 * Prove the domain is in the key's account, read the zone, refuse a conflict,
 * then add only the missing records with Spaceship's conflict checker ON.
 *
 * Endpoints (docs.spaceship.dev, 2026-10-30):
 *   - GET  /v1/domains/{domain}       "Get domain info", scope domains:read,
 *     limited to 5 requests per domain within 300 seconds. 404 = not in this
 *     account.
 *   - GET  /v1/dns/records/{domain}?take=&skip=  "Get domain resource records
 *     list", scope dnsrecords:read, `take` and `skip` required, 300 requests
 *     per user within 300 seconds.
 *   - PUT  /v1/dns/records/{domain}   "Save resource records", scope
 *     dnsrecords:write, body `{ force?: boolean, items: [...] }` (1..500
 *     items), 204 on success, 422 when the conflict checker refuses, 300
 *     requests per user per domain within 300 seconds. "Add custom DNS resource
 *     records or update TTL": an upsert that adds, never removes. `force: false`
 *     keeps Spaceship's own conflict checker on, so a CNAME clash comes back as
 *     422 instead of being forced through. DELETE is never called.
 *
 * The zone is the registrable domain (apexOf): Spaceship's records API is keyed
 * by the registered domain, and a subdomain session's records are named
 * relative to it.
 *
 * TODO(scope): whether a domain registered elsewhere but served by Spaceship
 * nameservers passes "Get domain info" is unproven. Today it would answer 404,
 * the user sees "not in this account", and guided setup stays one click away.
 *
 * No persistence, logging or telemetry belongs inside this function, and the
 * credential is never retried, refreshed or kept.
 */
export async function applySpaceshipRecords(
  input: {
    credentials: SpaceshipCredentials;
    domain: string;
    records: SessionRecord[];
    expiresAt: Date;
  },
  fetcher: typeof fetch = fetch,
): Promise<SpaceshipApplyOutcome> {
  const headers = {
    "X-API-Key": input.credentials.apiKey,
    "X-API-Secret": input.credentials.apiSecret,
    Accept: "application/json",
  };
  async function request(
    otherwise: SpaceshipStage,
    url: string,
    init: RequestInit = {},
  ): Promise<Response> {
    let response: Response;
    try {
      response = await fetcher(url, {
        ...init,
        headers: { ...headers, ...(init.body ? { "Content-Type": "application/json" } : {}) },
        cache: "no-store",
        redirect: "error",
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch {
      throw new SpaceshipError(otherwise);
    }
    if (!response.ok)
      throw new SpaceshipError(stageForStatus(response.status, otherwise), response.status);
    return response;
  }
  async function json(stage: SpaceshipStage, response: Response): Promise<unknown> {
    try {
      return await response.json();
    } catch {
      throw new SpaceshipError(stage);
    }
  }

  async function readZone(zone: string): Promise<SpaceshipExistingRecord[]> {
    const existing: SpaceshipExistingRecord[] = [];
    for (let page = 0; page < SPACESHIP_MAX_PAGES; page++) {
      const url = new URL(`${SPACESHIP_API_ORIGIN}/dns/records/${encodeURIComponent(zone)}`);
      url.searchParams.set("take", String(SPACESHIP_PAGE_SIZE));
      url.searchParams.set("skip", String(page * SPACESHIP_PAGE_SIZE));
      const body = zZonePage.safeParse(
        await json("unreadable", await request("read", url.toString())),
      );
      if (!body.success) throw new SpaceshipError("unreadable");
      existing.push(...normalizeSpaceshipZone(body.data.items, zone));
      if (body.data.items.length < SPACESHIP_PAGE_SIZE || existing.length >= body.data.total)
        return existing;
    }
    // More records than we read: a conflict could hide on a page we never saw.
    throw new SpaceshipError("unreadable");
  }

  try {
    const domain = normalizeDomain(input.domain);
    const zone = apexOf(domain);
    spaceshipRecordItems(domain, input.records, zone);

    const info = zDomainInfo.safeParse(
      await json(
        "unreadable",
        await request("ownership", `${SPACESHIP_API_ORIGIN}/domains/${encodeURIComponent(zone)}`),
      ),
    );
    if (!info.success) throw new SpaceshipError("unreadable");
    if (parseDomain(info.data.name) !== zone) throw new SpaceshipError("ownership");

    const existing = await readZone(zone);
    const toWrite = planSpaceshipWrite(domain, input.records, zone, existing);
    if (toWrite.length === 0) return { ok: true, written: 0 };
    if (input.expiresAt.getTime() <= Date.now()) throw new SpaceshipError("expired");
    const items = spaceshipRecordItems(domain, toWrite, zone);
    await request("write", `${SPACESHIP_API_ORIGIN}/dns/records/${encodeURIComponent(zone)}`, {
      method: "PUT",
      body: JSON.stringify({ force: false, items }),
    }).catch((error: unknown) => {
      // 422 is the save call's "entity is unprocessable": with force:false that
      // is Spaceship's conflict checker refusing, and nothing was saved.
      // TODO(scope): unproven live. The docs give 422 a `data` field but no
      // per-cause codes, so a 422 for another reason (a value Spaceship rejects)
      // also lands on the conflict notice and guided setup, never a retry loop.
      if (error instanceof SpaceshipError && error.status === 422)
        throw new SpaceshipError("conflict", 422);
      throw error;
    });
    return { ok: true, written: items.length };
  } catch (error) {
    // Every provider failure is already a fixed-stage SpaceshipError. Anything
    // else is a defect in this function; it is replaced, never forwarded, so
    // no exception raised while the credential was in scope leaves here.
    return {
      ok: false,
      error: error instanceof SpaceshipError ? error : new SpaceshipError("write"),
    };
  }
}
