// OVHcloud one-click connect over OVH's credential-request ("consent") API,
// ported from the 2026-10-30 spike (C:\pwa-runs\dodomain\ovh-spike). Proven
// live there: the unsigned POST /auth/credential, OVH's validation page listing
// exactly the zone-scoped rules below, the v1 signature against the real API,
// and 403 "This call has not been granted" for every call outside the zone.
//
// Sources (read 2026-10-30):
//   docs.ovhcloud.com/en/guides/manage-and-operate/api/first-steps
//     "$1$" + SHA1_HEX(AS+"+"+CK+"+"+METHOD+"+"+QUERY+"+"+BODY+"+"+TSTAMP)
//   docs.ovhcloud.com/en/guides/manage-and-operate/api/api-right-delegation
//   api.eu.ovhcloud.com/1.0/auth.json + /1.0/domain.json (schemas)
//   github.com/ovh/python-ovh ovh/client.py (endpoints, signing, /auth/time delta)
//
// One application key per REGION signs for every customer; each customer
// approves their own consumer key, scoped to ONE zone's records. The consumer
// key lives between start and callback only (sealed at rest by apps/web), and
// this module revokes it (POST /auth/logout) after every apply, success or not.
import { createHash } from "node:crypto";
import { domainToASCII } from "node:url";

import { emailPolicyKindOf } from "./email-records.ts";
import {
  allowsCoexistingValues,
  isOvhWritable,
  recordValueMatches,
  requiresPriority,
} from "./record-capabilities.ts";
import { fqdnFor, zoneRelativeName, zRecords, type SessionRecord } from "./records.ts";
import { z } from "./zod-runtime.ts";

import type { OvhRegion } from "./ovh-region.ts";

export { OVH_REGIONS, ovhRegionForNameServers, type OvhRegion } from "./ovh-region.ts";

export const OVH_API_BASES: Readonly<Record<OvhRegion, string>> = {
  ca: "https://ca.api.ovh.com/1.0",
  eu: "https://eu.api.ovh.com/1.0",
};
export const OVH_CALLBACK_PATH = "/api/v1/ovh/callback";
/** How long a started consent may take before its state is refused and reaped. */
export const OVH_FLOW_SECONDS = 1800;

export interface OvhApplication {
  applicationKey: string;
  applicationSecret: string;
}

/** Only the regions with BOTH an application key and secret appear here. */
export interface OvhConfig {
  regions: Partial<Record<OvhRegion, OvhApplication>>;
  /** `${APP_ORIGIN}/api/v1/ovh/callback`; the start route appends `?state=`. */
  callbackUrl: string;
}

/** The documented v1 signature. `url` is the FULL url including its query. */
export function signOvhRequest(input: {
  appSecret: string;
  consumerKey: string;
  method: string;
  url: string;
  body: string;
  timestamp: number | string;
}): string {
  const raw = [
    input.appSecret,
    input.consumerKey,
    input.method.toUpperCase(),
    input.url,
    input.body,
    String(input.timestamp),
  ].join("+");
  return "$1$" + createHash("sha1").update(raw, "utf8").digest("hex");
}

// A plain DNS zone name: lowercase labels, no wildcard, no path characters.
// Anything else could widen an access rule (a "*" or "/" in the zone segment).
const ZONE_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/;

/** The zone as OVH names it (ASCII, lower-case), or null when it could widen a rule. */
export function ovhZoneName(zone: string): string | null {
  const raw = zone.trim().replace(/\.$/, "");
  // domainToASCII parses like a URL host and would silently drop a "/*" tail,
  // so anything but letters, digits, dots and hyphens is refused first.
  if (!/^[\p{L}\p{N}.-]+$/u.test(raw)) return null;
  const ascii = domainToASCII(raw).toLowerCase();
  return ZONE_RE.test(ascii) ? ascii : null;
}

export interface OvhAccessRule {
  method: "GET" | "POST" | "PUT" | "DELETE";
  path: string;
}

/**
 * The smallest rule set DoDomain needs on ONE zone: read the zone and its
 * records, add records, refresh it. Add-only: no PUT or DELETE, because the
 * adapter never modifies or removes a record, and the customer's OVH approval
 * page lists every rule we ask for. No zone-level wildcard, so the grant can
 * never reach /domain/zone/<other-zone>, /domain/<zone> (registrar, nameserver
 * changes, transfer), /me, /order or billing.
 */
export function ovhZoneAccessRules(zoneInput: string): OvhAccessRule[] {
  const zone = ovhZoneName(zoneInput);
  if (zone === null || zone !== zoneInput) throw new OvhError("records");
  const base = `/domain/zone/${zone}`;
  return [
    { method: "GET", path: base },
    { method: "GET", path: `${base}/record` },
    { method: "GET", path: `${base}/record/*` },
    { method: "POST", path: `${base}/record` },
    { method: "POST", path: `${base}/refresh` },
  ];
}

type OvhStage =
  | "consent"
  | "time"
  | "credential"
  | "pending"
  | "refused"
  | "expired"
  | "scope"
  | "records"
  | "read"
  | "conflict"
  | "write"
  | "refresh"
  | "revoke";

/** Only fixed stages, the HTTP status and whether OVH called the consumer key
 * invalid escape this module. No response body, transport exception, key or
 * cause is ever attached. */
export class OvhError extends Error {
  readonly stage: OvhStage;
  readonly status: number | undefined;
  /** OVH answered 403 "This credential is not valid". At the "credential"
   * stage (the callback's first signed call) that is a Cancel on OVH's consent
   * page; at any later stage the customer revoked the key (or it expired)
   * after approving. Either way the user must reconnect. */
  readonly revoked: boolean;
  constructor(stage: OvhStage, status?: number, revoked = false) {
    super(
      `OVHcloud ${stage} failed${status === undefined ? "" : ` (HTTP ${status})`}${revoked ? " (credential no longer valid)" : ""}`,
    );
    this.name = "OvhError";
    this.stage = stage;
    this.status = status;
    this.revoked = revoked;
  }
}

const REVOKED_MESSAGE = /credential is not valid/i;

/** HTTP errors carry only fixed stages and statuses. A 403 body is read only to
 * tell a revoked consumer key apart; the text itself never leaves. */
async function request(
  fetcher: typeof fetch,
  stage: OvhStage,
  url: string,
  init: RequestInit,
): Promise<Response> {
  let response: Response;
  try {
    response = await fetcher(url, {
      ...init,
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new OvhError(stage);
  }
  if (response.ok) return response;
  let revoked = false;
  if (response.status === 403) {
    try {
      revoked = REVOKED_MESSAGE.test((await response.text()).slice(0, 2000));
    } catch {
      revoked = false;
    }
  }
  throw new OvhError(stage, response.status, revoked);
}

async function json(stage: OvhStage, response: Response): Promise<unknown> {
  try {
    const text = await response.text();
    return text === "" ? null : JSON.parse(text);
  } catch {
    throw new OvhError(stage);
  }
}

// The consumer key format OVH issues (32 alphanumerics in the spike); bounded
// loosely so a format change fails closed rather than storing junk.
const zConsumerKey = z.string().regex(/^[A-Za-z0-9]{16,128}$/);
const zCredentialRequest = z.object({
  consumerKey: zConsumerKey,
  validationUrl: z.string().min(1).max(2048),
  state: z.literal("pendingValidation"),
});
const OVH_VALIDATION_HOSTS = ["ovh.com", "ovhcloud.com", "ovh.ca", "ovh.net"];

/** The validation page must be an OVH https page: the user is redirected there. */
function validationUrlOf(raw: string): string | null {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" || url.username || url.password) return null;
  const host = url.hostname.toLowerCase();
  return OVH_VALIDATION_HOSTS.some((root) => host === root || host.endsWith(`.${root}`))
    ? url.toString()
    : null;
}

function callbackRedirection(callbackUrl: string, state: string): string {
  const url = new URL(callbackUrl);
  const local = url.protocol === "http:" && ["localhost", "127.0.0.1"].includes(url.hostname);
  if (
    (url.protocol !== "https:" && !local) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== OVH_CALLBACK_PATH
  )
    throw new OvhError("consent");
  // The state alphabet is URL-safe as is ([A-Za-z0-9_~.-]); appended verbatim,
  // since URLSearchParams would percent-encode the "~" for no reason.
  return `${url.toString()}?state=${zOvhState.parse(state)}`;
}

/** Our own random state (plus encoded embed context), carried in the
 * redirection URL OVH sends the user back to. */
const zOvhState = z
  .string()
  .max(450)
  .regex(/^[A-Za-z0-9_-]{32}(?:~e(?:\.[A-Za-z0-9_-]+)?)?$/);
/** OVH redirects to the exact URL we gave it; any extra parameter is ignored. */
export const zOvhCallback = z.object({ state: zOvhState });

/**
 * The "one click": an UNSIGNED credential request carrying only the
 * application key, the zone-scoped rules and where OVH sends the user back.
 * Returns the pending consumer key (seal it before storing) and the OVH page
 * the user approves on.
 */
export async function requestOvhConsent(
  input: {
    region: OvhRegion;
    application: OvhApplication;
    zone: string;
    callbackUrl: string;
    state: string;
  },
  fetcher: typeof fetch = fetch,
): Promise<{ consumerKey: string; validationUrl: string }> {
  const body = JSON.stringify({
    accessRules: ovhZoneAccessRules(input.zone),
    redirection: callbackRedirection(input.callbackUrl, input.state),
  });
  const parsed = zCredentialRequest.safeParse(
    await json(
      "consent",
      await request(fetcher, "consent", `${OVH_API_BASES[input.region]}/auth/credential`, {
        method: "POST",
        headers: {
          "X-Ovh-Application": input.application.applicationKey,
          "Content-Type": "application/json",
        },
        body,
      }),
    ),
  );
  if (!parsed.success) throw new OvhError("consent");
  const validationUrl = validationUrlOf(parsed.data.validationUrl);
  if (validationUrl === null) throw new OvhError("consent");
  return { consumerKey: parsed.data.consumerKey, validationUrl };
}

/** The ASCII, lower-case form of a domain, or null when it is not one. */
function parseDomain(domain: string): string | null {
  const normalized = domainToASCII(domain.trim().replace(/\.$/, "")).toLowerCase();
  return normalized && /^[a-z0-9.-]+$/.test(normalized) ? normalized : null;
}

export interface OvhRecordBody {
  fieldType: SessionRecord["type"];
  /** Relative to the zone; "" is the zone apex. */
  subDomain: string;
  target: string;
  ttl?: number;
}

const SUBDOMAIN_RE = /^(?:(?:[a-z0-9_-]+\.)*[a-z0-9_-]+)?$/;

/**
 * Names are relative to the zone the customer approved, "" for its apex.
 * - CNAME and MX targets are ABSOLUTE with a trailing dot: OVH stores the
 *   target as zone-file text, so a target without the dot would be read
 *   relative to the zone (`target.example.com.customer.com`).
 * - MX packs the preference into the target ("10 mx.example.com."): OVH's
 *   record body has no separate priority field.
 * - TXT is the RAW value, never pre-quoted: DigitalOcean taught that a quoted
 *   value can publish with literal quote characters (T-9671, 2026-11-05).
 *   Live-proven on dev 2026-11-11 (T-6776): OVH published the raw value
 *   `dodomain-verify=ovhdev1-20261111` without literal quotes.
 */
export function ovhRecordBodies(
  domain: string,
  records: SessionRecord[],
  zone: string,
): OvhRecordBody[] {
  const normalized = parseDomain(domain);
  const zoneName = ovhZoneName(zone);
  if (normalized === null || zoneName === null) throw new OvhError("records");
  const parsed = zRecords.min(1).safeParse(records);
  if (!parsed.success) throw new OvhError("records");
  return parsed.data.map((record) => {
    if (!isOvhWritable(record.type)) throw new OvhError("records");
    const fqdn = domainToASCII(fqdnFor(record.host, normalized)).toLowerCase();
    if (!fqdn || (fqdn !== zoneName && !fqdn.endsWith(`.${zoneName}`)))
      throw new OvhError("records");
    const relative = zoneRelativeName(fqdn, zoneName);
    const subDomain = relative === "@" ? "" : relative;
    if (!SUBDOMAIN_RE.test(subDomain)) throw new OvhError("records");
    if (record.ttl !== undefined && (record.ttl < 0 || record.ttl > 2147483647))
      throw new OvhError("records");
    if (
      requiresPriority(record.type) &&
      (record.priority === undefined || record.priority < 0 || record.priority > 65535)
    )
      throw new OvhError("records");
    const host = `${record.value.trim().replace(/\.$/, "")}.`;
    const target =
      record.type === "TXT"
        ? record.value
        : record.type === "CNAME"
          ? host
          : record.type === "MX"
            ? `${record.priority} ${host}`
            : record.value.trim();
    return {
      fieldType: record.type,
      subDomain,
      target,
      ...(record.ttl === undefined ? {} : { ttl: record.ttl }),
    };
  });
}

const TXT_STRING = /"((?:[^"\\]|\\["\\])*)"/g;
/** A TXT target as OVH may return it: surrounding quotes removed and split
 * strings ("a" "b") joined. Anything else carrying quotes or escapes is
 * ambiguous and comes back null. */
function existingTxtValue(raw: string): string | null {
  const value = raw.trim();
  if (!/["\\]/.test(value)) return value;
  if (!/^"(?:[^"\\]|\\["\\])*"(?:\s*"(?:[^"\\]|\\["\\])*")*$/.test(value)) return null;
  return [...value.matchAll(TXT_STRING)].map((m) => m[1]!.replace(/\\(["\\])/g, "$1")).join("");
}

/** A zone-file host as OVH stores it: absolute with a trailing dot, else
 * relative to the zone. Returned absolute, without the dot. */
function absoluteHost(raw: string, zone: string): string {
  const host = raw.trim().toLowerCase();
  if (host.endsWith(".")) return host.slice(0, -1);
  return host === "" || host === "@" ? zone : `${host}.${zone}`;
}

const zOvhRecord = z.object({
  id: z.number().int().positive(),
  fieldType: z.string(),
  subDomain: z.string().nullable().optional(),
  target: z.string(),
});
const zRecordIds = z.array(z.number().int().positive()).max(200);
const zCredential = z.object({
  status: z.enum(["pendingValidation", "validated", "refused", "expired"]),
  rules: z
    .array(z.object({ method: z.string(), path: z.string() }))
    .nullable()
    .optional(),
});

export type OvhApplyOutcome = { revokeFailure: OvhError | null } & (
  { ok: true } | { ok: false; error: OvhError }
);

/**
 * One request owns the consumer key's whole remaining life: check OVH says it
 * is validated and scoped to this zone only, read every name it will write,
 * refuse conflicts before the first write, add the missing records, refresh
 * the zone (OVH stages records until then), then revoke the key with
 * POST /auth/logout. No deletes, no updates, no storage, no telemetry.
 */
export async function applyOvhRecords(
  input: {
    region: OvhRegion;
    application: OvhApplication;
    consumerKey: string;
    zone: string;
    domain: string;
    records: SessionRecord[];
    expiresAt: Date;
  },
  fetcher: typeof fetch = fetch,
): Promise<OvhApplyOutcome> {
  const base = OVH_API_BASES[input.region];
  let timeDelta: number | undefined;
  let validated = false;

  async function serverTimeDelta(): Promise<number> {
    if (timeDelta === undefined) {
      const server = z
        .number()
        .int()
        .positive()
        .safeParse(
          await json(
            "time",
            await request(fetcher, "time", `${base}/auth/time`, { method: "GET" }),
          ),
        );
      if (!server.success) throw new OvhError("time");
      timeDelta = server.data - Math.floor(Date.now() / 1000);
    }
    return timeDelta;
  }

  async function signed(
    stage: OvhStage,
    method: "GET" | "POST",
    path: string,
    data?: unknown,
  ): Promise<unknown> {
    const url = base + path;
    const body = data === undefined ? "" : JSON.stringify(data);
    const timestamp = Math.floor(Date.now() / 1000) + (await serverTimeDelta());
    const headers: Record<string, string> = {
      "X-Ovh-Application": input.application.applicationKey,
      "X-Ovh-Consumer": input.consumerKey,
      "X-Ovh-Timestamp": String(timestamp),
      "X-Ovh-Signature": signOvhRequest({
        appSecret: input.application.applicationSecret,
        consumerKey: input.consumerKey,
        method,
        url,
        body,
        timestamp,
      }),
    };
    if (data !== undefined) headers["Content-Type"] = "application/json";
    return json(
      stage,
      await request(fetcher, stage, url, {
        method,
        headers,
        ...(body === "" ? {} : { body }),
      }),
    );
  }

  async function operate(): Promise<void> {
    const zone = ovhZoneName(input.zone);
    if (zone === null || zone !== input.zone) throw new OvhError("records");
    const allowed = new Set(ovhZoneAccessRules(zone).map((r) => `${r.method} ${r.path}`));
    const credential = zCredential.safeParse(
      await signed("credential", "GET", "/auth/currentCredential"),
    );
    if (!credential.success) throw new OvhError("credential");
    if (credential.data.status === "refused") throw new OvhError("refused");
    if (credential.data.status === "expired") throw new OvhError("expired");
    if (credential.data.status !== "validated") throw new OvhError("pending");
    validated = true;
    // The approved key must not reach past the zone we asked for.
    // currentCredential echoes the rules in this {method, path} form: the
    // 2026-11-11 dev proof (T-6776) passed this check and reached verified.
    for (const rule of credential.data.rules ?? []) {
      if (!allowed.has(`${rule.method.toUpperCase()} ${rule.path}`)) throw new OvhError("scope");
    }
    const desired = ovhRecordBodies(input.domain, input.records, zone);
    const recordPath = `/domain/zone/${zone}/record`;
    const existing: { subDomain: string; type: string; value: string; priority?: number }[] = [];
    for (const subDomain of new Set(desired.map((body) => body.subDomain))) {
      const ids = zRecordIds.safeParse(
        await signed(
          "read",
          "GET",
          `${recordPath}?${new URLSearchParams({ subDomain }).toString()}`,
        ),
      );
      if (!ids.success) throw new OvhError("read");
      for (const id of ids.data) {
        const row = zOvhRecord.safeParse(await signed("read", "GET", `${recordPath}/${id}`));
        if (!row.success) throw new OvhError("read");
        const type = row.data.fieldType.trim().toUpperCase();
        if (!/^[A-Z0-9]+$/.test(type)) throw new OvhError("conflict");
        let value: string | null = row.data.target.trim();
        let priority: number | undefined;
        if (type === "TXT") value = existingTxtValue(row.data.target);
        else if (type === "CNAME") value = absoluteHost(row.data.target, zone);
        else if (type === "MX") {
          const mx = /^(\d{1,5})\s+(\S+)$/.exec(value);
          if (mx === null) throw new OvhError("conflict");
          priority = Number(mx[1]);
          value = absoluteHost(mx[2]!, zone);
        }
        if (value === null) throw new OvhError("conflict");
        existing.push({
          subDomain: (row.data.subDomain ?? "").trim().toLowerCase(),
          type,
          value,
          ...(priority === undefined ? {} : { priority }),
        });
      }
    }
    // The whole requested batch is validated before any write, including names
    // absent from the snapshot. Identical requests are harmless duplicates.
    for (const [index, body] of desired.entries()) {
      for (const [otherIndex, other] of desired.slice(0, index).entries()) {
        if (body.subDomain !== other.subDomain) continue;
        if (body.fieldType === "CNAME" || other.fieldType === "CNAME") {
          if (
            body.fieldType !== other.fieldType ||
            !recordValueMatches(
              body.fieldType,
              input.records[index]!.value,
              input.records[otherIndex]!.value,
            )
          )
            throw new OvhError("conflict");
        }
        const policy =
          body.fieldType === "TXT" ? emailPolicyKindOf(input.records[index]!.value) : null;
        if (
          policy !== null &&
          other.fieldType === "TXT" &&
          emailPolicyKindOf(input.records[otherIndex]!.value) === policy &&
          input.records[index]!.value !== input.records[otherIndex]!.value
        )
          throw new OvhError("conflict");
      }
    }
    const writes: OvhRecordBody[] = [];
    for (const [index, body] of desired.entries()) {
      const record = input.records[index]!;
      const policy = record.type === "TXT" ? emailPolicyKindOf(record.value) : null;
      let present = false;
      for (const row of existing) {
        if (row.subDomain !== body.subDomain) continue;
        if (row.type !== body.fieldType) {
          if (row.type === "CNAME" || body.fieldType === "CNAME") throw new OvhError("conflict");
          continue;
        }
        present ||= recordValueMatches(record.type, record.value, row.value, {
          expectedPriority: record.priority,
          actualPriority: row.priority,
        });
        // An existing member can satisfy any requested value in this RRset.
        // Values outside that set still follow the shared conflict policy.
        const requested = desired.some((candidate, candidateIndex) => {
          if (candidate.subDomain !== body.subDomain || candidate.fieldType !== body.fieldType)
            return false;
          const expected = input.records[candidateIndex]!;
          return recordValueMatches(expected.type, expected.value, row.value, {
            expectedPriority: expected.priority,
            actualPriority: row.priority,
          });
        });
        if (
          !requested &&
          (!allowsCoexistingValues(body.fieldType) ||
            (policy !== null && emailPolicyKindOf(row.value) === policy))
        )
          throw new OvhError("conflict");
      }
      if (
        !present &&
        !writes.some(
          (write) =>
            write.subDomain === body.subDomain &&
            write.fieldType === body.fieldType &&
            write.target === body.target,
        )
      )
        writes.push(body);
    }
    for (const body of writes) {
      if (input.expiresAt.getTime() <= Date.now()) throw new OvhError("write");
      await signed("write", "POST", recordPath, body);
    }
    // Records are staged until the zone is refreshed (a new serial pushed to
    // OVH's nameservers); without it nothing ever resolves.
    if (writes.length > 0) await signed("refresh", "POST", `/domain/zone/${zone}/refresh`);
  }

  let settled: { ok: true } | { ok: false; error: OvhError };
  try {
    await operate();
    settled = { ok: true };
  } catch (error) {
    settled = { ok: false, error: error instanceof OvhError ? error : new OvhError("write") };
  }
  // Revoke on every path. A key OVH already calls invalid (403) has nothing
  // left to revoke; neither does one that was never validated.
  let revokeFailure: OvhError | null = null;
  try {
    await signed("revoke", "POST", "/auth/logout");
  } catch (error) {
    const failure = error instanceof OvhError ? error : new OvhError("revoke");
    const nothingToRevoke = failure.status === 403 || (!validated && failure.status === 401);
    if (!nothingToRevoke) revokeFailure = new OvhError("revoke", failure.status);
  }
  return { ...settled, revokeFailure };
}
