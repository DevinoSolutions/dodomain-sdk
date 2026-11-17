// Porkbun DNS Connect is a signed, single-use record request, NOT OAuth.
// Porkbun applies the records during consent; it grants no standing API access.
// https://porkbun.com/llms/guides/connect-a-service-to-porkbun-dns
import { createHmac } from "node:crypto";
import { domainToASCII } from "node:url";

import { apexOf, isNsAtZoneApex } from "./apex.ts";
import {
  caaAnswer,
  missingRecordFields,
  RECORD_TYPES,
  requiresPriority,
  typesTierCannotWrite,
} from "./record-capabilities.ts";
import { fqdnFor, zoneRelativeName, zRecords, type SessionRecord } from "./records.ts";
import { z } from "./zod-runtime.ts";

export const PORKBUN_CLIENT_ID = "dc_dodomain_fb0f78";
export const PORKBUN_MAX_RECORDS = 25;
export const PORKBUN_FLOW_SECONDS = 1800;
/** Our own bound on the `service` claim; the guide states none. */
export const PORKBUN_SERVICE_MAX_LENGTH = 100;
export const PORKBUN_CALLBACK_PATH = "/api/v1/porkbun/callback";
/** The consent page from Porkbun's public guide. The approval email named
 * admin.porkbun.com, which answers 403 to everyone; this host rendered our
 * signed request and applied it on dev (2026-10-29, T-4315). */
export const PORKBUN_AUTHORIZE_URL = "https://porkbun.com/dnsconnect/authorize";

/** The `error` codes Porkbun documents for `status=error`. Any other code is
 * still a failed, nothing-changed return: it maps to the generic notice instead
 * of leaving the customer on a raw 400 with the state unconsumed. */
export const PORKBUN_ERROR_CODES = [
  "domain_not_in_account",
  "domain_not_active",
  "invalid_records",
] as const;
export type PorkbunErrorCode = (typeof PORKBUN_ERROR_CODES)[number];

export interface PorkbunConfig {
  clientSecret: string;
  redirectUri: string;
}

// Includes the existing popup/embed suffix; the ENTIRE string is persisted and
// matched, not just its random head. Bound before any database lookup.
const zPorkbunState = z
  .string()
  .max(450)
  .regex(/^[A-Za-z0-9_-]{32}(?:~e(?:\.[A-Za-z0-9_-]+)?)?$/);

export const zPorkbunCallback = z.discriminatedUnion("status", [
  z.object({ state: zPorkbunState, status: z.literal("applied"), error: z.never().optional() }),
  z.object({ state: zPorkbunState, status: z.literal("partial"), error: z.never().optional() }),
  // The guide sends `error=access_denied` with a denial; a denial without it is
  // still a denial.
  z.object({
    state: zPorkbunState,
    status: z.literal("denied"),
    error: z.literal("access_denied").optional(),
  }),
  // `error` is required (the guide: "error is ..."), bounded to a code shape,
  // and never echoed: lib/porkbun-notice.ts maps it onto curated copy.
  z.object({
    state: zPorkbunState,
    status: z.literal("error"),
    error: z.string().regex(/^[a-z0-9_]{1,64}$/),
  }),
]);

export function isPorkbunErrorCode(value: string): value is PorkbunErrorCode {
  return (PORKBUN_ERROR_CODES as readonly string[]).includes(value);
}
export type PorkbunCallback = z.infer<typeof zPorkbunCallback>;

const zPorkbunRecord = z.object({
  type: z.enum(RECORD_TYPES),
  host: z.string(),
  content: z.string().min(1),
  ttl: z.number().int().positive().optional(),
  prio: z.number().int().min(0).max(65535).optional(),
});

const zPorkbunRequest = z.object({
  iss: z.literal(PORKBUN_CLIENT_ID),
  domain: z.string().min(1),
  records: z.array(zPorkbunRecord).min(1).max(PORKBUN_MAX_RECORDS),
  redirect_uri: z.url(),
  state: zPorkbunState,
  iat: z.number().int().nonnegative(),
  exp: z.number().int().positive(),
  /** The guide's optional claim for "the end service, if you set up DNS on
   * another company's behalf", shown as "<service> (via DoDomain)". Without it
   * Porkbun's consent review flags "The request does not name a service" (dev,
   * 2026-10-29). */
  service: z.string().min(1).max(PORKBUN_SERVICE_MAX_LENGTH).optional(),
});

/** The integrator's display name as Porkbun's `service` claim: whitespace
 * collapsed, bounded, or undefined when nothing printable is left (the claim is
 * optional, so an unnamed app simply omits it). */
export function porkbunServiceName(appName: string | null | undefined): string | undefined {
  const name = (appName ?? "").replace(/\s+/g, " ").trim().slice(0, PORKBUN_SERVICE_MAX_LENGTH);
  return name === "" ? undefined : name.trim();
}

/**
 * Porkbun's `content` for one session record. The DNS Connect guide lists SRV
 * and CAA as types but gives no content format, so this follows Porkbun's own
 * DNS record convention: SRV content is "weight port target" with the priority
 * in `prio` (as for MX), CAA content is the presentation form `flags tag
 * "value"`. Every other type's content is the value itself.
 * TODO(scope): no real Porkbun apply of SRV, CAA or NS has been run yet (the
 * 2026-10-29 dev proof covered TXT + CNAME); prove both formats on the dev
 * site before advertising those types as one-click at Porkbun.
 */
export function porkbunContent(record: SessionRecord): string {
  if (record.type === "SRV") {
    if (record.weight === undefined || record.port === undefined) {
      throw new Error("Porkbun DNS Connect: SRV record requires weight and port");
    }
    return `${record.weight} ${record.port} ${record.value}`;
  }
  if (record.type === "CAA") {
    if (record.flags === undefined || record.tag === undefined) {
      throw new Error("Porkbun DNS Connect: CAA record requires flags and tag");
    }
    return caaAnswer({ flags: record.flags, tag: record.tag, value: record.value });
  }
  return record.value;
}

/** Why Porkbun's one-click may not be offered for these records, or null when
 * it may. Porkbun takes at most 25 records per request, and only types its
 * row of TIER_WRITABLE_TYPES lists. Read by the hosted page (which also words
 * the provider chip from it) and by the start route before signing. */
export type PorkbunOneClickBlocker =
  | { reason: "no_records" }
  | { reason: "too_many_records"; limit: number; count: number }
  | { reason: "unwritable_types"; types: string[] };

export function porkbunOneClickBlocker(
  records: readonly { type: string }[],
): PorkbunOneClickBlocker | null {
  if (records.length === 0) return { reason: "no_records" };
  if (records.length > PORKBUN_MAX_RECORDS) {
    return { reason: "too_many_records", limit: PORKBUN_MAX_RECORDS, count: records.length };
  }
  const types = typesTierCannotWrite("porkbun_dns_connect", records);
  return types.length ? { reason: "unwritable_types", types } : null;
}

/** Compose against the SESSION domain first, then make names relative to the
 * registrable Porkbun domain. Otherwise @ on app.customer.co.uk changes the
 * customer's apex. Never set replace: Porkbun handles conflicts and SPF merge
 * on its consent screen, without us requesting a destructive RRset replacement. */
export function porkbunRecords(
  domain: string,
  records: SessionRecord[],
): {
  domain: string;
  records: z.infer<typeof zPorkbunRecord>[];
} {
  const normalized = domainToASCII(domain.trim().replace(/\.$/, "")).toLowerCase();
  if (!normalized) throw new Error("Porkbun DNS Connect: invalid domain");
  const zone = apexOf(normalized);
  const parsed = zRecords.min(1).max(PORKBUN_MAX_RECORDS).parse(records);
  return {
    domain: zone,
    records: parsed.map((record) => {
      const fqdn = domainToASCII(fqdnFor(record.host, normalized)).toLowerCase();
      if (!fqdn || (fqdn !== zone && !fqdn.endsWith(`.${zone}`))) {
        throw new Error("Porkbun DNS Connect: record is outside the requested domain");
      }
      const problem = missingRecordFields(record);
      if (problem !== null) {
        throw new Error(`Porkbun DNS Connect: ${problem.message}`);
      }
      if (record.type === "NS" && isNsAtZoneApex(fqdn)) {
        throw new Error("Porkbun DNS Connect: NS records are accepted below the root only");
      }
      return zPorkbunRecord.parse({
        type: record.type,
        host: zoneRelativeName(fqdn, zone),
        content: porkbunContent(record),
        ...(record.ttl === undefined ? {} : { ttl: record.ttl }),
        ...(requiresPriority(record.type) ? { prio: record.priority } : {}),
      });
    }),
  };
}

export function buildPorkbunAuthorizeUrl(input: {
  config: PorkbunConfig;
  domain: string;
  records: SessionRecord[];
  state: string;
  nowSeconds: number;
  expiresSeconds: number;
  /** The integrator app's display name; normalized by porkbunServiceName. */
  service?: string | null;
}): string {
  if (!input.config.clientSecret) throw new Error("Porkbun DNS Connect: missing client secret");
  const service = porkbunServiceName(input.service);
  const payload = zPorkbunRequest.parse({
    iss: PORKBUN_CLIENT_ID,
    ...porkbunRecords(input.domain, input.records),
    redirect_uri: input.config.redirectUri,
    state: input.state,
    iat: input.nowSeconds,
    exp: input.expiresSeconds,
    ...(service === undefined ? {} : { service }),
  });
  if (payload.exp <= payload.iat || payload.exp - payload.iat > 3600) {
    throw new Error("Porkbun DNS Connect: request lifetime must be between 1 and 3600 seconds");
  }
  const encode = (value: unknown): string =>
    Buffer.from(JSON.stringify(value)).toString("base64url");
  const signingInput = `${encode({ alg: "HS256", typ: "JWT" })}.${encode(payload)}`;
  const signature = createHmac("sha256", input.config.clientSecret)
    .update(signingInput)
    .digest("base64url");
  const url = new URL(PORKBUN_AUTHORIZE_URL);
  url.searchParams.set("request", `${signingInput}.${signature}`);
  return url.toString();
}
