// Porkbun DNS Connect is a signed, single-use record request, NOT OAuth.
// Porkbun applies the records during consent; it grants no standing API access.
// https://porkbun.com/llms/guides/connect-a-service-to-porkbun-dns
import { createHmac } from "node:crypto";
import { domainToASCII } from "node:url";

import { apexOf } from "./apex.ts";
import { RECORD_TYPES, requiresPriority } from "./record-capabilities.ts";
import { fqdnFor, zoneRelativeName, zRecords, type SessionRecord } from "./records.ts";
import { z } from "./zod-runtime.ts";

export const PORKBUN_CLIENT_ID = "dc_dodomain_fb0f78";
export const PORKBUN_MAX_RECORDS = 25;
export const PORKBUN_FLOW_SECONDS = 1800;
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
});

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
      if (requiresPriority(record.type) && record.priority === undefined) {
        throw new Error("Porkbun DNS Connect: MX record requires a priority");
      }
      return zPorkbunRecord.parse({
        type: record.type,
        host: zoneRelativeName(fqdn, zone),
        content: record.value,
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
}): string {
  if (!input.config.clientSecret) throw new Error("Porkbun DNS Connect: missing client secret");
  const payload = zPorkbunRequest.parse({
    iss: PORKBUN_CLIENT_ID,
    ...porkbunRecords(input.domain, input.records),
    redirect_uri: input.config.redirectUri,
    state: input.state,
    iat: input.nowSeconds,
    exp: input.expiresSeconds,
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
