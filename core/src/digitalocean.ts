// Public client with PKCE S256. Metadata and DNS record OpenAPI read 2026-11-04.
// https://cloud.digitalocean.com/.well-known/oauth-authorization-server
// https://github.com/digitalocean/openapi/blob/main/specification/resources/domains/models/domain_record.yml
// Proven live 2026-11-05 on dev against a real zone: the DCR public client's token
// is accepted by api.digitalocean.com/v2 and authorize grants the narrow domain:*
// scopes. Never fall back to broader permissions or request domain:delete.
import { createHash, randomBytes } from "node:crypto";
import { domainToASCII } from "node:url";

import { apexOf } from "./apex.ts";
import { emailPolicyKindOf } from "./email-records.ts";
import {
  allowsCoexistingValues,
  tierCanWrite,
  recordValueMatches,
  requiresPriority,
} from "./record-capabilities.ts";
import { fqdnFor, zoneRelativeName, zRecords, type SessionRecord } from "./records.ts";
import { z } from "./zod-runtime.ts";

export const DIGITALOCEAN_AUTHORIZE_URL = "https://cloud.digitalocean.com/v1/oauth/authorize";
export const DIGITALOCEAN_TOKEN_URL = "https://cloud.digitalocean.com/v1/oauth/token";
export const DIGITALOCEAN_REVOKE_URL = "https://cloud.digitalocean.com/v1/oauth/revoke";
export const DIGITALOCEAN_API_ORIGIN = "https://api.digitalocean.com";
const DIGITALOCEAN_REGISTER_URL = "https://cloud.digitalocean.com/v1/oauth/register";
export const DIGITALOCEAN_CALLBACK_PATH = "/api/v1/digitalocean/callback";
export const DIGITALOCEAN_FLOW_SECONDS = 1800;

export interface DigitalOceanConfig {
  clientId: string;
  redirectUri: string;
}

const zState = z
  .string()
  .max(450)
  .regex(/^[A-Za-z0-9_-]{32}(?:~e(?:\.[A-Za-z0-9_-]+)?)?$/);
export const zDigitalOceanCallback = z.union([
  z.object({ state: zState, code: z.string().min(1).max(4096), error: z.never().optional() }),
  z.object({
    state: zState,
    error: z.string().regex(/^[a-z0-9_]{1,64}$/),
    code: z.never().optional(),
  }),
]);

export function digitaloceanPkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}

export function buildDigitalOceanAuthorizeUrl(
  config: DigitalOceanConfig,
  state: string,
  challenge: string,
): string {
  if (!config.clientId || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) {
    throw new Error("DigitalOcean: invalid OAuth configuration or PKCE challenge");
  }
  const url = new URL(DIGITALOCEAN_AUTHORIZE_URL);
  url.search = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    response_type: "code",
    scope: "domain:read domain:create domain:update",
    state: zState.parse(state),
    code_challenge: challenge,
    code_challenge_method: "S256",
  }).toString();
  return url.toString();
}

type DigitalOceanStage =
  | "register"
  | "records"
  | "exchange"
  | "portfolio"
  | "ownership"
  | "read"
  | "conflict"
  | "write"
  | "revoke";
/** Only fixed stages and HTTP status escape the credential boundary. No response
 * body, transport exception, token, or cause is ever attached to this error. */
export class DigitalOceanError extends Error {
  readonly stage: DigitalOceanStage;
  readonly status: number | undefined;
  constructor(stage: DigitalOceanStage, status?: number) {
    super(`DigitalOcean ${stage} failed${status === undefined ? "" : ` (HTTP ${status})`}`);
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
  if (normalized === null) throw new DigitalOceanError("records");
  return normalized;
}

function existingName(raw: string, zone: string): string | null {
  const name = raw.trim().toLowerCase().replace(/\.$/, "");
  if (name === "" || name === "@" || name === zone) return "@";
  const relative = name.endsWith(`.${zone}`) ? name.slice(0, -(zone.length + 1)) : name;
  return /^(?:[a-z0-9_*-]+\.)*[a-z0-9_*-]+$/.test(relative) ? relative : null;
}

const TXT_STRING = /"((?:[^"\\]|\\["\\])*)"/g;
/** A TXT value as resolvers return it: surrounding quotes removed and split
 * strings ("a" "b") joined. Anything else carrying quotes or escapes is
 * ambiguous and comes back null. */
function existingTxtValue(raw: string): string | null {
  const value = raw.trim();
  if (!/["\\]/.test(value)) return value;
  if (!/^"(?:[^"\\]|\\["\\])*"(?:\s*"(?:[^"\\]|\\["\\])*")*$/.test(value)) return null;
  return [...value.matchAll(TXT_STRING)].map((m) => m[1]!.replace(/\\(["\\])/g, "$1")).join("");
}

interface DigitalOceanRecordBody {
  type: SessionRecord["type"];
  name: string;
  data: string;
  priority?: number;
  ttl?: number;
}

/** Names are relative to the selected owned zone, not the registrable apex.
 * TXT `data` is the raw value, never quoted or escaped: DigitalOcean stores `data`
 * literally and does its own zone-file quoting, so a pre-quoted value publishes
 * with literal quote characters (proven live 2026-11-05). CNAME/MX targets are
 * absolute, with a trailing dot. */
export function digitaloceanRecordBodies(
  domain: string,
  records: SessionRecord[],
  zone = apexOf(normalizeDomain(domain)),
): DigitalOceanRecordBody[] {
  const normalized = normalizeDomain(domain);
  const parsed = zRecords.min(1).safeParse(records);
  if (!parsed.success) throw new DigitalOceanError("records");
  return parsed.data.map((record) => {
    if (!tierCanWrite("digitalocean_oauth", record.type)) throw new DigitalOceanError("records");
    const fqdn = domainToASCII(fqdnFor(record.host, normalized)).toLowerCase();
    if (!fqdn || (fqdn !== zone && !fqdn.endsWith(`.${zone}`)))
      throw new DigitalOceanError("records");
    // https://docs.digitalocean.com/products/networking/dns/details/limits/
    if (record.ttl !== undefined && record.ttl < 30) throw new DigitalOceanError("records");
    if (
      requiresPriority(record.type) &&
      (record.priority === undefined || record.priority < 0 || record.priority > 65535)
    )
      throw new DigitalOceanError("records");
    const data =
      record.type === "TXT"
        ? record.value
        : record.type === "CNAME" || record.type === "MX"
          ? `${record.value.replace(/\.$/, "")}.`
          : record.value;
    return {
      type: record.type,
      name: zoneRelativeName(fqdn, zone),
      data,
      ...(record.priority === undefined ? {} : { priority: record.priority }),
      ...(record.ttl === undefined ? {} : { ttl: record.ttl }),
    };
  });
}

const zToken = z.object({
  access_token: z.string().min(1),
  refresh_token: z.string().min(1).optional(),
  // DigitalOcean also returns team_uuid (in info). Deliberately discarded:
  // the bearer-bound domain list is our ownership proof, not account metadata.
});
const zLinks = z.object({ pages: z.object({ next: z.string().optional() }).optional() }).optional();
const zDomains = z.object({ domains: z.array(z.unknown()), links: zLinks });
const zDomain = z.object({ name: z.string() });
const zRecord = z.object({
  id: z.number().int().positive(),
  name: z.string(),
  type: z.string(),
  data: z.string(),
  priority: z.number().int().nullable().optional(),
  ttl: z.number().int().positive().optional(),
});
const zRecordPage = z.object({ domain_records: z.array(zRecord), links: zLinks });

/** Ownership is the longest label-boundary suffix, including delegated zones. */
export function digitaloceanOwnedZone(domain: string, rows: unknown[]): string | null {
  const normalized = normalizeDomain(domain);
  let best: string | null = null;
  for (const row of rows) {
    const parsed = zDomain.safeParse(row);
    const name = parsed.success ? parseDomain(parsed.data.name) : null;
    if (
      name !== null &&
      (normalized === name || normalized.endsWith(`.${name}`)) &&
      (best === null || name.length > best.length)
    )
      best = name;
  }
  return best;
}

function issuedCredentials(body: unknown): string[] {
  if (typeof body !== "object" || body === null) return [];
  const { access_token: access, refresh_token: refresh } = body as Record<string, unknown>;
  return [
    ...new Set([refresh, access].filter((v): v is string => typeof v === "string" && v.length > 0)),
  ];
}

/** HTTP errors carry only fixed stages and statuses. Never expose a body,
 * arbitrary transport exception, credential or cause outside this module. */
async function request(
  fetcher: typeof fetch,
  stage: DigitalOceanStage,
  url: string,
  init: RequestInit,
): Promise<Response> {
  try {
    const response = await fetcher(url, {
      ...init,
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) throw new DigitalOceanError(stage, response.status);
    return response;
  } catch (error) {
    if (error instanceof DigitalOceanError) throw error;
    throw new DigitalOceanError(stage);
  }
}
async function json(stage: DigitalOceanStage, response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    throw new DigitalOceanError(stage);
  }
}

/** Operator-only DCR: runtime flows never register a client. The response may
 * contain a registration credential; only client_id can escape this boundary. */
export async function registerDigitalOceanClient(
  redirectUri: string,
  fetcher: typeof fetch = fetch,
): Promise<string> {
  const redirect = new URL(redirectUri);
  if (
    redirect.protocol !== "https:" ||
    redirect.username ||
    redirect.password ||
    redirect.search ||
    redirect.hash ||
    redirect.pathname !== DIGITALOCEAN_CALLBACK_PATH
  )
    throw new DigitalOceanError("register");
  const response = await json(
    "register",
    await request(fetcher, "register", DIGITALOCEAN_REGISTER_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_name: "DoDomain",
        redirect_uris: [redirectUri],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
      }),
    }),
  );
  const parsed = z
    .object({
      client_id: z
        .string()
        .min(1)
        .regex(/^[A-Za-z0-9._-]+$/),
    })
    .safeParse(response);
  if (!parsed.success) throw new DigitalOceanError("register");
  return parsed.data.client_id;
}

export type DigitalOceanApplyOutcome = { revokeFailure: DigitalOceanError | null } & (
  { ok: true } | { ok: false; error: Error }
);

/** One request owns the entire credential lifetime. All pages and all requested
 * records are checked before the first write. No deletes, refresh, storage or
 * telemetry. Every issued credential gets a revoke attempt before returning. */
export async function applyDigitalOceanRecords(
  input: {
    config: DigitalOceanConfig;
    code: string;
    verifier: string;
    domain: string;
    records: SessionRecord[];
    expiresAt: Date;
  },
  fetcher: typeof fetch = fetch,
): Promise<DigitalOceanApplyOutcome> {
  let credentials: string[] = [];
  let revocationBearer: string | undefined;
  async function operate(): Promise<void> {
    const exchanged = await json(
      "exchange",
      await request(fetcher, "exchange", DIGITALOCEAN_TOKEN_URL, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: input.config.clientId,
          redirect_uri: input.config.redirectUri,
          code: input.code,
          code_verifier: input.verifier,
        }).toString(),
      }),
    );
    credentials = issuedCredentials(exchanged);
    if (
      typeof exchanged === "object" &&
      exchanged !== null &&
      "access_token" in exchanged &&
      typeof exchanged.access_token === "string" &&
      exchanged.access_token.length > 0
    )
      revocationBearer = exchanged.access_token;
    const token = zToken.safeParse(exchanged);
    if (!token.success) throw new DigitalOceanError("exchange");
    const headers = {
      Authorization: `Bearer ${token.data.access_token}`,
      "Content-Type": "application/json",
    };
    const domainRows: unknown[] = [];
    // Construct page URLs ourselves. Never send the bearer to a provider-supplied
    // next link. Bounded pagination fails closed, never writes a partial view.
    for (let page = 1; ; page++) {
      if (page > 100) throw new DigitalOceanError("portfolio");
      const parsed = zDomains.safeParse(
        await json(
          "portfolio",
          await request(
            fetcher,
            "portfolio",
            `${DIGITALOCEAN_API_ORIGIN}/v2/domains?per_page=200&page=${page}`,
            { headers },
          ),
        ),
      );
      if (!parsed.success) throw new DigitalOceanError("portfolio");
      domainRows.push(...parsed.data.domains);
      if (!parsed.data.links?.pages?.next) break;
    }
    const zone = digitaloceanOwnedZone(input.domain, domainRows);
    if (zone === null) throw new DigitalOceanError("ownership");
    const desired = digitaloceanRecordBodies(input.domain, input.records, zone);
    const zoneUrl = `${DIGITALOCEAN_API_ORIGIN}/v2/domains/${encodeURIComponent(zone)}/records`;
    const current: z.infer<typeof zRecord>[] = [];
    for (let page = 1; ; page++) {
      if (page > 100) throw new DigitalOceanError("read");
      const parsed = zRecordPage.safeParse(
        await json(
          "read",
          await request(fetcher, "read", `${zoneUrl}?per_page=200&page=${page}`, { headers }),
        ),
      );
      if (!parsed.success) throw new DigitalOceanError("read");
      current.push(...parsed.data.domain_records);
      if (!parsed.data.links?.pages?.next) break;
    }
    const existing = current.map((record) => {
      const name = existingName(record.name, zone);
      const type = record.type.trim().toUpperCase();
      const value = type === "TXT" ? existingTxtValue(record.data) : record.data.trim();
      if (name === null || value === null || !/^[A-Z0-9]+$/.test(type))
        throw new DigitalOceanError("conflict");
      return { ...record, name, type, value };
    });
    // Validate the entire requested batch before any write, including names
    // absent from the snapshot. Identical requests are harmless duplicates.
    for (const [index, body] of desired.entries()) {
      for (const [otherIndex, other] of desired.slice(0, index).entries()) {
        if (body.name !== other.name) continue;
        if (body.type === "CNAME" || other.type === "CNAME") {
          if (
            body.type !== other.type ||
            !recordValueMatches(
              body.type,
              input.records[index]!.value,
              input.records[otherIndex]!.value,
            )
          )
            throw new DigitalOceanError("conflict");
        }
        const policy = body.type === "TXT" ? emailPolicyKindOf(input.records[index]!.value) : null;
        if (
          policy !== null &&
          other.type === "TXT" &&
          emailPolicyKindOf(input.records[otherIndex]!.value) === policy &&
          input.records[index]!.value !== input.records[otherIndex]!.value
        )
          throw new DigitalOceanError("conflict");
      }
    }
    const writes: DigitalOceanRecordBody[] = [];
    for (const [index, body] of desired.entries()) {
      const record = input.records[index]!;
      const matches = (value: string, priority?: number | null) =>
        recordValueMatches(record.type, record.value, value, {
          expectedPriority: record.priority,
          actualPriority: priority ?? undefined,
        });
      const policy = record.type === "TXT" ? emailPolicyKindOf(record.value) : null;
      let present = false;
      for (const row of existing) {
        if (row.name !== body.name) continue;
        if (row.type !== body.type) {
          if (row.type === "CNAME" || body.type === "CNAME")
            throw new DigitalOceanError("conflict");
          continue;
        }
        const same = matches(row.value, row.priority);
        present ||= same;
        // An existing member can satisfy any requested value in this RRset.
        // Values outside that set still follow the shared conflict policy.
        const requested = desired.some((candidate, candidateIndex) => {
          if (candidate.name !== body.name || candidate.type !== body.type) return false;
          const expected = input.records[candidateIndex]!;
          return recordValueMatches(expected.type, expected.value, row.value, {
            expectedPriority: expected.priority,
            actualPriority: row.priority ?? undefined,
          });
        });
        if (
          !requested &&
          (!allowsCoexistingValues(body.type) ||
            (policy !== null && emailPolicyKindOf(row.value) === policy))
        )
          throw new DigitalOceanError("conflict");
      }
      if (
        !present &&
        !writes.some(
          (write) =>
            write.name === body.name &&
            write.type === body.type &&
            write.data === body.data &&
            write.priority === body.priority,
        )
      ) {
        writes.push(body);
      }
    }
    for (const body of writes) {
      if (input.expiresAt.getTime() <= Date.now()) throw new DigitalOceanError("write");
      await request(fetcher, "write", zoneUrl, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
      });
    }
  }

  let settled: { ok: true } | { ok: false; error: Error };
  try {
    await operate();
    settled = { ok: true };
  } catch (error) {
    settled = {
      ok: false,
      error: error instanceof DigitalOceanError ? error : new DigitalOceanError("write"),
    };
  }
  let revokeFailure: DigitalOceanError | null = null;
  // Revoke a distinct refresh grant first while the access bearer is still
  // usable. A refresh token is never an Authorization bearer. Even malformed
  // exchanges without an access bearer get public-client revocation attempts.
  // TODO(T-9671): verify refresh-grant revocation/cascade behavior in the live
  // rehearsal; the provider's published revoke example documents access only.
  for (const credential of credentials) {
    try {
      await request(fetcher, "revoke", DIGITALOCEAN_REVOKE_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          ...(revocationBearer === undefined
            ? {}
            : { Authorization: `Bearer ${revocationBearer}` }),
        },
        body: new URLSearchParams({
          token: credential,
          client_id: input.config.clientId,
        }).toString(),
      });
    } catch (error) {
      revokeFailure ??=
        error instanceof DigitalOceanError ? error : new DigitalOceanError("revoke");
    }
  }
  return { ...settled, revokeFailure };
}
