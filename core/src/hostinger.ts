// Endpoints discovered from Hostinger's authorization-server metadata, 2026-10-30.
// Public client, PKCE S256, no scopes. Never return an account token to a caller.
import { createHash, randomBytes } from "node:crypto";
import { domainToASCII } from "node:url";

import { apexOf } from "./apex.ts";
import { emailPolicyKindOf } from "./email-records.ts";
import {
  allowsCoexistingValues,
  isHostingerWritable,
  recordAnswerMatches,
  requiresPriority,
} from "./record-capabilities.ts";
import { fqdnFor, zoneRelativeName, zRecords, type SessionRecord } from "./records.ts";
import { z } from "./zod-runtime.ts";

export const HOSTINGER_AUTHORIZE_URL =
  "https://auth.hostinger.com/api/external/v1/oauth-server/authorize";
export const HOSTINGER_TOKEN_URL = "https://auth.hostinger.com/api/external/v1/oauth-server/token";
export const HOSTINGER_REVOKE_URL =
  "https://auth.hostinger.com/api/external/v1/oauth-server/token/revoke";
export const HOSTINGER_API_ORIGIN = "https://developers.hostinger.com";
export const HOSTINGER_CALLBACK_PATH = "/api/v1/hostinger/callback";
export const HOSTINGER_FLOW_SECONDS = 1800;

export interface HostingerConfig {
  clientId: string;
  redirectUri: string;
}

const zState = z
  .string()
  .max(450)
  .regex(/^[A-Za-z0-9_-]{32}(?:~e(?:\.[A-Za-z0-9_-]+)?)?$/);
export const zHostingerCallback = z.union([
  z.object({ state: zState, code: z.string().min(1).max(4096), error: z.never().optional() }),
  z.object({
    state: zState,
    error: z.string().regex(/^[a-z0-9_]{1,64}$/),
    code: z.never().optional(),
  }),
]);

export function hostingerPkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}

export function buildHostingerAuthorizeUrl(
  config: HostingerConfig,
  state: string,
  challenge: string,
): string {
  if (!config.clientId || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) {
    throw new Error("Hostinger: invalid OAuth configuration or PKCE challenge");
  }
  const url = new URL(HOSTINGER_AUTHORIZE_URL);
  url.search = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    response_type: "code",
    state: zState.parse(state),
    code_challenge: challenge,
    code_challenge_method: "S256",
  }).toString();
  return url.toString();
}

type HostingerStage =
  | "records"
  | "exchange"
  | "portfolio"
  | "ownership"
  | "read"
  | "conflict"
  | "validate"
  | "write"
  | "revoke";
/** Only fixed stages and HTTP status escape the credential boundary. No response
 * body, transport exception, token, or cause is ever attached to this error. */
export class HostingerError extends Error {
  readonly stage: HostingerStage;
  readonly status: number | undefined;
  constructor(stage: HostingerStage, status?: number) {
    super(`Hostinger ${stage} failed${status === undefined ? "" : ` (HTTP ${status})`}`);
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
  if (normalized === null) throw new HostingerError("records");
  return normalized;
}

interface HostingerRecordSet {
  name: string;
  type: SessionRecord["type"];
  ttl?: number;
  records: { content: string }[];
}

/** Hostinger accepts all current session types. MX preference is part of content.
 * Compose against the session domain BEFORE making names relative to the zone.
 * Group RRsets so multiple requested values never compete as separate updates. */
export function hostingerZoneBody(
  domain: string,
  records: SessionRecord[],
  zone = apexOf(normalizeDomain(domain)),
  /** `name:TYPE` keys of record sets the zone already has. With overwrite:false
   * Hostinger rewrites an existing set's TTL to the one we send, so a set the
   * customer already owns (their apex SPF TXT, say) goes out with no ttl. */
  existingSets: ReadonlySet<string> = new Set(),
): { overwrite: false; zone: HostingerRecordSet[] } {
  const normalized = normalizeDomain(domain);
  const parsed = zRecords.min(1).safeParse(records);
  if (!parsed.success) throw new HostingerError("records");
  const sets = new Map<string, HostingerRecordSet>();
  for (const record of parsed.data) {
    if (!isHostingerWritable(record.type)) throw new HostingerError("records");
    const fqdn = domainToASCII(fqdnFor(record.host, normalized)).toLowerCase();
    if (!fqdn || (fqdn !== zone && !fqdn.endsWith(`.${zone}`))) throw new HostingerError("records");
    if (record.ttl !== undefined && record.ttl <= 0) throw new HostingerError("records");
    if (
      requiresPriority(record.type) &&
      (record.priority === undefined || record.priority < 0 || record.priority > 65535)
    )
      throw new HostingerError("records");
    const name = zoneRelativeName(fqdn, zone);
    const content = requiresPriority(record.type)
      ? `${record.priority} ${record.value}`
      : record.value;
    const key = `${name}:${record.type}`;
    const existing = sets.get(key);
    if (existing) {
      if (existing.ttl !== record.ttl) throw new HostingerError("records");
      if (!existing.records.some((r) => r.content === content)) existing.records.push({ content });
    } else {
      sets.set(key, {
        name,
        type: record.type,
        ...(record.ttl === undefined || existingSets.has(key) ? {} : { ttl: record.ttl }),
        records: [{ content }],
      });
    }
  }
  return { overwrite: false, zone: [...sets.values()] };
}

// The portfolio is read row by row: a null, empty or malformed entry is
// skipped, so one bad row can neither hide the domain the customer does own
// nor turn into the wrong message for them.
const zPortfolio = z.array(z.unknown());
const zPortfolioEntry = z.object({ domain: z.string() });
const zZone = z.array(
  z.object({
    name: z.string(),
    type: z.string(),
    records: z.array(z.object({ content: z.string(), is_disabled: z.boolean().optional() })),
  }),
);
const zToken = z.object({
  access_token: z.string().min(1),
  refresh_token: z.string().min(1).optional(),
});

function ownedDomains(rows: unknown[]): Set<string> {
  const owned = new Set<string>();
  for (const row of rows) {
    const entry = zPortfolioEntry.safeParse(row);
    const domain = entry.success ? parseDomain(entry.data.domain) : null;
    if (domain !== null) owned.add(domain);
  }
  return owned;
}

/** Every token-shaped string the exchange returned, read before strict
 * validation so a response that fails the schema is still revoked. */
function issuedCredentials(body: unknown): string[] {
  if (typeof body !== "object" || body === null) return [];
  const { access_token: access, refresh_token: refresh } = body as Record<string, unknown>;
  // Observed 2026-10-30: refresh_token is the same JWT. Should Hostinger ever
  // issue a distinct one, it dies with the access token rather than outliving it.
  return [
    ...new Set([access, refresh].filter((v): v is string => typeof v === "string" && v.length > 0)),
  ];
}

interface ExistingSet {
  /** Zone-relative, lower-case, "@" for the apex: the same form hostingerZoneBody writes. */
  name: string;
  type: string;
  /** Values of the enabled records, TXT quoting removed. */
  active: string[];
}

/** A zone record name in the form our own record names take, or null when it
 * cannot be read with confidence. "@", "" and the zone itself are the apex;
 * a fully qualified name (trailing dot or not) is made relative to the zone. */
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

// TODO(scope): Hostinger's real zone GET shape and the TXT format it stores
// on write are unproven until a live write against a Hostinger zone. Until
// then every plausible spelling is normalized here, and a name or value that
// still cannot be read refuses the one-click (conflict, then guided setup).
function normalizeZone(sets: z.infer<typeof zZone>, zone: string): ExistingSet[] {
  return sets.map((set) => {
    const name = existingName(set.name, zone);
    const type = set.type.trim().toUpperCase();
    if (name === null || !/^[A-Z0-9]+$/.test(type)) throw new HostingerError("conflict");
    const active = set.records
      .filter((r) => !r.is_disabled)
      .map((r) => {
        const value = type === "TXT" ? existingTxtValue(r.content) : r.content.trim();
        if (value === null) throw new HostingerError("conflict");
        return value;
      });
    return { name, type, active };
  });
}

/** The provider operation's own result, and the revoke that ran after it. A
 * revoke failure is reported on its own and never replaces `ok`/`error`: a
 * write that landed stays a write that landed. */
export type HostingerApplyOutcome = { revokeFailure: HostingerError | null } & (
  { ok: true } | { ok: false; error: Error }
);

/** This request owns the token's whole lifetime. Portfolio proves ownership;
 * zone GET is used only for conflict protection. Revoke always runs once the
 * operation has settled, including on malformed responses, validation
 * refusal, write failure or expiry, and cannot change that outcome.
 * No refresh, persistence, logging or telemetry belongs inside this function. */
export async function applyHostingerRecords(
  input: {
    config: HostingerConfig;
    code: string;
    verifier: string;
    domain: string;
    records: SessionRecord[];
    expiresAt: Date;
  },
  fetcher: typeof fetch = fetch,
): Promise<HostingerApplyOutcome> {
  async function request(stage: HostingerStage, url: string, init: RequestInit): Promise<Response> {
    try {
      const response = await fetcher(url, {
        ...init,
        cache: "no-store",
        redirect: "error",
        signal: AbortSignal.timeout(10_000),
      });
      if (!response.ok) throw new HostingerError(stage, response.status);
      return response;
    } catch (error) {
      if (error instanceof HostingerError) throw error;
      throw new HostingerError(stage);
    }
  }
  async function json(stage: HostingerStage, response: Response): Promise<unknown> {
    try {
      return await response.json();
    } catch {
      throw new HostingerError(stage);
    }
  }
  /** Every credential gets its revoke attempt; the first failure is returned. */
  async function revokeAll(tokens: string[]): Promise<HostingerError | null> {
    let failure: HostingerError | null = null;
    for (const credential of tokens) {
      try {
        await request("revoke", HOSTINGER_REVOKE_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token: credential, client_id: input.config.clientId }),
        });
      } catch (error) {
        failure ??= error instanceof HostingerError ? error : new HostingerError("revoke");
      }
    }
    return failure;
  }

  let credentials: string[] = [];
  async function operate(): Promise<void> {
    const exchanged = await json(
      "exchange",
      await request("exchange", HOSTINGER_TOKEN_URL, {
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
    const token = zToken.safeParse(exchanged);
    if (!token.success) throw new HostingerError("exchange");
    const headers = {
      Authorization: `Bearer ${token.data.access_token}`,
      "Content-Type": "application/json",
    };
    const portfolio = zPortfolio.safeParse(
      await json(
        "portfolio",
        await request("portfolio", `${HOSTINGER_API_ORIGIN}/api/domains/v1/portfolio`, { headers }),
      ),
    );
    if (!portfolio.success) throw new HostingerError("portfolio");
    const domain = normalizeDomain(input.domain);
    const apex = apexOf(domain);
    const owned = ownedDomains(portfolio.data);
    const zone = owned.has(apex) ? apex : owned.has(domain) ? domain : null;
    if (zone === null) throw new HostingerError("ownership");
    hostingerZoneBody(domain, input.records, zone);
    const zoneUrl = `${HOSTINGER_API_ORIGIN}/api/dns/v1/zones/${encodeURIComponent(zone)}`;
    const current = zZone.safeParse(
      await json("read", await request("read", zoneUrl, { headers })),
    );
    if (!current.success) throw new HostingerError("read");
    const existing = normalizeZone(current.data, zone);
    // Appending an incompatible address/mail route or a second SPF policy is
    // unsafe even with overwrite:false. Leave it visible for guided resolution.
    const recordsToWrite: SessionRecord[] = [];
    for (const record of input.records) {
      const name = zoneRelativeName(
        domainToASCII(fqdnFor(record.host, domain)).toLowerCase(),
        zone,
      );
      const matches = (value: string) =>
        recordAnswerMatches(record.type, record.value, value, record.priority);
      const policy = record.type === "TXT" ? emailPolicyKindOf(record.value) : null;
      let alreadyPresent = false;
      for (const set of existing) {
        if (set.name !== name || !set.active.length) continue;
        if (set.type !== record.type) {
          if (set.type === "CNAME" || record.type === "CNAME") throw new HostingerError("conflict");
          continue;
        }
        const conflicting = set.active.some((value) => !matches(value));
        alreadyPresent ||= set.active.some(matches);
        if (
          conflicting &&
          (!allowsCoexistingValues(record.type) ||
            (policy !== null &&
              set.active.some((value) => emailPolicyKindOf(value) === policy && !matches(value))))
        )
          throw new HostingerError("conflict");
      }
      if (!alreadyPresent) recordsToWrite.push(record);
    }
    if (recordsToWrite.length === 0) return;
    const body = hostingerZoneBody(
      domain,
      recordsToWrite,
      zone,
      new Set(existing.map((set) => `${set.name}:${set.type}`)),
    );
    await request("validate", `${zoneUrl}/validate`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });
    if (input.expiresAt.getTime() <= Date.now()) throw new HostingerError("write");
    await request("write", zoneUrl, { method: "PUT", headers, body: JSON.stringify(body) });
  }

  let settled: { ok: true } | { ok: false; error: Error };
  try {
    await operate();
    settled = { ok: true };
  } catch (error) {
    // Every provider failure is already a fixed-stage HostingerError; anything
    // else is a defect here and keeps its own error for the caller to report.
    settled = { ok: false, error: error instanceof Error ? error : new HostingerError("exchange") };
  }
  // The outcome is fixed before the revoke runs, so a revoke failure can
  // only ever be reported next to it, never in its place.
  return { ...settled, revokeFailure: await revokeAll(credentials) };
}
