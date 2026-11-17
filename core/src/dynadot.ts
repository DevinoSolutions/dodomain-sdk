// Dynadot one-click connect (T-16321) over Dynadot's OAuth-protected MCP server.
// Proven live 2026-11-10 (by hand, not by this module): protected resource
// https://mcp.dynadot.com, authorization server https://oauth.dynadot.com,
// PKCE S256 only, a PUBLIC client (no secret) registered once by an operator at
// https://oauth.dynadot.com/connect/register. The authorize request carries
// `resource` and NO scope (Dynadot grants one all-or-nothing permission). The
// token response is {access_token (JWT), token_type "Bearer", expires_in 1799}:
// no refresh token, no scope.
//
// That grant can register, renew and delete domains (116 tools). This adapter
// calls ONLY `get_domain_records` and `set_domain_records` (plus the MCP
// `initialize` handshake); scripts/check-dynadot-bans.sh fails the build on any
// other tool name here. `set_domain_records` REPLACES the whole zone unless
// `add_dns_to_current_setting` is true, so every write sends it true (gated too).
//
// Revocation: Dynadot's POST /oauth/revoke refuses our public client ("missing
// or unresolvable redirect_uri"), so no revoke works. The token is therefore
// exchanged and used INSIDE one callback request and then dropped: it is never
// returned, stored, logged or reported.
// TODO(T-16321): the dropped token stays valid at Dynadot until it expires on
// its own (expires_in 1799, about 30 minutes). Report the broken public-client
// revoke to Dynadot, and revoke here once it works.
import { createHash, randomBytes } from "node:crypto";
import { domainToASCII } from "node:url";

import { apexOf } from "./apex.ts";
import { emailPolicyKindOf } from "./email-records.ts";
import {
  allowsCoexistingValues,
  recordValueMatches,
  requiresPriority,
  tierCanWrite,
} from "./record-capabilities.ts";
import { fqdnFor, zoneRelativeName, zRecords, type SessionRecord } from "./records.ts";
import { z } from "./zod-runtime.ts";

export const DYNADOT_AUTHORIZE_URL = "https://oauth.dynadot.com/oauth/authorize";
export const DYNADOT_TOKEN_URL = "https://oauth.dynadot.com/oauth/token";
/** The RFC 8707 resource the token is minted for (the MCP server). */
export const DYNADOT_MCP_RESOURCE = "https://mcp.dynadot.com";
export const DYNADOT_MCP_URL = "https://mcp.dynadot.com/mcp";
export const DYNADOT_CALLBACK_PATH = "/api/v1/dynadot/callback";
/** How long a started approval may take before its state is refused and reaped. */
export const DYNADOT_FLOW_SECONDS = 1800;
const MCP_PROTOCOL_VERSION = "2025-06-18";
/** set_domain_records schema limits (read 2026-11-10). */
const MAX_MAIN_RECORDS = 20;
const MAX_SUB_RECORDS = 100;
/** Existing row types the shared conflict rules can reason about. */
const PLAIN_DNS_TYPES: ReadonlySet<string> = new Set([
  "A",
  "AAAA",
  "CNAME",
  "TXT",
  "MX",
  "SRV",
  "CAA",
  "NS",
]);
/** The bound on one MCP response body we are willing to parse. */
const MAX_RESPONSE_CHARS = 1_000_000;

export interface DynadotConfig {
  clientId: string;
  redirectUri: string;
}

const zState = z
  .string()
  .max(450)
  .regex(/^[A-Za-z0-9_-]{32}(?:~e(?:\.[A-Za-z0-9_-]+)?)?$/);
export const zDynadotCallback = z.union([
  z.object({ state: zState, code: z.string().min(1).max(4096), error: z.never().optional() }),
  z.object({
    state: zState,
    error: z.string().regex(/^[a-z0-9_]{1,64}$/),
    code: z.never().optional(),
  }),
]);

export function dynadotPkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}

/** The exact authorize parameters proven live: no `scope` (one grant only). */
export function buildDynadotAuthorizeUrl(
  config: DynadotConfig,
  state: string,
  challenge: string,
): string {
  if (!config.clientId || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) {
    throw new Error("Dynadot: invalid OAuth configuration or PKCE challenge");
  }
  const url = new URL(DYNADOT_AUTHORIZE_URL);
  url.search = new URLSearchParams({
    response_type: "code",
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    code_challenge: challenge,
    code_challenge_method: "S256",
    state: zState.parse(state),
    resource: DYNADOT_MCP_RESOURCE,
  }).toString();
  return url.toString();
}

type DynadotStage =
  | "records"
  | "exchange"
  | "initialize"
  | "mcp_not_enabled"
  | "read"
  | "domain"
  | "conflict"
  | "write";
/** Only fixed stages and HTTP status escape the credential boundary. No response
 * body, provider text, transport exception, token, or cause is ever attached. */
export class DynadotError extends Error {
  readonly stage: DynadotStage;
  readonly status: number | undefined;
  constructor(stage: DynadotStage, status?: number) {
    super(`Dynadot ${stage} failed${status === undefined ? "" : ` (HTTP ${status})`}`);
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
  if (normalized === null) throw new DynadotError("records");
  return normalized;
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

/** One `dns_main_list` row (the zone apex). */
export interface DynadotMainRecord {
  record_type: string;
  record_value1: string;
  record_value2?: string;
}
/** One `dns_sub_list` row; `sub_host` is relative to the domain. */
export interface DynadotSubRecord extends DynadotMainRecord {
  sub_host: string;
}
/** What one requested record becomes: an apex row or a sub-host row. */
export type DynadotRecordBody =
  { list: "main"; row: DynadotMainRecord } | { list: "sub"; row: DynadotSubRecord };

/**
 * The Dynadot domain a session's records live in: the registrable apex, since
 * Dynadot holds DNS per registered domain. Every record must sit inside it.
 * Apex records go in `dns_main_list`, everything below it in `dns_sub_list`
 * with `sub_host` relative to the domain. TXT is the RAW value, CNAME and MX
 * targets carry no trailing dot, and MX priority is `record_value2`.
 * TODO(T-16321): the first live write must confirm TXT publishes raw (no
 * literal quotes, DigitalOcean's #724 lesson) and that targets without a
 * trailing dot are taken as absolute names.
 */
export function dynadotRecordBodies(
  domain: string,
  records: SessionRecord[],
): { zone: string; bodies: DynadotRecordBody[] } {
  const normalized = normalizeDomain(domain);
  const zone = apexOf(normalized);
  const parsed = zRecords.min(1).safeParse(records);
  if (!parsed.success) throw new DynadotError("records");
  const bodies = parsed.data.map((record): DynadotRecordBody => {
    if (!tierCanWrite("dynadot_oauth", record.type)) throw new DynadotError("records");
    const fqdn = domainToASCII(fqdnFor(record.host, normalized)).toLowerCase();
    if (!fqdn || (fqdn !== zone && !fqdn.endsWith(`.${zone}`))) throw new DynadotError("records");
    if (
      requiresPriority(record.type) &&
      (record.priority === undefined || record.priority < 0 || record.priority > 65535)
    )
      throw new DynadotError("records");
    const value =
      record.type === "CNAME" || record.type === "MX"
        ? record.value.replace(/\.$/, "")
        : record.value;
    const row: DynadotMainRecord = {
      record_type: record.type,
      record_value1: value,
      ...(record.type === "MX" ? { record_value2: String(record.priority) } : {}),
    };
    const name = zoneRelativeName(fqdn, zone);
    return name === "@" ? { list: "main", row } : { list: "sub", row: { sub_host: name, ...row } };
  });
  return { zone, bodies };
}

// ── The existing-records read (shape NOT yet proven) ────────────────────────

/** One record as read back, in the vocabulary of set_domain_records. */
interface ExistingRow {
  /** "@" for a main (apex) record, else the lower-case sub host. */
  name: string;
  type: string;
  value1: string;
  value2: string | undefined;
}

const MAIN_KEYS = ["dns_main_list", "main_records", "main_domains", "MainDomains", "main"];
const SUB_KEYS = ["dns_sub_list", "sub_records", "sub_domains", "SubDomains", "sub"];
const TYPE_KEYS = ["record_type", "RecordType", "type"];
const VALUE1_KEYS = ["record_value1", "Value", "value", "value1", "RecordValue1"];
const VALUE2_KEYS = ["record_value2", "Value2", "value2", "RecordValue2", "priority", "Distance"];
const SUB_HOST_KEYS = ["sub_host", "Subhost", "SubHost", "subhost", "sub_domain"];
const TTL_KEYS = ["ttl", "TTL", "Ttl"];

function isRecordObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function pick(row: Record<string, unknown>, keys: readonly string[]): unknown {
  for (const key of keys) if (Object.hasOwn(row, key)) return row[key];
  return undefined;
}

function scalar(value: unknown): string | undefined {
  if (typeof value === "string") return value;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return undefined;
}

/** The first object (depth-first, bounded) carrying a main or sub record list. */
function findRecordSet(value: unknown, depth = 0): Record<string, unknown> | null {
  if (depth > 5) return null;
  if (isRecordObject(value)) {
    if ([...MAIN_KEYS, ...SUB_KEYS].some((key) => Array.isArray(value[key]))) return value;
    for (const child of Object.values(value)) {
      const found = findRecordSet(child, depth + 1);
      if (found !== null) return found;
    }
  }
  return null;
}

function existingRows(list: unknown, main: boolean): ExistingRow[] | null {
  if (list === undefined) return [];
  if (!Array.isArray(list)) return null;
  const rows: ExistingRow[] = [];
  for (const item of list) {
    if (!isRecordObject(item)) return null;
    const type = scalar(pick(item, TYPE_KEYS))?.trim().toUpperCase();
    const value1 = scalar(pick(item, VALUE1_KEYS))?.trim();
    const value2Raw = pick(item, VALUE2_KEYS);
    const value2 = value2Raw === undefined || value2Raw === null ? undefined : scalar(value2Raw);
    if (!type || !/^[A-Z0-9 _-]{1,32}$/.test(type) || value1 === undefined) return null;
    if (value2Raw !== undefined && value2Raw !== null && value2 === undefined) return null;
    let name = "@";
    if (!main) {
      const sub = scalar(pick(item, SUB_HOST_KEYS))?.trim().toLowerCase().replace(/\.$/, "");
      if (!sub || !/^(?:[a-z0-9_*-]+\.)*[a-z0-9_*-]+$/.test(sub)) return null;
      name = sub;
    }
    rows.push({ name, type, value1, value2: value2?.trim() });
  }
  return rows;
}

/**
 * What get_domain_records returned, parsed defensively. The tool's output shape
 * is NOT proven yet: the parser accepts the set_domain_records vocabulary
 * (`dns_main_list` / `dns_sub_list` of `{record_type, record_value1,
 * record_value2, sub_host}`) and Dynadot's api3 `get_dns` shape
 * (`MainDomains` / `SubDomains` of `{RecordType, Value, Value2, Subhost}`), in
 * `structuredContent` or as JSON text in `content[0].text`. Anything it cannot
 * read fully returns null and the caller REFUSES (a conflict notice) rather
 * than guess, because the write echoes the existing apex rows back.
 * TODO(T-16321): pin the real output shape on the first live run and narrow
 * this parser to it.
 */
export function parseDynadotRecords(
  result: unknown,
): { main: ExistingRow[]; sub: ExistingRow[]; ttl: number | undefined } | null {
  if (!isRecordObject(result)) return null;
  const candidates: unknown[] = [];
  if (result.structuredContent !== undefined) candidates.push(result.structuredContent);
  if (Array.isArray(result.content)) {
    for (const part of result.content) {
      if (isRecordObject(part) && part.type === "text" && typeof part.text === "string") {
        try {
          candidates.push(JSON.parse(part.text));
        } catch {
          // Not JSON: this part carries no record set.
        }
      }
    }
  }
  for (const candidate of candidates) {
    const set = findRecordSet(candidate);
    if (set === null) continue;
    const main = existingRows(pick(set, MAIN_KEYS), true);
    const sub = existingRows(pick(set, SUB_KEYS), false);
    if (main === null || sub === null) return null;
    const ttlRaw = pick(set, TTL_KEYS);
    const ttl =
      typeof ttlRaw === "number" && Number.isInteger(ttlRaw) && ttlRaw > 0
        ? ttlRaw
        : typeof ttlRaw === "string" && /^[1-9][0-9]{0,9}$/.test(ttlRaw)
          ? Number(ttlRaw)
          : undefined;
    return { main, sub, ttl };
  }
  return null;
}

// ── HTTP + the MCP streamable-HTTP client ───────────────────────────────────

/** HTTP errors carry only fixed stages and statuses. Never expose a body,
 * arbitrary transport exception, credential or cause outside this module. */
async function request(
  fetcher: typeof fetch,
  stage: DynadotStage,
  url: string,
  init: RequestInit,
): Promise<Response> {
  try {
    const response = await fetcher(url, {
      ...init,
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    });
    if (!response.ok) throw new DynadotError(stage, response.status);
    return response;
  } catch (error) {
    if (error instanceof DynadotError) throw error;
    throw new DynadotError(stage);
  }
}

async function text(stage: DynadotStage, response: Response): Promise<string> {
  let body: string;
  try {
    body = await response.text();
  } catch {
    throw new DynadotError(stage);
  }
  if (body.length > MAX_RESPONSE_CHARS) throw new DynadotError(stage);
  return body;
}

/** The JSON-RPC messages in an MCP response: an SSE stream (`data:` lines,
 * events split by a blank line) or a plain JSON object or batch array. */
export function parseMcpMessages(contentType: string | null, body: string): unknown[] | null {
  const messages: unknown[] = [];
  if ((contentType ?? "").toLowerCase().includes("text/event-stream")) {
    for (const event of body.split(/\r?\n\r?\n/)) {
      const data = event
        .split(/\r?\n/)
        .filter((line) => line.startsWith("data:"))
        .map((line) => line.slice(5).replace(/^ /, ""))
        .join("\n");
      if (data.trim() === "") continue;
      try {
        messages.push(JSON.parse(data));
      } catch {
        return null;
      }
    }
    return messages;
  }
  if (body.trim() === "") return messages;
  try {
    const parsed: unknown = JSON.parse(body);
    return Array.isArray(parsed) ? (parsed as unknown[]) : [parsed];
  } catch {
    return null;
  }
}

/** Read an SSE response only until the reply we wait for has arrived, then
 * release the stream: a server may keep the stream open after answering. */
async function sseUntil(
  stage: DynadotStage,
  response: Response,
  done: (message: unknown) => boolean,
): Promise<unknown[] | null> {
  const reader = response.body?.getReader();
  if (reader === undefined) return [];
  const decoder = new TextDecoder();
  let buffered = "";
  try {
    for (;;) {
      const chunk = await reader.read();
      if (!chunk.done) buffered += decoder.decode(chunk.value, { stream: true });
      if (buffered.length > MAX_RESPONSE_CHARS) throw new DynadotError(stage);
      // Only complete events (ending in a blank line) are parsed mid-stream.
      const end = chunk.done ? buffered.length : buffered.search(/\r?\n\r?\n(?![\s\S]*\r?\n\r?\n)/);
      const complete = chunk.done ? buffered : end < 0 ? "" : buffered.slice(0, end);
      const messages = parseMcpMessages("text/event-stream", complete);
      if (messages === null) return null;
      if (chunk.done || messages.some(done)) return messages;
    }
  } catch (error) {
    if (error instanceof DynadotError) throw error;
    throw new DynadotError(stage);
  } finally {
    await reader.cancel().catch(() => undefined);
  }
}

/** The only tools this adapter may call (scripts/check-dynadot-bans.sh). */
type DynadotToolName = "get_domain_records" | "set_domain_records";

const TOOL_ERROR_MCP_NOT_ENABLED = /^\s*MCP_NOT_ENABLED\b/;

/** A short-lived MCP session bound to one bearer, used inside one request. */
function mcpSession(bearer: string, fetcher: typeof fetch) {
  let sessionId: string | undefined;
  let nextId = 1;

  async function post(stage: DynadotStage, message: Record<string, unknown>): Promise<Response> {
    return request(fetcher, stage, DYNADOT_MCP_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${bearer}`,
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
        "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
        ...(sessionId === undefined ? {} : { "Mcp-Session-Id": sessionId }),
      },
      body: JSON.stringify(message),
    });
  }

  /** One JSON-RPC request; returns its `result` or throws a fixed-stage error. */
  async function rpc(
    stage: DynadotStage,
    method: string,
    params: Record<string, unknown>,
  ): Promise<{ result: Record<string, unknown>; response: Response }> {
    const id = nextId++;
    const response = await post(stage, { jsonrpc: "2.0", id, method, params });
    const contentType = response.headers.get("content-type");
    const isReply = (m: unknown) => isRecordObject(m) && m.id === id;
    const messages = (contentType ?? "").toLowerCase().includes("text/event-stream")
      ? await sseUntil(stage, response, isReply)
      : parseMcpMessages(contentType, await text(stage, response));
    if (messages === null) throw new DynadotError(stage);
    const reply = messages.find(isReply);
    if (!isRecordObject(reply) || reply.error !== undefined || !isRecordObject(reply.result))
      throw new DynadotError(stage);
    return { result: reply.result, response };
  }

  return {
    async initialize(): Promise<void> {
      const { response } = await rpc("initialize", "initialize", {
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: "DoDomain", version: "1.0.0" },
      });
      const header = response.headers.get("mcp-session-id");
      if (header !== null) {
        if (!/^[\x21-\x7E]{1,256}$/.test(header)) throw new DynadotError("initialize");
        sessionId = header;
      }
      // A notification: the server answers 202 with no body.
      await post("initialize", { jsonrpc: "2.0", method: "notifications/initialized" });
    },
    /** Tool failures arrive as HTTP 200 with `isError: true`. Only the
     * MCP_NOT_ENABLED code is distinguished; no provider text escapes. */
    async callTool(
      stage: DynadotStage,
      name: DynadotToolName,
      args: Record<string, unknown>,
    ): Promise<Record<string, unknown>> {
      const { result } = await rpc(stage, "tools/call", { name, arguments: args });
      if (result.isError === true) {
        const first = Array.isArray(result.content) ? result.content[0] : undefined;
        const message = isRecordObject(first) && typeof first.text === "string" ? first.text : "";
        // A refused read means the domain is not readable in the approving
        // account (not there, or not on Dynadot DNS): its own stage.
        throw new DynadotError(
          TOOL_ERROR_MCP_NOT_ENABLED.test(message)
            ? "mcp_not_enabled"
            : stage === "read"
              ? "domain"
              : stage,
        );
      }
      return result;
    },
  };
}

const zToken = z.object({
  access_token: z.string().min(1),
  // Dynadot answers "Bearer"; anything else is a token we do not know how to use.
  token_type: z
    .string()
    .regex(/^bearer$/i)
    .optional(),
});

export type DynadotApplyOutcome = { ok: true } | { ok: false; error: DynadotError };

/**
 * One request owns the entire credential lifetime: exchange the code, read the
 * domain's records, refuse every conflict before the single write, then drop
 * the token (no revoke works, see the header). Add-only: the write ALWAYS sends
 * `add_dns_to_current_setting: true`, never deletes or overwrites.
 */
export async function applyDynadotRecords(
  input: {
    config: DynadotConfig;
    code: string;
    verifier: string;
    domain: string;
    records: SessionRecord[];
    expiresAt: Date;
  },
  fetcher: typeof fetch = fetch,
): Promise<DynadotApplyOutcome> {
  async function operate(): Promise<void> {
    const { zone, bodies } = dynadotRecordBodies(input.domain, input.records);
    const exchanged = await (
      await request(fetcher, "exchange", DYNADOT_TOKEN_URL, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: input.code,
          redirect_uri: input.config.redirectUri,
          client_id: input.config.clientId,
          code_verifier: input.verifier,
          resource: DYNADOT_MCP_RESOURCE,
        }).toString(),
      })
    )
      .json()
      .catch(() => {
        throw new DynadotError("exchange");
      });
    const token = zToken.safeParse(exchanged);
    if (!token.success) throw new DynadotError("exchange");
    const mcp = mcpSession(token.data.access_token, fetcher);
    await mcp.initialize();

    const read = parseDynadotRecords(
      await mcp.callTool("read", "get_domain_records", { domain_name: zone }),
    );
    // Unreadable existing records: refuse rather than guess, since the write
    // echoes the apex rows back (see below).
    if (read === null) throw new DynadotError("conflict");
    const existing = [...read.main, ...read.sub].map((row) => {
      const value = row.type === "TXT" ? existingTxtValue(row.value1) : row.value1;
      if (value === null) throw new DynadotError("conflict");
      const priority = row.value2 === undefined ? undefined : Number(row.value2);
      return {
        name: row.name,
        type: row.type,
        value,
        priority: priority !== undefined && Number.isInteger(priority) ? priority : undefined,
      };
    });

    const nameOf = (body: DynadotRecordBody) => (body.list === "main" ? "@" : body.row.sub_host);
    // Validate the entire requested batch before the write, including names
    // absent from the snapshot. Identical requests are harmless duplicates.
    for (const [index, body] of bodies.entries()) {
      for (const [otherIndex, other] of bodies.slice(0, index).entries()) {
        if (nameOf(body) !== nameOf(other)) continue;
        const type = body.row.record_type;
        const otherType = other.row.record_type;
        if (type === "CNAME" || otherType === "CNAME") {
          if (
            type !== otherType ||
            !recordValueMatches(type, input.records[index]!.value, input.records[otherIndex]!.value)
          )
            throw new DynadotError("conflict");
        }
        const policy = type === "TXT" ? emailPolicyKindOf(input.records[index]!.value) : null;
        if (
          policy !== null &&
          otherType === "TXT" &&
          emailPolicyKindOf(input.records[otherIndex]!.value) === policy &&
          input.records[index]!.value !== input.records[otherIndex]!.value
        )
          throw new DynadotError("conflict");
      }
    }
    const writes: DynadotRecordBody[] = [];
    for (const [index, body] of bodies.entries()) {
      const record = input.records[index]!;
      const name = nameOf(body);
      const policy = record.type === "TXT" ? emailPolicyKindOf(record.value) : null;
      let present = false;
      for (const row of existing) {
        if (row.name !== name) continue;
        // Dynadot also keeps non-DNS rows (URL forwarding, email forwarding)
        // that occupy a name in ways the shared rules cannot judge: refuse.
        if (!PLAIN_DNS_TYPES.has(row.type)) throw new DynadotError("conflict");
        if (row.type !== record.type) {
          if (row.type === "CNAME" || record.type === "CNAME") throw new DynadotError("conflict");
          continue;
        }
        present ||= recordValueMatches(record.type, record.value, row.value, {
          expectedPriority: record.priority,
          actualPriority: row.priority,
        });
        // An existing member can satisfy any requested value in this RRset.
        // Values outside that set still follow the shared conflict policy.
        const requested = bodies.some((candidate, candidateIndex) => {
          if (nameOf(candidate) !== name || candidate.row.record_type !== record.type) return false;
          const expected = input.records[candidateIndex]!;
          return recordValueMatches(expected.type, expected.value, row.value, {
            expectedPriority: expected.priority,
            actualPriority: row.priority,
          });
        });
        if (
          !requested &&
          (!allowsCoexistingValues(body.row.record_type) ||
            (policy !== null && emailPolicyKindOf(row.value) === policy))
        )
          throw new DynadotError("conflict");
      }
      if (
        !present &&
        !writes.some(
          (write) =>
            nameOf(write) === name &&
            write.row.record_type === body.row.record_type &&
            write.row.record_value1 === body.row.record_value1 &&
            write.row.record_value2 === body.row.record_value2,
        )
      )
        writes.push(body);
    }
    if (writes.length === 0) return;

    // dns_main_list in add mode: the schema says it is REQUIRED when
    // add_dns_to_current_setting is true, but not what it must hold when we only
    // add sub records. The safest reading, whichever way Dynadot treats it: send
    // every existing apex row back exactly as read, plus our new apex rows, so
    // an "add" keeps them and a "replace the main list" cannot lose one.
    // TODO(T-16321): prove on the first live write that echoed apex rows are
    // neither duplicated nor altered, and what an empty zone apex needs.
    const mainList: DynadotMainRecord[] = [
      ...read.main.map((row) => ({
        record_type: row.type,
        record_value1: row.value1,
        ...(row.value2 === undefined ? {} : { record_value2: row.value2 }),
      })),
      ...writes.flatMap((body) => (body.list === "main" ? [body.row] : [])),
    ];
    const subList = writes.flatMap((body) => (body.list === "sub" ? [body.row] : []));
    if (mainList.length > MAX_MAIN_RECORDS || subList.length > MAX_SUB_RECORDS)
      throw new DynadotError("records");
    if (input.expiresAt.getTime() <= Date.now()) throw new DynadotError("write");
    await mcp.callTool("write", "set_domain_records", {
      domain_name: zone,
      dns_main_list: mainList,
      dns_sub_list: subList,
      // Dynadot's TTL is one value per domain: send back the one we read so the
      // write never changes it. TODO(T-16321): confirm on the first live write
      // that leaving it out (nothing read) keeps the current TTL.
      ...(read.ttl === undefined ? {} : { ttl: read.ttl }),
      // NEVER false or absent: without it the call REPLACES the whole zone.
      add_dns_to_current_setting: true,
    });
  }

  try {
    await operate();
    return { ok: true };
  } catch (error) {
    // Rebuilt from fixed fields so no provider-side stack or value travels on.
    return {
      ok: false,
      error:
        error instanceof DynadotError
          ? new DynadotError(error.stage, error.status)
          : new DynadotError("write"),
    };
  }
}
