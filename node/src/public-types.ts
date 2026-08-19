// The SDK's PUBLISHED type surface — plain TypeScript, zero imports.
//
// Why this file exists (the F-010 "revisit AT publish time" item, discharged
// at publish 2026-07-31): tsup's rollup-dts pass keeps bare
// `from "@dodomain/core/..."` / `from "zod"` imports in dist/index.d.ts
// (noExternal only governs the esbuild JS bundle; dts.resolve corrupts zod's
// types — full history in tsup.config.ts). An external `npm install
// @dodomain/node` consumer cannot resolve those, so the public API is typed
// against THIS import-free module instead and the emitted d.ts is
// self-contained.
//
// F-008 (no hand-typed drift) still holds: these shapes are pinned against
// the core zod schemas by compile-time mutual-assignability assertions in
// schema-parity.check.ts — covered by `pnpm typecheck`, which prepublishOnly
// runs, so a schema change that drifts from this file fails the publish.

/** DNS record types a connect session can carry. */
export type DnsRecordType = "A" | "AAAA" | "CNAME" | "TXT" | "MX";

/** One DNS record for the end user to create (pin: core zRecord). */
export interface DnsRecord {
  type: DnsRecordType;
  host: string;
  value: string;
  /** Required by the API for MX records. */
  priority?: number;
  ttl?: number;
}

/** Body for sessions.create (pin: core zCreateSessionInput). */
export interface CreateSessionInput {
  /**
   * OAuth-token (team-scoped) callers pass this to pick the app the session
   * belongs to. Secret-key callers omit it — the key already implies the app.
   */
  appId?: string;
  domain: string;
  /** Accepted and stored for wire-compat; consumed by nothing server-side. */
  recipe?: string;
  records: DnsRecord[];
  /** Where the hosted flow offers to send the user back (http/https only). */
  returnUrl?: string;
}

/** One requested record paired with the name verification will check for it
 * (pin: core zComposedRecord). */
export interface ComposedDnsRecord {
  type: DnsRecordType;
  /** Echoed exactly as sent. */
  host: string;
  /** What POST /verify will look up on authoritative DNS. */
  fqdn: string;
}

/** A non-fatal advisory about an ACCEPTED create (pin: core zSessionWarning).
 * Branch on `code`; the session exists either way. */
export interface SessionWarning {
  /** `duplicate_host_label`: `host` repeats the leading label of `domain`, so
   * the composed `fqdn` doubles it (e.g. "links" under "links.acme.com"). */
  code: "duplicate_host_label";
  message: string;
  host: string;
  fqdn: string;
}

/** A minted connect session (pin: core zCreateSessionResponse). */
export interface Session {
  id: string;
  token: string;
  /** ISO 8601 datetime. */
  expiresAt: string;
  connectUrl: string;
  /** The composed names this session will be verified at — one per requested
   * record, in the order they were sent. */
  records: ComposedDnsRecord[];
  /** Present only when there is something worth saying about the request. */
  warnings?: SessionWarning[];
}

// ── Connections ─────────────────────────────────────────────────────────────
// The `connections` namespace (2026-08-17). Before it, every integrator
// hand-rolled raw fetch against /api/v1/connections and hand-wrote these
// shapes — BioFlow shipped exactly that, with a comment naming this namespace
// as the swap point.

/** Last OBSERVED DNS health of a live connection (pin: core
 * zDomainConnectionStatus). `broken` means the monitor saw the record drift,
 * not that the connection was removed — read `disconnectedAt` for that. */
export type ConnectionStatus = "active" | "broken";

/** One connected domain and its live DNS health (pin: core zConnectionSummary).
 * Identical whether it arrives from `connections.list` or `connections.get`. */
export interface Connection {
  id: string;
  appId: string;
  /** The id `sessions.create` returned — the correlation handle webhook
   * payloads carry too. */
  sessionId: string;
  /** The session's domain. */
  domain: string;
  /**
   * The session's domain AGAIN, not a record name — an alias of `domain` kept
   * for wire compatibility (prod E2E wave 2, 2026-08-18). Read `recordFqdns`
   * for the names DoDomain actually looks up.
   */
  fqdn: string;
  /**
   * The fully-qualified names DoDomain verifies on authoritative DNS — one per
   * record of the session, composed under its domain (host `@` means the
   * domain itself). Empty only if the session's records are missing.
   */
  recordFqdns: string[];
  status: ConnectionStatus;
  /** ISO 8601 datetime, or null before the first successful check. */
  verifiedAt: string | null;
  /** ISO 8601 datetime, or null before the first check of any kind. */
  lastCheckedAt: string | null;
  /** ISO 8601 datetime while the record is drifted; null when healthy. */
  brokenAt: string | null;
  /** ISO 8601 datetime once disconnected — non-null means DoDomain stopped
   * monitoring this connection. */
  disconnectedAt: string | null;
  createdAt: string;
}

/** Filters for connections.list (pin: core zListConnectionsQuery input). All
 * optional; the server applies its own defaults for anything omitted. */
export interface ListConnectionsInput {
  /** Narrow to one app. Secret-key callers may only restate their own app. */
  appId?: string;
  /** Exact match on the session's domain. */
  domain?: string;
  /** 1–100; the server defaults to 50. */
  limit?: number;
  /** The `nextCursor` of a previous page. Opaque — never construct one. */
  cursor?: string;
  /** Include connections you disconnected. Defaults to false ("what is live"). */
  includeDisconnected?: boolean;
}

/** One page of connections (pin: core zListConnectionsResponse). */
export interface ListConnectionsResult {
  connections: Connection[];
  /** Pass back as `cursor` for the next page; null on the last page. */
  nextCursor: string | null;
}

/** Outcome of connections.delete (pin: core zDisconnectConnectionResponse).
 * Idempotent: a repeat returns the ORIGINAL timestamp with
 * `alreadyDisconnected: true` and emits no second webhook. */
export interface DisconnectConnectionResult {
  id: string;
  /** ISO 8601 datetime the connection was archived at. */
  disconnectedAt: string;
  /** false = this call performed the disconnect; true = it was already gone. */
  alreadyDisconnected: boolean;
}

/** Outcome of connections.reverify (pin: core zReverifyConnectionResponse).
 * The recheck runs in DoDomain's worker — the RESULT arrives as a
 * connection.verified / connection.failed webhook, not in this response. */
export interface ReverifyConnectionResult {
  accepted: true;
}

// ── Sessions (read) ─────────────────────────────────────────────────────────

/** A session read back by ID with your credential (pin: core zIntegratorSession).
 *
 * This is the shape `sessions.get` returns — NOT the public token-arm shape.
 * Two things it can do that a token read cannot: it is addressable by the
 * `sessionId` every webhook payload carries (the token never appears in one),
 * and it reads an EXPIRED session instead of refusing it. */
export interface IntegratorSession {
  id: string;
  /** The app that owns the session. */
  appId: string;
  domain: string;
  /** The COMPOSED names DoDomain verifies on authoritative DNS — not the raw
   * record echo. Same shape `sessions.create` returned. */
  records: ComposedDnsRecord[];
  recipe: string | null;
  /** Lifecycle state, e.g. "pending" / "verified" / "expired". Do NOT infer
   * expiry from this — read `expired`. */
  status: string;
  /** 1 = Cloudflare one-click, 2 = Domain Connect, 3 = manual. `null` together
   * with `detectedProvider` means detection has not run yet — never a failure. */
  tier: number | null;
  detectedProvider: string | null;
  /** The connection id once the session finalized; null until then. */
  connectionId: string | null;
  createdAt: string;
  expiresAt: string;
  /** DERIVED at read (`expiresAt <= now`), so it is already true in the window
   * before the reaper persists `status: "expired"`. */
  expired: boolean;
}

// ── Apps ────────────────────────────────────────────────────────────────────

/** One app on the caller's team (pin: an element of core zListAppsResponse).
 * Only the publishable key is ever returned — secret material is absent from
 * this contract by construction. */
export interface App {
  id: string;
  name: string;
  /** The publishable widget key (`pk_*`) — safe to ship to a browser. */
  publicKey: string;
  sandbox: boolean;
  /** Integrator branding; null until configured. */
  logoUrl: string | null;
  brandColor: string | null;
  createdAt: string;
}

/** Result of apps.list (pin: core zListAppsResponse). A secret key sees exactly
 * its OWN app; an OAuth token with `apps:read` sees the whole team. */
export interface ListAppsResult {
  apps: App[];
}

// ── Domains ─────────────────────────────────────────────────────────────────

/** Which connect flow a domain qualifies for: 1 = Cloudflare one-click,
 * 2 = Domain Connect one-click, 3 = manual records. */
export type DetectionTier = 1 | 2 | 3;

/** How the connect flow will be driven for the detected provider. */
export type DetectionMethod = "oauth" | "domain-connect" | "guided";

/** How sure detection is of the provider match. */
export type DetectionConfidence = "high" | "medium" | "low";

/** Copy for walking an end user through creating records by hand at their
 * provider (pin: core zProviderGuide). */
export interface ProviderGuide {
  provider: string;
  label: string;
  dashboardUrl?: string;
  /** How this provider wants a record host written, e.g. "subdomain only". */
  hostFormat: string;
  /** What this provider calls the zone apex in its own record editor. */
  apexToken: "@" | "(blank)" | "%domain%";
  steps: string[];
  notes?: string[];
}

/** Body for domains.check (pin: core zCheckDomainInput). */
export interface CheckDomainInput {
  /** The bare domain, at most 253 octets (the DNS name ceiling). */
  domain: string;
}

/** Pre-flight verdict for a domain (pin: core zCheckDomainResponse). Nothing is
 * persisted by the call that returns this. */
export interface CheckDomainResult {
  /** The domain as submitted, trimmed. */
  domain: string;
  /** The zone that OWNS the records — the registrable apex, or a delegated
   * subzone when one exists. This is the zone the end user opens. */
  zone: string;
  provider: string;
  label: string;
  tier: DetectionTier;
  method: DetectionMethod;
  confidence: DetectionConfidence;
  nameServers: string[];
  /** `discovered: false` ⇒ no `providerId`/`providerName`. */
  domainConnect: {
    discovered: boolean;
    providerId?: string;
    providerName?: string;
  };
  guide: ProviderGuide;
}

// ── Webhook endpoints ───────────────────────────────────────────────────────
// The delivery targets an app POSTs its events to — the same set the dashboard's
// Webhooks card manages, so this can be driven from CI/IaC instead of clicked.

/** One registered delivery target (pin: core zWebhookEndpointSummary).
 * Deliberately carries NO `secret`: the signing secret is show-once, so no read
 * surface can ever hand back the ability to forge our signatures. */
export interface WebhookEndpoint {
  id: string;
  appId: string;
  /** The NORMALIZED url stored for the endpoint, not the raw input string. */
  url: string;
  createdAt: string;
}

/** Result of webhookEndpoints.list (pin: core zListWebhookEndpointsResponse). */
export interface ListWebhookEndpointsResult {
  endpoints: WebhookEndpoint[];
}

/** Body for webhookEndpoints.create and .update (pin: core
 * zWebhookEndpointInput). One shape, because `url` is the only mutable field. */
export interface WebhookEndpointInput {
  /** Must be https and must not resolve to a localhost/private/link-local
   * address; an app cannot register the same normalized url twice. Both
   * refusals arrive as a `DoDomainError` with `status: 400`. */
  url: string;
}

/** What create and rotateSecret return (pin: core
 * zWebhookEndpointSecretResponse) — the endpoint PLUS its plaintext signing
 * secret.
 *
 * **SHOW-ONCE.** `secret` appears in these two responses and in no read surface
 * ever again: store it the moment you receive it. Feed it to `verifyWebhook` as
 * the `secret` argument. */
export interface WebhookEndpointWithSecret extends WebhookEndpoint {
  /** `whsec_...` — store it now; nothing returns it a second time. */
  secret: string;
}

/** Outcome of webhookEndpoints.delete (pin: core
 * zDeleteWebhookEndpointResponse). A body rather than a bare 204 so an
 * automated caller can log WHAT it removed. */
export interface DeleteWebhookEndpointResult {
  id: string;
  deleted: true;
}

// ── Credentials ─────────────────────────────────────────────────────────────

/** Outcome of keys.rotate (pin: core zRotateAppSecretKeyResponse).
 *
 * **NO GRACE WINDOW.** The key that authorized the call stopped authenticating
 * the instant this was produced, so this object is the ONLY copy of the new
 * secret — a caller that drops it has locked itself out of the API and must
 * rotate again from the dashboard. */
export interface RotateSecretKeyResult {
  appId: string;
  /** Echoed UNCHANGED — rotation never touches the publishable key. Assert on
   * it to confirm an automated rotation rewrote the app you meant. */
  publicKey: string;
  /** The NEW `dd_sk_...`. Persist it before doing anything else. */
  secretKey: string;
  rotatedAt: string;
}

// ── Webhooks ────────────────────────────────────────────────────────────────

/** Every event type DoDomain delivers (pin: core zWebhookEventType). */
export type WebhookEventType =
  | "connection.verified"
  | "connection.failed"
  | "connection.disconnected"
  | "session.completed"
  | "session.abandoned";

/** The canonical webhook envelope (pin: core zWebhookEvent). Dedupe on `id`;
 * branch on `type`. `data` is left as an open record on purpose — the payload
 * varies per `type` and gains fields additively. */
export interface WebhookEvent {
  /** Stable idempotency key — the same value on every retry of one delivery. */
  id: string;
  type: WebhookEventType;
  /** ISO 8601 datetime. */
  occurredAt: string;
  data: Record<string, unknown>;
}

/** The EXACT body DoDomain PUTs on the wire (pin: core zWebhookEventWire):
 * the canonical envelope plus the deprecated `event` alias. Type your receiver
 * against `WebhookEvent` unless you still read the alias. */
export interface WebhookEventWire extends WebhookEvent {
  /**
   * @deprecated Legacy alias for `type`, byte-identical to it. Present only so
   * receivers written against the pre-2026-08-06 `{event,data}` body keep
   * working. New receivers must read `type` and dedupe on `id`.
   */
  event: WebhookEventType;
}

/**
 * Verifies a DoDomain webhook signature header over the RAW request body.
 * (pin: core verifyWebhook)
 */
export type VerifyWebhook = (
  secret: string,
  body: string,
  header: string,
  toleranceMs?: number,
  nowMs?: number,
) => boolean;
