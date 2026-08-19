// The session-payload + webhook-event zod schemas (F-008) — the ONE home for
// these two cross-package boundary shapes. Client-safe (no `node:` imports),
// so this flows through to client components exactly like records.ts.
//
// NOTE: this file deliberately does not export a bare `CreateSessionInput`
// type alias. Consumers that need the inferred type derive it locally:
// `type X = z.infer<typeof zCreateSessionInput>` (see
// packages/node/src/index.ts) — the schema VALUE (the single source of
// truth) is exported either way.

import { z } from "zod";

import { BRAND_COLOR_PATTERN } from "./branding.ts";
import type { ProviderGuide } from "./guides.ts";
import type { ComposedRecord, RecordHostWarning } from "./records.ts";
import { zRecord, zRecords } from "./records.ts";

// ── POST /api/v1/sessions ───────────────────────────────────────────────────
// Replaces apps/web's local `BodySchema` + the node SDK's hand-typed
// `CreateSessionInput` interface. Every rule a session body must satisfy lives
// HERE, so a single `.safeParse()` is the one gate a caller needs.
//
// A session that parses must be CONNECTABLE. Two shapes used to parse into a
// dead end and are now rejected up front, because 201 + a connectUrl the user
// cannot finish is worse than a 400 the integrator sees in development:
//   • recipe-only. `ConnectSession.recipe` is read by nothing — the tier-2
//     Domain Connect start route compiles a recipe from the session's RECORDS
//     (apps/web/src/lib/dc-config.ts), and the docs already say sending a
//     recipe id does nothing useful today. `records` is therefore required;
//     `recipe` stays accepted (and stored) for wire-compat, but no longer
//     substitutes for records.
//   • no domain. The old `.optional()` let the route store `domain ?? ""`,
//     which renders an empty <h1> on the hosted page and makes detect fail
//     `invalid_request` — a repair that only moved the error somewhere less
//     legible. Required and hostname-shaped instead.
const zDomainName = z
  .string()
  .trim()
  .max(253, { message: "Domain is too long (253 characters max)." })
  // Two-or-more DNS labels, ≤63 chars each, no leading/trailing hyphen. Case
  // is accepted as sent (DNS is case-insensitive) but a TRAILING ROOT DOT is
  // not: the value is stored and compared as-is against verify's fqdns, so one
  // canonical stored spelling is worth more than accepting a rare one. Rejects
  // what the empty-string repair used to swallow — a URL, a host:port, a bare
  // single label.
  .regex(/^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i, {
    message: "Enter a domain like app.customer.com (no scheme, port, or trailing dot).",
  });

export const zCreateSessionInput = z.object({
  // W4 MCP: OAuth-token callers are TEAM-scoped (not app-scoped like a
  // dd_sk_ secret key), so they pass appId to pick which app the session
  // belongs to. API-key callers' app is implicit in the key; if an API-key
  // caller sends a mismatching appId the route rejects it — that's route
  // logic, not schema logic.
  appId: z.string().min(1).optional(),
  domain: zDomainName,
  /** Accepted and stored for wire-compat; consumed by nothing (see above). */
  recipe: z.string().optional(),
  records: zRecords,
  /**
   * Where the hosted flow offers to send the user back. Rendered as an <a
   * href> on the connect page (connect-flow.tsx) and echoed by the public
   * session GET, so the SCHEME is constrained here rather than left to
   * React's internal blocklist: bare `z.url()` accepts `javascript:`,
   * `data:`, and `vbscript:` (verified against zod 4.4.3), which would make an
   * integrator-supplied string an execution vector on our own origin.
   * Embedded credentials are refused the same way zLogoUrl refuses them.
   */
  returnUrl: z
    .url({ protocol: /^https?$/, message: "returnUrl must be an http:// or https:// URL." })
    .max(2048, { message: "returnUrl is too long (2048 characters max)." })
    .refine((value) => !hasEmbeddedCredentials(value), {
      message: "returnUrl must not contain embedded credentials.",
    })
    .optional(),
});

/** True when a URL string carries a userinfo component ("https://user:pw@host").
 * Browsers hide it, it travels with the request, and it is never something an
 * integrator needs on a link we render — refused on every URL this file
 * accepts (returnUrl above, zLogoUrl below). Unparseable input answers `true`
 * (refused) so a caller can never reach a permissive default. */
function hasEmbeddedCredentials(value: string): boolean {
  try {
    const url = new URL(value);
    return url.username !== "" || url.password !== "";
  } catch {
    return true;
  }
}

// One requested record paired with the fully-qualified name verification will
// check for it (F3). Derived from zRecord — `type` and `host` are PICKED off the
// one record schema rather than re-declared, so the composed view can never
// disagree with the shape it composes. `satisfies z.ZodType<ComposedRecord>`
// pins it to records.ts's pure composeRecords() output, the zProviderGuide
// idiom: change one without the other and typecheck fails.
export const zComposedRecord = zRecord.pick({ type: true, host: true }).extend({
  /** What POST /verify will look up on authoritative DNS. */
  fqdn: z.string().min(1),
}) satisfies z.ZodType<ComposedRecord>;

/**
 * A non-fatal advisory attached to an ACCEPTED create (F3). Warnings are not
 * errors and never change a status code — the session is created either way.
 * Branch on `code`; the vocabulary is closed (a new code is an additive enum
 * member) so a receiver can switch on it instead of matching prose.
 */
export const zSessionWarning = z.object({
  code: z.enum(["duplicate_host_label"]),
  message: z.string().min(1),
  host: z.string(),
  fqdn: z.string().min(1),
}) satisfies z.ZodType<RecordHostWarning>;

export type SessionWarning = z.infer<typeof zSessionWarning>;

// Replaces the node SDK's hand-typed `Session` interface.
//
// F3 (BioFlow live E2E 2026-08-12): `records` and `warnings` are ADDITIVE
// fields on a response body — every pre-existing field is byte-identical, and
// an integrator that ignores both keeps behaving exactly as before. They exist
// because the composed fqdn — the name we will actually monitor — used to
// appear NOWHERE until verification failed: a caller sending
// `domain: "links.acme.com"` with `host: "links"` got a 200 and discovered
// "links.links.acme.com" only from a failing verify. `records` is required (the
// route always builds it from the same helper verification uses), `warnings` is
// present only when something is worth saying.
export const zCreateSessionResponse = z.object({
  id: z.string(),
  token: z.string().min(1),
  expiresAt: z.iso.datetime(),
  connectUrl: z.string().min(1),
  /** The composed names this session will be verified at — one per requested record. */
  records: z.array(zComposedRecord),
  /** Advisories about an accepted request; omitted when there are none. */
  warnings: z.array(zSessionWarning).optional(),
});

export type CreateSessionResponse = z.infer<typeof zCreateSessionResponse>;

// ── GET /api/v1/sessions/:token ─────────────────────────────────────────────
// The public session shape — deferred by U1 (PLAN-U1 §9) to F-008. Reserved
// for future SDK status-polling; today the only caller is apps/web's own test
// suite (the route's doc-comment is corrected alongside this in the route
// file itself). `records` is the parsed/typed shape (via
// apps/web/src/lib/session-records.ts's parseSessionRecords over the DB's
// `recordsJson` JSON column), not a raw passthrough of that column.
export const zPublicSession = z.object({
  id: z.string(),
  domain: z.string(),
  records: zRecords,
  recipe: z.string().nullable(),
  status: z.string(),
  tier: z.number().int().nullable(),
  detectedProvider: z.string().nullable(),
  returnUrl: z.string().nullable(),
  expiresAt: z.iso.datetime(),
});

export type PublicSession = z.infer<typeof zPublicSession>;

// ── GET /api/v1/sessions/:id (integrator-authed) ────────────────────────────
// The SAME path as zPublicSession above, discriminated by the credential: pass
// the `dd_sess_` token and you get the public shape; pass a `dd_sk_` secret key
// (or an OAuth token with `sessions:read`) and you may address the session by
// its `id` and get THIS shape. Two things only this arm can do, and they are why
// it exists (BioFlow partner gap 2026-08-17 — integrators had no server-side
// session lifecycle at all and were inferring the 24h expiry with client-side
// timestamp math):
//
//   1. It is addressable by the id WEBHOOKS carry. Every payload names
//      `sessionId`, never the token, so a `session.abandoned`/`session.completed`
//      receiver previously had no endpoint to ask "…and what state is it in now?"
//      without having stored the token itself at creation.
//   2. It reads an EXPIRED session. The token route runs getLiveSession, which
//      throws 410 the moment `expiresAt` passes — correct for a capability URL,
//      useless for observability, because the one moment an integrator most
//      wants the final state is after the session died. This arm reports it:
//      `expired` is DERIVED at read (`expiresAt <= now`), so it is true even in
//      the window before the reaper cron persists `status: "expired"`.
//
// `records` is the COMPOSED shape (type/host/fqdn) — the names DoDomain actually
// looks up on authoritative DNS — not the raw request echo `zPublicSession`
// returns. A support conversation is about the fqdn, and this endpoint exists for
// support conversations. It is the identical shape `zCreateSessionResponse.records`
// already returns, built by the same composeRecords helper.
export const zIntegratorSession = z.object({
  id: z.string(),
  /** The app that owns the session — the axis the caller's credential is scoped on. */
  appId: z.string(),
  domain: z.string(),
  /** The composed names this session is verified at (see zComposedRecord). */
  records: z.array(zComposedRecord),
  recipe: z.string().nullable(),
  status: z.string(),
  tier: z.number().int().nullable(),
  detectedProvider: z.string().nullable(),
  /** DomainConnection.id once the session finalized; null until then. */
  connectionId: z.string().nullable(),
  createdAt: z.iso.datetime(),
  expiresAt: z.iso.datetime(),
  /** DERIVED at read: `expiresAt <= now`. True before the reaper persists `expired`. */
  expired: z.boolean(),
});

export type IntegratorSession = z.infer<typeof zIntegratorSession>;

// ── Webhook event envelope + per-type payloads ──────────────────────────────
// The stable event `id` U2 deferred to this fix (PLAN-U2 §10.3): the
// canonical value is `WebhookDelivery.id` (packages/db/prisma/schema.prisma).
//
// STATUS (D-003, CLOSED 2026-08-06 — the envelope cutover): this ENVELOPE
// schema (`zWebhookEvent`) IS now on the wire. apps/web/src/lib/
// webhook-delivery.ts's `deliverWebhook` POSTs `zWebhookEventWire` (below):
// the canonical `{ id, type, occurredAt, data }` PLUS a deprecated `event`
// alias, and it sets the `x-dodomain-delivery-id` header PLAN-F-008 §9
// specified. `id` is the stable idempotency key (= `WebhookDelivery.id`) that
// U2 deferred; `occurredAt` is that row's `createdAt`, so both are stable
// across every retry of the same delivery.
//
// WHY ADDITIVE RATHER THAN A HARD SWAP: D-003's plan said "swap it while
// external consumers are zero". That premise expired — Uptimely shipped a live
// receiver (`uptimely-app/src/app/api/webhooks/dodomain/route.ts`, 2026-07-21)
// whose zod schema REQUIRES `event`, so a naked swap would have 400'd every
// delivery into the retry ladder and silently frozen its custom-domain state.
// Emitting a superset keeps every existing receiver working untouched while the
// canonical fields become permanent — which is what "before first SDK publish"
// was protecting: the SDK-facing shape is now settled, not pending.
//
// `event` is DEPRECATED and removal is gated on a real check, never a memory:
// scripts/check-webhook-envelope.sh pins the wire keys, and the alias may only
// be dropped once every registered endpoint is confirmed reading `type`.
//
// The per-type payload schemas BELOW are separate: they validate the
// `data`/`payload` object each emitter writes, and ARE wired (Scale foundation
// 2026-07-10, via apps/web/src/lib/webhook-events.ts).
//
// EVENT VOCABULARY (Scale foundation 2026-07-10): all FOUR integrator webhook
// events PLAN.md committed to now have emitters. Two orthogonal axes:
//   • connection.* — DOMAIN-centric: the ongoing DNS health of a connected
//     domain.
//       - `connection.verified`: the DNS connection is live. Emitted by
//         finalizeConnection (connections.ts) on first verify, AND re-emitted
//         with `recovered:true` when a `broken` connection recovers — by the
//         re-verify cron (apps/web/src/worker/jobs/connection-recheck.ts) or by
//         finalizeConnection itself when the end-user restores the records and
//         re-verifies (#49). This is the ONE event that repeats for a live
//         domain; `session.completed` below fires exactly once per session.
//       - `connection.failed`: something went wrong with the connection — a
//         previously-live connection drifted (re-verify cron, reason
//         `dns_drift`), or a connect attempt failed mid-flow (W6, reason
//         `session_failed` — see the note below).
//       - `connection.disconnected` (F3, 2026-07-29): the INTEGRATOR ended the
//         connection through `DELETE /api/v1/connections/:connectionId` — the
//         drift monitor stops sampling it and no further connection.* event can
//         fire for it unless the same session is re-verified. ADDITIVE to this
//         vocabulary: a receiver that doesn't know the type must ignore it (the
//         documented contract on /docs/webhooks), and it can only ever reach an
//         integrator who called the new endpoint themselves.
//   • session.* — FLOW-centric: a single connect session's lifecycle.
//       - `session.completed`: the connect flow reached terminal success —
//         emitted by finalizeConnection in the SAME tx as connection.verified
//         (both fire at finalize; different axis, not a duplicate).
//       - `session.abandoned`: the session expired without completing — emitted
//         by the session-reaper cron (apps/web/src/worker/jobs/session-reaper.ts).
// (Not to be confused with queue.ts's "webhook.delivery_failed" — that's an
// OPERATIONAL Event row for the DLQ terminal state, U2/F-001, never an
// integrator-facing webhook type, and intentionally excluded from this enum.)
//
// connection.failed carries TWO reasons (discriminated union below), one per
// axis — and since #45 each arm also states its axis outright in a `scope`
// field (`connection` for dns_drift, `session` for session_failed) so a
// receiver never has to infer scope from a reason list:
//   - `dns_drift` — the re-verify cron's previously-live-connection break.
//   - `session_failed` (W6) — a connect ATTEMPT failed mid-flow (Cloudflare
//     OAuth denied/expired, the record write errored, or the tier-2 Domain
//     Connect provider hop failed/was denied), emitted by the Cloudflare
//     callback AND the Domain Connect start/callback routes via apps/web's
//     failSessionAndEmitWebhook
//     (lib/connections.ts) in the SAME tx as the "failed" transition. NOTE:
//     `failed` is RETRYABLE (session-state.ts LEGAL_TRANSITIONS) — an
//     integrator may see connection.failed(session_failed) and LATER
//     connection.verified for the same session when the user retries and
//     succeeds; a never-completed session is still covered by
//     session.abandoned at expiry.
export const WEBHOOK_EVENT_TYPES = [
  "connection.verified",
  "connection.failed",
  "connection.disconnected",
  "session.completed",
  "session.abandoned",
] as const;

export const zWebhookEventType = z.enum(WEBHOOK_EVENT_TYPES);

export type WebhookEventType = z.infer<typeof zWebhookEventType>;

export const zWebhookEvent = z.object({
  /** Stable idempotency key. Canonical value = WebhookDelivery.id. */
  id: z.string().min(1),
  type: zWebhookEventType,
  occurredAt: z.iso.datetime(),
  data: z.record(z.string(), z.unknown()),
});

export type WebhookEvent = z.infer<typeof zWebhookEvent>;

// The EXACT body `deliverWebhook` serializes — the canonical envelope above
// plus the legacy alias, so producer and consumer share one schema (the org
// rule) instead of the transport hand-rolling an object literal.
//
// Key order here is the key order on the wire (JSON.stringify follows insertion
// order, and `.extend` appends): id, type, occurredAt, data, event. The
// signature covers the serialized string, so the order must not drift casually
// — scripts/check-webhook-envelope.sh pins it.
export const zWebhookEventWire = zWebhookEvent.extend({
  /**
   * @deprecated Legacy alias for `type`, byte-identical to it. Present only so
   * receivers written against the pre-2026-08-06 `{event,data}` body keep
   * working. New receivers must read `type` and dedupe on `id`.
   */
  event: zWebhookEventType,
});

export type WebhookEventWire = z.infer<typeof zWebhookEventWire>;

// The `data` payload each emitter writes to its Event row + WebhookDelivery
// rows. Validated in-tx (before any row is written) by the emission helper
// (apps/web/src/lib/webhook-events.ts), so a producer bug fails loud rather than
// shipping a malformed webhook. Minimal + honest — only fields an emitter
// actually sets. `sessionId` threads through every payload as the integrator's
// correlation handle (same id returned by POST /api/v1/sessions).
//
// F2 (BioFlow live E2E 2026-08-12): every payload that announces a CONNECTION
// also carries `connectionId` — `DomainConnection.id`, the id
// `DELETE /api/v1/connections/:connectionId` and
// `POST /api/v1/connections/:connectionId/reverify` are keyed by. Without it an
// integrator who received "this domain is live" had to list-and-match by domain
// before it could act on the very resource the event announced. ADDITIVE on the
// wire (a receiver that ignores it is unaffected) and required in the schema
// wherever a connection row provably exists at emit time — the one arm where it
// does not is connection.failed/session_failed, a connect ATTEMPT that never
// created a row (see zConnectionSessionFailedPayload).
export const zConnectionVerifiedPayload = z.object({
  domain: z.string(),
  sessionId: z.string(),
  /** DomainConnection.id — the connections API's key (F2). */
  connectionId: z.string(),
  /** Set on a broken→active recovery — by the re-verify cron, or by a
   * re-finalize that healed the connection (#49); absent on first finalize. */
  recovered: z.boolean().optional(),
});
export type ConnectionVerifiedPayload = z.infer<typeof zConnectionVerifiedPayload>;

/**
 * FIX(#45): the axis a `connection.failed` belongs to, as a machine-readable
 * field rather than something a receiver has to infer from `reason`.
 *
 * The event vocabulary note above frames the whole webhook surface on two
 * orthogonal axes — DOMAIN-centric `connection.*` and FLOW-centric `session.*`
 * — but `connection.failed` straddles them: `dns_drift` is a live connection
 * regressing (domain axis), while `session_failed` is one connect ATTEMPT
 * failing (flow axis, retryable, nothing is "broken" yet). Uptimely had to
 * special-case `reason` parsing to apply session-scoped semantics.
 *
 *   - `connection` — a domain that WAS live is no longer healthy. Act on the
 *                    customer's live domain (alert, mark degraded, re-check).
 *   - `session`    — an in-flight connect attempt failed. Act on the flow
 *                    (offer a retry); the customer may still succeed on the
 *                    same session, and you may later get connection.verified
 *                    for it.
 *
 * ADDITIVE by construction: the issue asked for separate event NAMES, which
 * would have broken every receiver subscribed to `connection.failed` (and
 * double-delivering both shapes is worse). `reason`, the event type, and every
 * existing field are byte-identical; `scope` is a new field a receiver may
 * ignore. It is also the durable axis: a third `reason` on either side gets the
 * right scope without receivers relearning a reason list.
 */
export const zConnectionFailedScope = z.enum(["connection", "session"]);
export type ConnectionFailedScope = z.infer<typeof zConnectionFailedScope>;

/** connection.failed / dns_drift — the re-verify cron found a previously-live
 * connection's records missing or changed on authoritative DNS. */
export const zConnectionDnsDriftPayload = z.object({
  domain: z.string(),
  sessionId: z.string(),
  /** DomainConnection.id — the connections API's key (F2). */
  connectionId: z.string(),
  fqdn: z.string(),
  reason: z.literal("dns_drift"),
  /** Domain axis: a live connection regressed (see zConnectionFailedScope). */
  scope: z.literal("connection"),
  /** The expected records that no longer match on authoritative DNS. */
  records: z.array(z.object({ fqdn: z.string(), type: z.string() })),
});
export type ConnectionDnsDriftPayload = z.infer<typeof zConnectionDnsDriftPayload>;

/** connection.failed / session_failed (W6) — a connect ATTEMPT failed mid-flow.
 * Retryable: the same session may later emit connection.verified (see the
 * WEBHOOK_EVENT_TYPES vocabulary note above).
 *
 * Deliberately WITHOUT the `connectionId` its sibling arms carry (F2): this
 * failure happens before any DomainConnection row exists, so there is no id to
 * name. `sessionId` is the handle here — and when the user retries and
 * succeeds, the resulting connection.verified carries the connectionId for the
 * same session. */
export const zConnectionSessionFailedPayload = z.object({
  domain: z.string(),
  sessionId: z.string(),
  reason: z.literal("session_failed"),
  /** Flow axis: one connect ATTEMPT failed (see zConnectionFailedScope). */
  scope: z.literal("session"),
  /** Which hop failed: the provider OAuth/consent step (for tier-2 Domain
   * Connect, `oauth_authorize` covers the whole provider-hosted
   * discovery/consent/apply hop — consent and apply are ONE step there),
   * or the DNS record write. */
  failedStep: z.enum(["oauth_authorize", "record_write"]),
  /** Best-effort human-readable detail (e.g. the thrown error's message). */
  error: z.string().optional(),
});
export type ConnectionSessionFailedPayload = z.infer<typeof zConnectionSessionFailedPayload>;

export const zConnectionFailedPayload = z.discriminatedUnion("reason", [
  zConnectionDnsDriftPayload,
  zConnectionSessionFailedPayload,
]);
export type ConnectionFailedPayload = z.infer<typeof zConnectionFailedPayload>;

/** connection.disconnected (F3) — the integrator called
 * `DELETE /api/v1/connections/:connectionId`. Terminal for the MONITOR: the
 * hourly re-verify cron stops sampling the connection, so no further
 * `connection.failed(dns_drift)` / `connection.verified(recovered)` can fire
 * for it. NOT terminal for the SESSION: if the same connect session is verified
 * again (the user reconnects before the session expires), finalizeConnection
 * clears the archive and re-emits `connection.verified`. */
export const zConnectionDisconnectedPayload = z.object({
  domain: z.string(),
  sessionId: z.string(),
  /** DomainConnection.id — the id the caller passed to DELETE (F2), echoed so
   * an integrator's OTHER consumers (the ones that didn't make the call) can
   * reconcile without a lookup. */
  connectionId: z.string(),
  fqdn: z.string(),
  disconnectedAt: z.iso.datetime(),
});
export type ConnectionDisconnectedPayload = z.infer<typeof zConnectionDisconnectedPayload>;

/** session.completed — the flow-terminal, exactly-once signal. It carries
 * `connectionId` too (F2): firing once per session makes it the natural hook
 * for "provision this domain", and that handler is precisely the one that later
 * needs the connections API key. */
export const zSessionCompletedPayload = z.object({
  domain: z.string(),
  sessionId: z.string(),
  /** DomainConnection.id — the connections API's key (F2). */
  connectionId: z.string(),
});
export type SessionCompletedPayload = z.infer<typeof zSessionCompletedPayload>;

export const zSessionAbandonedPayload = z.object({
  domain: z.string(),
  sessionId: z.string(),
  /** The session's last status before the reaper persisted `expired`. */
  lastStatus: z.string(),
  expiredAt: z.iso.datetime(),
});
export type SessionAbandonedPayload = z.infer<typeof zSessionAbandonedPayload>;

// Type → payload-schema table (the emission helper's validation map). `satisfies`
// keeps it TOTAL over WebhookEventType — adding an event type to the enum above
// without a payload schema here fails to typecheck.
export const WEBHOOK_EVENT_PAYLOAD_SCHEMAS = {
  "connection.verified": zConnectionVerifiedPayload,
  "connection.failed": zConnectionFailedPayload,
  "connection.disconnected": zConnectionDisconnectedPayload,
  "session.completed": zSessionCompletedPayload,
  "session.abandoned": zSessionAbandonedPayload,
} satisfies Record<WebhookEventType, z.ZodType>;

// ── Provider detection (session detect + public domains/check) ──────────────
// The detect-response boundary shapes. Two consumers of one detection engine:
// POST /api/v1/sessions/:token/detect (the connect flow's own detection) and
// POST /api/v1/domains/check (the integrator-authed pre-flight check). Both
// routes type their response literal against these schemas so a drift between
// what the route builds and what this file promises is a compile error — the
// same producer/consumer discipline as zCreateSessionResponse above.

// Mirror of guides.ts's ProviderGuide. `satisfies z.ZodType<ProviderGuide>`
// binds the two statically: adding/renaming a ProviderGuide field without
// updating this schema fails typecheck (drift can't ship silently).
export const zProviderGuide = z.object({
  provider: z.string(),
  label: z.string(),
  dashboardUrl: z.string().optional(),
  hostFormat: z.string(),
  apexToken: z.enum(["@", "(blank)", "%domain%"]),
  steps: z.array(z.string()),
  notes: z.array(z.string()).optional(),
}) satisfies z.ZodType<ProviderGuide>;

// Building blocks shared by both detect-response schemas — mirrors detect.ts's
// Tier / ProviderMatch["method"] / ProviderMatch["confidence"]. Not exported:
// consumers read them through the response schemas below.
const zDetectionTier = z.union([z.literal(1), z.literal(2), z.literal(3)]);
const zDetectionMethod = z.enum(["oauth", "domain-connect", "guided"]);
const zDetectionConfidence = z.enum(["high", "medium", "low"]);

// ── POST /api/v1/sessions/:token/detect ─────────────────────────────────────
// `zone` is the DNS zone that OWNS the session's records — the zone the user
// must open at their provider, not the subdomain being connected, so the
// connect-flow guide can name it. Normally the registrable apex (eTLD+1):
// "feastables.com" for a session connecting "shop.feastables.com". When a
// subzone is DELEGATED to its own nameservers it is that subzone instead
// ("dc.customer.com" for "status.dc.customer.com"), because those nameservers
// — not the apex's — are what will hold the record. `tier`/`method`/
// `provider`/`nameServers` are all decided against this same zone.
export const zDetectSessionResponse = z.object({
  provider: z.string(),
  label: z.string(),
  zone: z.string(),
  tier: zDetectionTier,
  method: zDetectionMethod,
  confidence: zDetectionConfidence,
  nameServers: z.array(z.string()),
  domainConnect: z.object({ providerId: z.string(), providerName: z.string() }).nullable(),
  /**
   * true ⇒ THIS session can one-click via the tier-2 Domain Connect apply
   * path: the flag is on, the session's records compile to one of the two
   * constrained templates, zone discovery succeeded, AND the DNS provider has
   * onboarded our template. Fail-closed best-effort (a hard-capped probe in
   * the detect route — apps/web/src/lib/dc-config.ts's
   * probeDomainConnectReady): any failure/timeout ⇒ false, so detect never
   * blocks on DC endpoints and the connect flow falls back to manual records.
   * Flag off ⇒ always false (the pre-tier-2 UI, unchanged).
   */
  domainConnectReady: z.boolean(),
  guide: zProviderGuide,
});

export type DetectSessionResponse = z.infer<typeof zDetectSessionResponse>;

// ── POST /api/v1/domains/check ──────────────────────────────────────────────
// Integrator-authed pre-flight: "which provider/tier/flow will this domain
// get?" before ever creating a session (checkDomain parity — available on
// every plan). Input is the bare domain; 253 octets is the DNS name ceiling
// (RFC 1035), so anything longer is rejected as malformed rather than fed to
// a wasted lookup.
export const zCheckDomainInput = z.object({
  domain: z.string().trim().min(1).max(253),
});

export const zCheckDomainResponse = z.object({
  /** The domain as submitted (trimmed). */
  domain: z.string(),
  /** The zone that owns the records (registrable apex, or a delegated subzone
   * when one exists) — see zDetectSessionResponse.zone. */
  zone: z.string(),
  provider: z.string(),
  label: z.string(),
  tier: zDetectionTier,
  method: zDetectionMethod,
  confidence: zDetectionConfidence,
  nameServers: z.array(z.string()),
  /** Domain Connect discovery outcome: `discovered:false` ⇒ no providerId/providerName. */
  domainConnect: z.object({
    discovered: z.boolean(),
    providerId: z.string().optional(),
    providerName: z.string().optional(),
  }),
  guide: zProviderGuide,
});

export type CheckDomainResponse = z.infer<typeof zCheckDomainResponse>;

// ── POST /api/v1/connections/:connectionId/reverify ─────────────────────────
// 202 body for the on-demand connection re-verify enqueue. `accepted:true` is
// deliberate (not a jobId): the check may coalesce with an already-queued job
// for the same connection, so a per-request job id would over-promise.
export const zReverifyConnectionResponse = z.object({
  accepted: z.literal(true),
});

export type ReverifyConnectionResponse = z.infer<typeof zReverifyConnectionResponse>;

// ── /api/v1 error envelope ──────────────────────────────────────────────────
// The ONE error-body shape apps/web's jsonError (apps/web/src/lib/api/errors.ts)
// produces for every /api/v1 failure: `{ error: <code>, message?, details? }`.
// `error` stays a plain string here (NOT a re-typed enum): the finite 10-code
// vocabulary is OWNED by apps/web's ApiErrorCode, and core cannot import from
// the app — re-declaring the union here would be exactly the producer/consumer
// drift this file exists to prevent. Consumer today: @dodomain/ai-tools' REST
// self-hop helper, which maps non-2xx bodies onto typed tool errors for the
// MCP endpoint.
export const zApiErrorBody = z.object({
  error: z.string(),
  message: z.string().optional(),
  details: z.unknown().optional(),
});

export type ApiErrorBody = z.infer<typeof zApiErrorBody>;

// ── App name ────────────────────────────────────────────────────────────────
// THE single rule for App.name (packages/db/prisma/schema.prisma) — one column
// that is simultaneously the dashboard list/breadcrumb label AND the
// end-user-facing product name on the hosted connect flow (until branding
// overrides nothing: there is no second display-name column). Every writer
// parses THIS: the dashboard's createApp and renameApp server actions.
//
// It used to live inline inside zAppBrandingInput, which made the app's name
// look like a branding-only "Display name" and left issue #37's reporter
// believing the app name was immutable (they delete-and-recreated instead,
// rotating their keys). Extracting it is what lets rename be its own
// discoverable control without a second validation rule drifting from this one.
export const zAppName = z
  .string()
  .trim()
  .min(1, { message: "Name is required." })
  .max(80, { message: "Name is too long (80 characters max)." });

// ── App branding (integrator-supplied, END-USER-facing) ────────────────────
// The write-boundary schema for App.logoUrl / App.brandColor
// (packages/db/prisma/schema.prisma) — consumed by the dashboard's
// updateAppBranding server action. The app's NAME is deliberately NOT here
// (see zAppName above): one column, one editor. logoUrl is UNTRUSTED input
// rendered to END USERS on the hosted connect flow: https-only, no embedded
// credentials, and it is never fetched server-side (client-side <img> only —
// no SSRF surface; see apps/web/src/components/brand-mark.tsx). brandColor
// stays #RRGGBB so branding.ts's contrast clamp can always parse it.
const zLogoUrl = z
  .string()
  .trim()
  .max(600, { message: "Logo URL is too long (600 characters max)." })
  .url({ message: "Logo URL must be a valid URL." })
  .refine(
    (value) => {
      try {
        return new URL(value).protocol === "https:" && !hasEmbeddedCredentials(value);
      } catch {
        return false;
      }
    },
    { message: "Logo URL must be https:// (no embedded credentials)." },
  );

const zBrandColor = z.string().trim().regex(BRAND_COLOR_PATTERN, {
  message: "Brand color must be a 6-digit hex like #0E6B4E.",
});

export const zAppBrandingInput = z.object({
  logoUrl: zLogoUrl.nullable(),
  brandColor: zBrandColor.nullable(),
});

export type AppBrandingInput = z.infer<typeof zAppBrandingInput>;

// ── App allowed origins (integrator-supplied) ───────────────────────────────
// The write-boundary schema for App.allowedOrigins (packages/db/prisma/
// schema.prisma) — consumed by the dashboard's updateAppAllowedOrigins server
// action.
//
// TODO(scope): NOTHING READS App.allowedOrigins YET. The column has been
// written `[]` at app creation since it was added and has no reader anywhere in
// the product — the embedded widget's postMessage targetOrigin comes from the
// `origin` query param the widget puts on the iframe URL itself
// (packages/core/src/message-types.ts ORIGIN_PARAM), NOT from this list, and no
// route consults it. So this schema defines the STORED shape only; the
// enforcement hop that turns the list into an actual restriction is a separate
// change (it belongs at the hosted flow's embed boundary, which is out of this
// PR's scope — /connect/[token] is off limits here). Until then the editor's
// copy must not imply a restriction that isn't running, and this comment is the
// marker that says so.
//
// An ORIGIN is scheme + host + optional port — RFC 6454's serialization, which
// is exactly what a browser puts in the `Origin` header and what
// `window.location.origin` returns. Anything with a path, query, fragment or
// userinfo is not an origin, and silently truncating one to its origin would
// store something the integrator did not type.
const ORIGIN_MAX_LENGTH = 253 + 16;

// `new URL` is NOT a host validator: for special schemes it happily parses
// "https://*.example.com" and hands back "*.example.com" as the hostname, so a
// wildcard would sail through a parse-only check (caught by
// test/allowed-origins.test.ts). The host must therefore be matched explicitly:
// dot-separated LDH labels (letters/digits/hyphen, no leading or trailing
// hyphen) — which also covers an IPv4 literal — or a bracketed IPv6 literal,
// which `new URL` has already normalized and validated by the time we see it.
const HOSTNAME_PATTERN = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$/;

function isAcceptableHostname(hostname: string): boolean {
  if (hostname.startsWith("[") && hostname.endsWith("]")) return true;
  return HOSTNAME_PATTERN.test(hostname);
}

/**
 * Normalizes one origin to its canonical serialization, or returns null when
 * the input is not a well-formed origin this product accepts.
 *
 * Canonical means: lowercased scheme and host, the DEFAULT port removed (so
 * `https://a.com:443` and `https://a.com` can never both sit in one list and
 * compare unequal), and no trailing slash. `new URL` does all three, which is
 * why the check is written as a parse-and-compare rather than a regex: the
 * value we store is then byte-identical to what a browser would send.
 *
 * Scheme policy: https only, EXCEPT http on a loopback host. An integrator
 * integrates against `http://localhost:3000` before they ever have a
 * certificate, so refusing it would make the field unusable at exactly the
 * moment it is filled in; loopback is not reachable by a third party, so it
 * carries none of the risk plain http carries on a public host.
 *
 * Wildcards (`https://*.example.com`) are deliberately NOT accepted. Wildcard
 * semantics are a matching rule, and no matcher exists yet (see the
 * unenforced-column note above) — accepting the syntax now would store a
 * pattern whose meaning the product has not defined.
 */
export function normalizeAllowedOrigin(value: string): string | null {
  const trimmed = value.trim();
  if (trimmed === "" || trimmed.length > ORIGIN_MAX_LENGTH) return null;
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return null;
  }
  if (url.username !== "" || url.password !== "") return null;
  // `new URL` always yields "/" for a bare origin, so a pathname of anything
  // else means the integrator typed a URL rather than an origin.
  if (url.pathname !== "/" || url.search !== "" || url.hash !== "") return null;
  // A trailing slash IS the empty path, so "https://a.com/" is still an origin;
  // one with a path is not, and the check above already rejected it.
  const isLoopback =
    url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLoopback)) return null;
  if (!isAcceptableHostname(url.hostname)) return null;
  return url.origin;
}

/** One origin, normalized on the way in — the value stored is the canonical form. */
export const zAllowedOrigin = z.string().transform((value, ctx) => {
  const normalized = normalizeAllowedOrigin(value);
  if (normalized === null) {
    ctx.addIssue({
      code: "custom",
      message: `“${value.trim()}” is not an origin. Use scheme + host, like https://app.example.com — no path, and https unless it's localhost.`,
    });
    return z.NEVER;
  }
  return normalized;
});

/** How many origins one app may list. Bounded so the column stays a list, not a corpus. */
export const ALLOWED_ORIGINS_MAX = 20;

/**
 * The whole list, normalized and de-duplicated.
 *
 * De-duplication happens AFTER normalization on purpose: `https://a.com` and
 * `https://A.com:443` are the same origin, and a list that shows both reads as
 * two rules when it is one.
 */
export const zAppAllowedOriginsInput = z
  .array(zAllowedOrigin)
  .max(ALLOWED_ORIGINS_MAX, {
    message: `Too many origins (${ALLOWED_ORIGINS_MAX} max).`,
  })
  .transform((origins) => [...new Set(origins)]);

// ── GET /api/v1/apps ────────────────────────────────────────────────────────
// The route (apps/web/src/app/api/v1/apps/route.ts, W4 MCP Phase 2) types its
// response literal against ListAppsResponse — the zCreateSessionResponse
// discipline: drift between route and this contract is a compile error. Lists
// the caller team's apps. Field names verified against the App model
// (packages/db/prisma/schema.prisma); secret material (secretKeyHash) is
// deliberately absent and must never be added.
export const zListAppsResponse = z.object({
  apps: z.array(
    z.object({
      id: z.string(),
      name: z.string(),
      /** The publishable widget key (pk_*) — safe to expose; NEVER the secret key. */
      publicKey: z.string(),
      sandbox: z.boolean(),
      /** Integrator branding (see zAppBrandingInput) — null until configured. */
      logoUrl: z.string().nullable(),
      brandColor: z.string().nullable(),
      createdAt: z.iso.datetime(),
    }),
  ),
});

export type ListAppsResponse = z.infer<typeof zListAppsResponse>;

// ── GET /api/v1/connections ─────────────────────────────────────────────────
// The route (apps/web/src/app/api/v1/connections/route.ts, W4 MCP Phase 2)
// types its response literal against ListConnectionsResponse (same discipline
// as zListAppsResponse above).
//
// Query filters are all optional. `limit` is a plain number here on purpose:
// the route coerces its searchParams strings (Number(...)) BEFORE parsing,
// while JSON-shaped callers (the MCP tool layer) pass a number natively — one
// schema, both ingresses.
export const zListConnectionsQuery = z.object({
  appId: z.string().min(1).optional(),
  domain: z.string().min(1).optional(),
  limit: z.number().int().min(1).max(100).default(50),
  /**
   * F3 (2026-07-29): opaque forward cursor — the `nextCursor` a previous page
   * returned. Absent = first page. Without it an integrator with more than 100
   * connections could never ENUMERATE them, which is exactly what the "reconcile
   * after a restore-from-backup" case in the finding needs. Opaque by contract:
   * it happens to be the last row's id today, and callers must not construct one.
   */
  cursor: z.string().min(1).optional(),
  /**
   * F3: include connections the integrator disconnected (`DELETE
   * /api/v1/connections/:connectionId`). Default false — a disconnected
   * connection is gone from the integrator's own product, so the default list
   * is "what is live". Set true to reconcile against the archive.
   */
  includeDisconnected: z.boolean().default(false),
});

export type ListConnectionsQuery = z.infer<typeof zListConnectionsQuery>;

// Mirrors the DomainConnectionStatus Prisma enum (packages/db/prisma/
// schema.prisma): `broken` is an OBSERVED post-connect DNS-drift fact
// (persisted with brokenAt by the re-verify cron), not a derived state.
export const zDomainConnectionStatus = z.enum(["active", "broken"]);

// Caller-safe projection of DomainConnection, plus appId/domain/recordFqdns
// read from its ConnectSession (the connection row itself carries none of the
// three — the route joins, and composes the record names with core's own
// helper).
// `sessionId` is the integrator's correlation handle (the same id webhook
// payloads and POST /api/v1/sessions carry). The three health timestamps are
// nullable straight from the model: verifiedAt/lastCheckedAt are unset until
// the first check, brokenAt only while drifted.
export const zConnectionSummary = z.object({
  id: z.string(),
  appId: z.string(),
  sessionId: z.string(),
  domain: z.string(),
  /**
   * The session's domain again — NOT a record name (prod E2E wave 2,
   * 2026-08-18). `DomainConnection.fqdn` has been written as `session.domain`
   * since the model existed (lib/connections.ts), so a connection verified for
   * the record `status.acme.com` reports `fqdn: "acme.com"`. The name promises
   * more than the value carries, and the value is NOT fixable in place: a
   * session may carry SEVERAL records, so there is no single honest "the"
   * fqdn, and rewriting the column for new rows only would leave one field
   * meaning two different things depending on when the row was written —
   * undetectable to the integrators already reading it (Uptimely, BioFlow).
   *
   * So it stays exactly as it is, and `recordFqdns` below carries the honest
   * answer. Prefer `recordFqdns`; treat this as an alias of `domain`.
   */
  fqdn: z.string(),
  /**
   * The fully-qualified names DoDomain actually monitors for this connection —
   * every record of the owning session composed under its domain, by the SAME
   * `composeRecords`/`fqdnFor` helper POST /verify checks against, so the
   * monitored set and the reported set cannot drift.
   *
   * ADDITIVE (prod E2E wave 2, 2026-08-18): every pre-existing field is
   * byte-identical and a receiver that ignores this keeps behaving exactly as
   * before — the zCreateSessionResponse `records` precedent. Empty only for a
   * session whose records are missing or malformed.
   */
  recordFqdns: z.array(z.string().min(1)),
  status: zDomainConnectionStatus,
  verifiedAt: z.iso.datetime().nullable(),
  lastCheckedAt: z.iso.datetime().nullable(),
  brokenAt: z.iso.datetime().nullable(),
  /**
   * F3 (2026-07-29): set once the integrator disconnected this connection —
   * the drift monitor no longer samples it. `status` keeps the LAST OBSERVED
   * DNS health (active/broken) rather than gaining a third enum value on
   * purpose: an existing integrator parsing `status` against
   * `["active","broken"]` keeps parsing. Read `disconnectedAt !== null` as
   * "monitoring stopped".
   */
  disconnectedAt: z.iso.datetime().nullable(),
  createdAt: z.iso.datetime(),
});

export type ConnectionSummary = z.infer<typeof zConnectionSummary>;

export const zListConnectionsResponse = z.object({
  connections: z.array(zConnectionSummary),
  /** F3: pass back as `?cursor=` for the next page; null on the last page. */
  nextCursor: z.string().nullable(),
});

export type ListConnectionsResponse = z.infer<typeof zListConnectionsResponse>;

// ── DELETE /api/v1/connections/:connectionId ────────────────────────────────
// F3 (Uptimely dogfood 2026-07-21/22, issue #38): the disconnect the API was
// missing. Idempotent by construction — a repeat DELETE returns the ORIGINAL
// disconnectedAt with `alreadyDisconnected: true` and fires no second webhook,
// so an integrator's own retry loop can never double-emit.
export const zDisconnectConnectionResponse = z.object({
  id: z.string(),
  disconnectedAt: z.iso.datetime(),
  /** false = this call performed the disconnect (and emitted
   * `connection.disconnected`); true = it was already disconnected. */
  alreadyDisconnected: z.boolean(),
});

export type DisconnectConnectionResponse = z.infer<typeof zDisconnectConnectionResponse>;

// ── POST /api/v1/sessions/:token/verify ─────────────────────────────────────
// The live-DNS-check response of the verify route (apps/web/src/app/api/v1/
// sessions/[token]/verify/route.ts), which types its response literal against
// VerifySessionResponse (same discipline as zListConnectionsResponse above;
// MCP-3 discharged) — the MCP tool layer validates the same shape it relays.
// `outcome` mirrors VerificationResult["outcome"] (./types.ts) — a re-listed
// literal union would drift, so keep them eye-matched via this comment until
// verify results themselves move behind a schema.
export const zVerifySessionResponse = z.object({
  verified: z.boolean(),
  records: z.array(
    z.object({
      fqdn: z.string(),
      type: z.string(),
      present: z.boolean(),
      note: z.string(),
      outcome: z.enum(["verified", "propagating", "absent", "indeterminate", "domain_not_found"]),
      /** DNS error code behind an unconfirmed check — "NS_RESOLUTION_FAILED"/the record
       * query's code on "indeterminate", the apex NS query's code on "domain_not_found". */
      authoritativeError: z.string().optional(),
    }),
  ),
});

export type VerifySessionResponse = z.infer<typeof zVerifySessionResponse>;

// ── /api/v1/webhook-endpoints ───────────────────────────────────────────────
// The REST lifecycle for an app's webhook endpoints (2026-08-17): the same set
// the dashboard's Webhooks card manages, so an integrator can drive it from CI/
// IaC instead of clicking. The routes type their response literals against
// these (the zListConnectionsResponse discipline — drift is a compile error).
//
// SHOW-ONCE, exactly like the dashboard: the signing secret is returned by
// CREATE and by ROTATE and never again. That is why the secret lives on its own
// response schema (zWebhookEndpointSecretResponse) and is ABSENT from the
// summary every read surface returns — a `secret` field on the summary would
// make "list your endpoints" a secret-disclosure endpoint.
export const zWebhookEndpointSummary = z.object({
  id: z.string(),
  appId: z.string(),
  /** The NORMALIZED url the row carries (what `validateWebhookUrl` returned),
   * not the raw input string — a trailing-slash variant is stored canonical. */
  url: z.string(),
  createdAt: z.iso.datetime(),
});

export type WebhookEndpointSummary = z.infer<typeof zWebhookEndpointSummary>;

export const zListWebhookEndpointsResponse = z.object({
  endpoints: z.array(zWebhookEndpointSummary),
});

export type ListWebhookEndpointsResponse = z.infer<typeof zListWebhookEndpointsResponse>;

/**
 * Body of both POST (create) and PATCH (update) — one shape, because the only
 * mutable field an endpoint has is its URL. Deliberately NOT `z.url()`: the URL
 * policy (https-only, no localhost/private literals, normalization) has ONE
 * home in apps/web/src/lib/webhook-url.ts, which the dashboard action and these
 * routes both call; a second, weaker rule here would be the exact drift the
 * boundary-schema convention exists to prevent. This schema only asserts "a
 * non-empty string field named url is present".
 */
export const zWebhookEndpointInput = z.object({
  url: z.string().min(1),
});

export type WebhookEndpointInput = z.infer<typeof zWebhookEndpointInput>;

/** Create + rotate: the summary PLUS the plaintext signing secret, shown once. */
export const zWebhookEndpointSecretResponse = zWebhookEndpointSummary.extend({
  /** `whsec_...` — store it now; no read surface ever returns it again. */
  secret: z.string(),
});

export type WebhookEndpointSecretResponse = z.infer<typeof zWebhookEndpointSecretResponse>;

/** DELETE — 200 with a body (not 204) for the same reason the connection
 * disconnect returns one: a caller can log WHAT it removed. */
export const zDeleteWebhookEndpointResponse = z.object({
  id: z.string(),
  deleted: z.literal(true),
});

export type DeleteWebhookEndpointResponse = z.infer<typeof zDeleteWebhookEndpointResponse>;

// ── POST /api/v1/keys/rotate ────────────────────────────────────────────────
// Self-rotation of the calling app's SECRET key — the automatable half of
// credential lifecycle. The public key is echoed unchanged (it identifies the
// app in the widget and is never rotated here), which is how a CI job can
// assert it rewrote the right app's secret. There is deliberately no create/
// list/delete of keys over the API: see the route's header.
export const zRotateAppSecretKeyResponse = z.object({
  appId: z.string(),
  /** Unchanged by rotation — echoed so an automated caller can verify the app. */
  publicKey: z.string(),
  /** The NEW `dd_sk_...`, shown once. The old key stopped authenticating the
   * moment this response was produced — there is no overlap window. */
  secretKey: z.string(),
  rotatedAt: z.iso.datetime(),
});

export type RotateAppSecretKeyResponse = z.infer<typeof zRotateAppSecretKeyResponse>;
