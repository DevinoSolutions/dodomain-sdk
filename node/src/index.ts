// @dodomain/node — server SDK. Thin typed client over the DoDomain REST API.
// Usage:
//   const dodomain = new DoDomain({ secretKey: process.env.DODOMAIN_SECRET_KEY });
//   const session = await dodomain.sessions.create({ domain, records, returnUrl });
// No account yet (keyless start, T-18036):
//   const dodomain = new DoDomain({ keyless: true });
//   const session = await dodomain.sessions.create({ domain, records });
//   session.keyless?.claimUrl, session.keyless?.allowance

import { DODOMAIN_DEFAULT_ORIGIN } from "@dodomain/core/origin";
import {
  zCheckDomainInput,
  zCheckDomainResponse,
  zConnectionSummary,
  zCreateKeylessSessionInput,
  zCreateSessionInput,
  zCreateSessionResponse,
  zDeleteWebhookEndpointResponse,
  zDisconnectConnectionResponse,
  zIntegratorSession,
  zKeylessSessionResponse,
  zKeylessStatusResponse,
  zListAppsResponse,
  zListConnectionsQuery,
  zListConnectionsResponse,
  zListWebhookEndpointsResponse,
  zReverifyConnectionResponse,
  zRotateAppSecretKeyInput,
  zRotateAppSecretKeyResponse,
  zWebhookEndpointInput,
  zWebhookEndpointSecretResponse,
  zWebhookEndpointSummary,
} from "@dodomain/core/schemas";
import { verifyWebhook as coreVerifyWebhook } from "@dodomain/core/webhook";
import type { z } from "zod";

import {
  DoDomainError,
  DoDomainKeylessError,
  errorFromResponse,
  redactKeylessKeys,
} from "./errors.ts";
import {
  KEYLESS_PROOF_DEFAULT_TIMEOUT_MS,
  KEYLESS_PROOF_MAX_TIMEOUT_MS,
  readProofChallenge,
  solveKeylessProof,
} from "./keyless.ts";
import type {
  CheckDomainInput,
  CheckDomainResult,
  ConnectSessionSummary,
  Connection,
  CreateKeylessSessionInput,
  CreateSessionInput,
  DeleteWebhookEndpointResult,
  DisconnectConnectionResult,
  IntegratorSession,
  KeylessConnectSessionSummary,
  KeylessStatus,
  ListAppsResult,
  ListConnectionsInput,
  ListConnectionsResult,
  ListWebhookEndpointsResult,
  ReverifyConnectionResult,
  RotateSecretKeyInput,
  RotateSecretKeyResult,
  VerifyWebhook,
  WebhookEndpoint,
  WebhookEndpointInput,
  WebhookEndpointWithSecret,
} from "./public-types.ts";

// PUBLISH (2026-07-31, discharges F-010's "revisit at publish time" flag):
// every type this entry EXPORTS comes from the import-free public-types.ts,
// so the emitted dist/index.d.ts is fully self-contained for an external
// `npm install @dodomain/node` consumer (rollup-dts kept bare
// @dodomain/core / zod imports when types came from core — tsup.config.ts
// has the full history). Runtime still validates against the core schemas
// (inlined into dist by noExternal), and schema-parity.check.ts pins the
// public types to those schemas at typecheck time (F-008: one schema, no
// silent drift).
export type {
  App,
  CheckDomainInput,
  CheckDomainResult,
  ComposedDnsRecord,
  ConnectSessionSummary,
  Connection,
  ConnectionStatus,
  CreateKeylessSessionInput,
  CreateSessionInput,
  DeleteWebhookEndpointResult,
  DetectionConfidence,
  DetectionMethod,
  DetectionTier,
  DisconnectConnectionResult,
  DnsRecord,
  DnsRecordType,
  IntegratorSession,
  KeylessAllowance,
  KeylessConnectSessionSummary,
  KeylessSessionInfo,
  KeylessStatus,
  ListAppsResult,
  ListConnectionsInput,
  ListConnectionsResult,
  ListWebhookEndpointsResult,
  ProviderGuide,
  ReverifyConnectionResult,
  RotateSecretKeyInput,
  RotateSecretKeyResult,
  SessionWarning,
  TlsIssuanceAdvisory,
  WebhookEndpoint,
  WebhookEndpointInput,
  WebhookEndpointWithSecret,
  WebhookEvent,
  WebhookEventType,
  WebhookEventWire,
} from "./public-types.ts";
// Back-compat aliases — same types, second spelling, never a second copy.
// `SessionRecord`/`CreateSessionResponse` are the pre-F-008 names;
// `Session` is the pre-0.5.0 name of ConnectSessionSummary (naming batch 8:
// it was the third meaning of "session" in this codebase). `Session` carries
// @deprecated JSDoc on the source type; all three go away in the next major.
export type {
  DnsRecord as SessionRecord,
  ConnectSessionSummary as CreateSessionResponse,
  Session,
} from "./public-types.ts";

// FIX(F-010): re-exported so an integrator needs only this ONE package to
// both mint sessions AND verify the signed webhook. verifyWebhook is
// wire-format-agnostic (it only checks the HMAC signature over the raw body
// string), so this re-export carries no coupling to the webhook envelope
// shape (see D-003, unchanged). Typed via the local VerifyWebhook alias so
// the d.ts stays self-contained (signature pinned in schema-parity.check.ts).
export const verifyWebhook: VerifyWebhook = coreVerifyWebhook;

export { DoDomainError, DoDomainKeylessError } from "./errors.ts";
export type { DoDomainErrorFields, KeylessErrorCode } from "./errors.ts";
export {
  KEYLESS_MAX_DIFFICULTY_BITS,
  solveKeylessProof,
  type SolveKeylessProofOptions,
} from "./keyless.ts";

interface DoDomainCommonOptions {
  /** Override the API base (defaults to DODOMAIN_DEFAULT_ORIGIN, https://app.dodomain.io). */
  baseUrl?: string;
  fetchImpl?: typeof fetch;
}

/** The usual client: an app's `dd_sk_` secret key, server-side only. */
export interface DoDomainSecretKeyOptions extends DoDomainCommonOptions {
  secretKey: string;
  keyless?: false;
}

/**
 * Keyless start (T-18036): no account and no key. `sessions.create` calls
 * `POST /api/v1/keyless/sessions`, solves the proof of work the first call
 * asks for, and keeps the returned `dd_ks_` key for later calls. Opt in
 * explicitly: a missing `secretKey` still throws, so an unset environment
 * variable can never quietly turn a production client into a test app.
 */
export interface DoDomainKeylessOptions extends DoDomainCommonOptions {
  keyless: true;
  /** A `dd_ks_` key from an earlier keyless start, to keep using that app. */
  keylessKey?: string;
  /** How long one proof-of-work solve may take (default 120 000 ms). */
  proofTimeoutMs?: number;
  secretKey?: undefined;
}

export type DoDomainOptions = DoDomainSecretKeyOptions | DoDomainKeylessOptions;

/** Per-call options. `signal` aborts the request and, in keyless mode, the
 * proof-of-work search. */
export interface DoDomainCallOptions {
  signal?: AbortSignal;
}

const KEYLESS_KEY_PREFIX = "dd_ks_";

// The one place a caller-supplied id becomes a path segment. Rejects an
// empty/blank id client-side (status 0 — no request was sent) rather than
// letting it collapse the URL onto the COLLECTION route, where a stray
// `DELETE ""` would hit a different endpoint entirely. Percent-encoded for the
// same reason: a hostile id stays ONE segment and can never climb the path.
function pathSegment(field: string, noun: string, value: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new DoDomainError("invalid_request", 0, {
      [field]: [`a non-empty ${noun} is required`],
    });
  }
  return encodeURIComponent(value);
}

function connectionPath(connectionId: string, suffix = ""): string {
  return `/api/v1/connections/${pathSegment("connectionId", "connection id", connectionId)}${suffix}`;
}

function webhookEndpointPath(endpointId: string, suffix = ""): string {
  return `/api/v1/webhook-endpoints/${pathSegment("endpointId", "webhook endpoint id", endpointId)}${suffix}`;
}

// The prefix that marks the PUBLIC arm of GET /api/v1/sessions/:tokenOrId. The
// route discriminates on the segment's SHAPE, not on the credential, so handing
// `sessions.get` a `dd_sess_` token would silently take the token arm and come
// back with the narrower public body — which this SDK could only report as the
// opaque `invalid_response_shape`. Refusing it here names the actual mistake.
const SESSION_TOKEN_PREFIX = "dd_sess_";

function sessionPath(sessionId: string): string {
  const segment = pathSegment("sessionId", "session id", sessionId);
  if (sessionId.startsWith(SESSION_TOKEN_PREFIX)) {
    throw new DoDomainError("invalid_request", 0, {
      sessionId: [
        "expected a session id (the `sessionId` webhooks carry), not a `dd_sess_` token — that token addresses the public arm of this route, which returns a different shape",
      ],
    });
  }
  return `/api/v1/sessions/${segment}`;
}

export class DoDomain {
  private readonly baseUrl: string;
  /** The `dd_sk_` key, or null on a keyless client. */
  private readonly secretKey: string | null;
  private readonly fetchImpl: typeof fetch;
  /** Keyless mode only: the `dd_ks_` key, once a keyless start returned it. */
  private keylessKeyValue: string | null = null;
  private readonly proofTimeoutMs: number;
  /** An anonymous keyless start in flight, so concurrent creates on a fresh
   * client wait for its key instead of each starting a keyless app. */
  private keylessStart: Promise<unknown> | null = null;

  constructor(opts: DoDomainOptions) {
    this.proofTimeoutMs = KEYLESS_PROOF_DEFAULT_TIMEOUT_MS;
    if (opts.keyless === true) {
      if (opts.secretKey !== undefined) {
        throw new Error("DoDomain: pass either secretKey or keyless: true, not both");
      }
      if (opts.keylessKey !== undefined && !opts.keylessKey.startsWith(KEYLESS_KEY_PREFIX)) {
        throw new Error("DoDomain: keylessKey must be a keyless key (dd_ks_…)");
      }
      this.secretKey = null;
      this.keylessKeyValue = opts.keylessKey ?? null;
      const proofTimeoutMs = opts.proofTimeoutMs ?? KEYLESS_PROOF_DEFAULT_TIMEOUT_MS;
      if (
        !Number.isFinite(proofTimeoutMs) ||
        proofTimeoutMs <= 0 ||
        proofTimeoutMs > KEYLESS_PROOF_MAX_TIMEOUT_MS
      ) {
        throw new Error(
          `DoDomain: proofTimeoutMs must be a number of milliseconds above 0 and at most ${KEYLESS_PROOF_MAX_TIMEOUT_MS} (a challenge lives 5 minutes)`,
        );
      }
      this.proofTimeoutMs = proofTimeoutMs;
    } else {
      if (!opts.secretKey?.startsWith("dd_sk_")) {
        throw new Error(
          "DoDomain: a secret key (dd_sk_…) is required. To try DoDomain with no account, use new DoDomain({ keyless: true }).",
        );
      }
      this.secretKey = opts.secretKey;
    }
    // FIX(F-010): was "https://api.dodomain.io" — that subdomain is not
    // registered/served; app.dodomain.io is the one origin that actually
    // serves both /api/v1/* and /connect/:token (see packages/core/src/origin.ts).
    this.baseUrl = (opts.baseUrl ?? DODOMAIN_DEFAULT_ORIGIN).replace(/\/$/, "");
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  /**
   * Keyless mode only: the `dd_ks_` key of this client's keyless app, or null
   * before the first `sessions.create` returned one (and always null on a
   * secret-key client). It is returned once; persist it and pass it back as
   * `keylessKey` to keep using the same app from another process.
   */
  get keylessKey(): string | null {
    return this.keylessKeyValue;
  }

  readonly sessions = {
    /**
     * `POST /api/v1/sessions` — mint a connect session; hand `connectUrl` to
     * your user.
     *
     * On a keyless client (`new DoDomain({ keyless: true })`) this calls
     * `POST /api/v1/keyless/sessions` instead: the first call solves the proof
     * of work the API asks for (about 1 to 3 seconds at the usual 20 bits) and
     * retries once with it, then the client keeps the returned `dd_ks_` key
     * and later calls need no proof. The result then carries `keyless`: the
     * allowance and the `claimUrl` that moves the app into an account. A
     * keyless refusal throws `DoDomainKeylessError` (branch on `code`). On a
     * keyless client, `appName` names the app on the hosted connect page (the
     * first call only); a secret-key client refuses it.
     */
    create: async (
      input: CreateSessionInput & Pick<CreateKeylessSessionInput, "appName">,
      options: DoDomainCallOptions = {},
    ): Promise<ConnectSessionSummary> => {
      if (this.secretKey === null) return this.createKeylessSession(input, options.signal);
      if (input.appName !== undefined) {
        throw new DoDomainError("invalid_request", 0, {
          appName: ["appName names a keyless app; a secret-key client's app already has its name"],
        });
      }
      // Validate the caller's own input against the SAME schema the server
      // enforces, before it ever crosses the network — a bad call fails fast
      // with a DoDomainError (status 0: no request was sent), not a round
      // trip just to get the identical 400 back.
      const parsedInput = zCreateSessionInput.safeParse(input);
      if (!parsedInput.success) {
        throw new DoDomainError("invalid_request", 0, parsedInput.error.flatten());
      }
      return this.request("POST", "/api/v1/sessions", parsedInput.data, zCreateSessionResponse, {
        signal: options.signal,
      });
    },

    /**
     * `GET /api/v1/sessions/:sessionId` — read a session back BY ID, with your
     * credential. This is the arm addressable by the `sessionId` every webhook
     * payload carries, so a `session.abandoned` / `session.completed` receiver
     * can ask what state the session actually ended in.
     *
     * It reads an EXPIRED session rather than refusing it: check the `expired`
     * flag, which is derived at read (`expiresAt <= now`) and is therefore
     * already true in the window before the reaper persists
     * `status: "expired"` — never infer expiry from `status` alone.
     *
     * Passing a `dd_sess_` token throws `DoDomainError` with `status: 0`: the
     * token addresses the same path's PUBLIC arm, which answers with a
     * different (and, once the 24 hours are up, permanently 410'd) shape.
     * Unknown and not-yours both throw `status: 404`.
     */
    get: async (sessionId: string): Promise<IntegratorSession> =>
      this.request("GET", sessionPath(sessionId), undefined, zIntegratorSession),
  };

  readonly apps = {
    /**
     * `GET /api/v1/apps` — the apps this credential can see. A secret key sees
     * exactly its OWN app (the key is app-scoped, and listing siblings would
     * widen one leaked key into team-wide reconnaissance); an OAuth token with
     * `apps:read` sees every app on the team. Only the publishable `pk_*` key
     * is ever returned.
     */
    list: async (): Promise<ListAppsResult> =>
      this.request("GET", "/api/v1/apps", undefined, zListAppsResponse),
  };

  readonly domains = {
    /**
     * `POST /api/v1/domains/check` — stateless pre-flight: which provider hosts
     * the domain, which zone owns its records, which connect tier and flow it
     * will get, and the manual guide if it comes to that. Nothing is persisted
     * and no session is created, so this is the call to make before deciding
     * what UI to show. Available on every plan.
     */
    check: async (input: CheckDomainInput): Promise<CheckDomainResult> => {
      const parsedInput = zCheckDomainInput.safeParse(input);
      if (!parsedInput.success) {
        throw new DoDomainError("invalid_request", 0, parsedInput.error.flatten());
      }
      return this.request("POST", "/api/v1/domains/check", parsedInput.data, zCheckDomainResponse);
    },
  };

  // Credential-lifecycle namespaces (webhookEndpoints, keys). These routes are
  // `dd_sk_`-ONLY server-side: an OAuth bearer is refused 403 with
  // `details.code === "SECRET_KEY_REQUIRED"` rather than granted a new scope,
  // because nothing in the scope grammar covers credential lifecycle. This SDK
  // only ever authenticates with a secret key (the constructor rejects anything
  // else), so that 403 is unreachable THROUGH THE SDK — it is documented on
  // keys.rotate for anyone reading a raw API log alongside SDK code.
  readonly webhookEndpoints = {
    /**
     * `GET /api/v1/webhook-endpoints` — this app's delivery targets. NEVER
     * returns `secret`: the signing secret is show-once at create and rotate,
     * so a leaked read cannot recover the ability to forge our signatures.
     */
    list: async (): Promise<ListWebhookEndpointsResult> =>
      this.request("GET", "/api/v1/webhook-endpoints", undefined, zListWebhookEndpointsResponse),

    /**
     * `POST /api/v1/webhook-endpoints` — register one delivery target.
     *
     * **The returned `secret` is shown ONCE.** It appears here and in
     * `rotateSecret`, and in no read surface ever again — persist it in this
     * same code path, before you do anything else with the result. It is the
     * `secret` argument to `verifyWebhook`.
     *
     * A non-https url, one resolving to a localhost/private/link-local address,
     * and a duplicate of a url this app already registered all throw
     * `DoDomainError` with `status: 400` and the reason in `body.message`. At
     * the plan's endpoint cap it is `status: 402`.
     */
    create: async (input: WebhookEndpointInput): Promise<WebhookEndpointWithSecret> => {
      const parsedInput = zWebhookEndpointInput.safeParse(input);
      if (!parsedInput.success) {
        throw new DoDomainError("invalid_request", 0, parsedInput.error.flatten());
      }
      return this.request(
        "POST",
        "/api/v1/webhook-endpoints",
        parsedInput.data,
        zWebhookEndpointSecretResponse,
      );
    },

    /**
     * `PATCH /api/v1/webhook-endpoints/:endpointId` — point an existing
     * endpoint at a new url. The signing secret is deliberately UNTOUCHED, so
     * moving hosts never forces a receiver to re-key; `rotateSecret` is the
     * explicit sibling for that. Same url policy and duplicate rule as
     * `create`. A url that actually changes also resumes an auto-paused
     * endpoint (see `resume`). An unknown id and another app's id both throw
     * `status: 404`.
     */
    update: async (endpointId: string, input: WebhookEndpointInput): Promise<WebhookEndpoint> => {
      const path = webhookEndpointPath(endpointId);
      const parsedInput = zWebhookEndpointInput.safeParse(input);
      if (!parsedInput.success) {
        throw new DoDomainError("invalid_request", 0, parsedInput.error.flatten());
      }
      return this.request("PATCH", path, parsedInput.data, zWebhookEndpointSummary);
    },

    /**
     * `DELETE /api/v1/webhook-endpoints/:endpointId` — stop delivering to the
     * endpoint. Past delivery rows survive as evidence, but a failed delivery
     * to a deleted endpoint can no longer be redriven.
     */
    delete: async (endpointId: string): Promise<DeleteWebhookEndpointResult> =>
      this.request(
        "DELETE",
        webhookEndpointPath(endpointId),
        undefined,
        zDeleteWebhookEndpointResponse,
      ),

    /**
     * `POST /api/v1/webhook-endpoints/:endpointId/rotate-secret` — mint a new
     * signing secret and return it **once**.
     *
     * **IMMEDIATE CUTOVER, no dual-secret window:** the worker reads the secret
     * live at delivery time, so signatures switch at once — including retries
     * of deliveries created before the rotation. Deploy the new secret to your
     * receiver promptly, and do not discard this response until you have.
     */
    rotateSecret: async (endpointId: string): Promise<WebhookEndpointWithSecret> =>
      this.request(
        "POST",
        webhookEndpointPath(endpointId, "/rotate-secret"),
        undefined,
        zWebhookEndpointSecretResponse,
      ),

    /**
     * `POST /api/v1/webhook-endpoints/:endpointId/resume` — resume an endpoint
     * DoDomain auto-paused (no successful delivery for 7 days and at least 5
     * dead-lettered deliveries in that span; `pausedAt` is set while it is).
     * Clears `pausedAt` and restarts the 7-day clock. Idempotent: an endpoint
     * that is not paused comes back unchanged. Deliveries recorded as skipped
     * while it was paused are NOT resent by this call — redrive them from the
     * dashboard. An `update` that changes the url resumes the endpoint too.
     */
    resume: async (endpointId: string): Promise<WebhookEndpoint> =>
      this.request(
        "POST",
        webhookEndpointPath(endpointId, "/resume"),
        undefined,
        zWebhookEndpointSummary,
      ),
  };

  readonly keys = {
    /**
     * `POST /api/v1/keys/rotate` — the calling app's secret key rotates ITSELF,
     * which is what makes scheduled credential rotation automatable instead of
     * a dashboard click.
     *
     * **DEFAULT: NO GRACE WINDOW.** With no argument (or `overlapHours: 0`) the
     * key that authorized this call stops authenticating the instant it
     * returns, so the returned `secretKey` is the ONLY copy of the new
     * credential — persist it before anything else. A caller that drops it has
     * locked itself out of the API and must rotate again from the dashboard.
     * A zero-overlap rotation also TERMINATES any overlap window still live
     * from an earlier rotation — it is the "revoke the previous key now"
     * escape hatch.
     *
     * **OPT-IN OVERLAP:** `{ overlapHours: 1 }` or `{ overlapHours: 24 }`
     * keeps the OLD key authenticating alongside the new one until the
     * returned `previousKeyExpiresAt`, so a rotator can deploy the new key
     * with zero downtime. Exactly ONE previous key is ever kept: rotating
     * again overwrites the slot, and key n-1 dies instantly regardless of
     * remaining window. Either way, this client instance keeps using the key
     * it was constructed with, so construct a new `DoDomain` with the returned
     * `secretKey` to keep working past the window. `publicKey` is echoed
     * unchanged, so an automated job can assert it rewrote the app it meant to.
     *
     * There is deliberately no create/list/revoke-another-key on this API: a
     * stolen `dd_sk_` must not be able to mint a second, hidden credential that
     * survives the owner rotating the one they know about.
     *
     * On the raw API an OAuth bearer is refused here with `403` and
     * `details.code === "SECRET_KEY_REQUIRED"`; this SDK only ever sends a
     * `dd_sk_` key, so through it that refusal cannot occur.
     */
    rotate: async (input: RotateSecretKeyInput = {}): Promise<RotateSecretKeyResult> => {
      const parsedInput = zRotateAppSecretKeyInput.safeParse(input);
      if (!parsedInput.success) {
        throw new DoDomainError("invalid_request", 0, parsedInput.error.flatten());
      }
      // The default cutover goes on the wire as NO body — the exact request
      // every server version has always accepted; only a requested window
      // sends the (newer) body.
      return this.request(
        "POST",
        "/api/v1/keys/rotate",
        parsedInput.data.overlapHours === 0 ? undefined : parsedInput.data,
        zRotateAppSecretKeyResponse,
      );
    },
  };

  // The connections namespace (2026-08-17). Before it, an integrator who needed
  // to list, read, disconnect, or recheck a connection had to hand-roll raw
  // fetch and hand-write the response shapes — BioFlow shipped exactly that,
  // with a comment naming this namespace as the swap point. Every method
  // validates the caller's arguments before the network hop and the server's
  // body after it, against the SAME core schemas the routes are typed against
  // (the sessions.create discipline).
  readonly connections = {
    /**
     * `GET /api/v1/connections` — one page of connections, newest first.
     * Follow `nextCursor` to walk past the 100-row page ceiling; only filters
     * you actually pass are sent, so the server keeps owning the defaults.
     */
    list: async (input: ListConnectionsInput = {}): Promise<ListConnectionsResult> => {
      const parsedInput = zListConnectionsQuery.safeParse(input);
      if (!parsedInput.success) {
        throw new DoDomainError("invalid_request", 0, parsedInput.error.flatten());
      }
      // Only the keys the caller actually passed go on the wire — an omitted
      // filter must mean "the server's default", not this SDK build's copy of
      // it (zListConnectionsQuery applies defaults on parse; sending those back
      // would freeze them at SDK-publish time). The schema validates without
      // transforming these five, so the caller's own values are what parsed.
      const query = new URLSearchParams();
      if (input.appId !== undefined) query.set("appId", input.appId);
      if (input.domain !== undefined) query.set("domain", input.domain);
      if (input.cursor !== undefined) query.set("cursor", input.cursor);
      if (input.limit !== undefined) query.set("limit", String(input.limit));
      if (input.includeDisconnected !== undefined) {
        query.set("includeDisconnected", String(input.includeDisconnected));
      }
      const qs = query.toString();
      return this.request(
        "GET",
        `/api/v1/connections${qs === "" ? "" : `?${qs}`}`,
        undefined,
        zListConnectionsResponse,
      );
    },

    /**
     * `GET /api/v1/connections/:connectionId` — read ONE connection, including
     * ones you already disconnected. Same shape as an element of `list`.
     * Unknown or not-yours both throw `DoDomainError` with `status: 404`.
     */
    get: async (connectionId: string): Promise<Connection> =>
      this.request("GET", connectionPath(connectionId), undefined, zConnectionSummary),

    /**
     * `DELETE /api/v1/connections/:connectionId` — disconnect: archives the
     * connection and STOPS its DNS monitoring (no more drift webhooks).
     * Idempotent — a repeat returns the original `disconnectedAt` with
     * `alreadyDisconnected: true` and emits no second webhook.
     */
    delete: async (connectionId: string): Promise<DisconnectConnectionResult> =>
      this.request(
        "DELETE",
        connectionPath(connectionId),
        undefined,
        zDisconnectConnectionResponse,
      ),

    /**
     * `POST /api/v1/connections/:connectionId/reverify` — queue an on-demand
     * DNS recheck. Returns as soon as the job is ACCEPTED (HTTP 202): the
     * verdict arrives as a `connection.verified` / `connection.failed` webhook,
     * never in this response. A connection checked within the last 10 minutes
     * throws `DoDomainError` with `status: 429`.
     */
    reverify: async (connectionId: string): Promise<ReverifyConnectionResult> =>
      this.request(
        "POST",
        connectionPath(connectionId, "/reverify"),
        undefined,
        zReverifyConnectionResponse,
      ),
  };

  readonly keyless = {
    /**
     * `GET /api/v1/keyless` — the keyless app's allowance and claim link.
     * Keyless mode only, and only once the client holds a `dd_ks_` key (after
     * the first `sessions.create`, or from `keylessKey`); before that it throws
     * `KEYLESS_KEY_MISSING` with `status: 0`.
     */
    status: async (options: DoDomainCallOptions = {}): Promise<KeylessStatus> => {
      const key = this.keylessKeyValue;
      if (key === null) {
        throw new DoDomainKeylessError(
          "keyless_key_missing",
          0,
          {
            message:
              this.secretKey === null
                ? "This keyless client has no dd_ks_ key yet: create a session first, or pass keylessKey."
                : "keyless.status() reads a keyless app; this client uses a secret key.",
          },
          "KEYLESS_KEY_MISSING",
        );
      }
      return this.send("GET", "/api/v1/keyless", undefined, zKeylessStatusResponse, {
        authorization: `Bearer ${key}`,
        signal: options.signal,
      });
    },
  };

  /** The keyless arm of sessions.create. */
  private async createKeylessSession(
    input: CreateKeylessSessionInput & { appId?: string },
    signal: AbortSignal | undefined,
  ): Promise<KeylessConnectSessionSummary> {
    if (input.appId !== undefined) {
      throw new DoDomainError("invalid_request", 0, {
        appId: ["a keyless client has no appId to pass: its dd_ks_ key is its app"],
      });
    }
    const parsed = zCreateKeylessSessionInput.safeParse(input);
    if (!parsed.success) {
      throw new DoDomainError("invalid_request", 0, parsed.error.flatten());
    }
    // A fresh client with a start already in flight waits for it, so N
    // concurrent creates start ONE keyless app (the network's daily share of
    // starts is small), then reuse its key.
    // Each waiter still honours its OWN signal: aborting one create stops its
    // wait without touching the start the others are waiting on.
    while (this.keylessKeyValue === null && this.keylessStart !== null) {
      await untilSettledOrAborted(this.keylessStart, signal);
    }
    const key = this.keylessKeyValue;
    if (key !== null) {
      return this.postKeylessSession(parsed.data, { authorization: `Bearer ${key}` }, signal);
    }
    const start = this.startKeylessApp(parsed.data, signal);
    this.keylessStart = start;
    try {
      return await start;
    } finally {
      if (this.keylessStart === start) this.keylessStart = null;
    }
  }

  /** An anonymous start: the 428 challenge, the solve, the retry with the
   * proof, and at most ONE more solve when that retry is refused because the
   * network now needs a harder proof (`proof_too_easy`) or the challenge
   * expired while solving (`proof_expired`). */
  private async startKeylessApp(
    body: CreateKeylessSessionInput,
    signal: AbortSignal | undefined,
  ): Promise<KeylessConnectSessionSummary> {
    let refusal: DoDomainKeylessError;
    try {
      return await this.postKeylessSession(body, {}, signal);
    } catch (error) {
      if (!(error instanceof DoDomainKeylessError) || error.code !== "KEYLESS_PROOF_REQUIRED") {
        throw error;
      }
      refusal = error;
    }
    for (let solves = 1; ; solves++) {
      const challenge = readProofChallenge(refusal);
      const proof = await solveKeylessProof(challenge.challenge, challenge.difficultyBits, {
        signal,
        timeoutMs: this.proofTimeoutMs,
      });
      try {
        return await this.postKeylessSession(body, { [challenge.header]: proof }, signal);
      } catch (error) {
        // Anything else, or a third 428, propagates: retrying forever would
        // hide a network that is being throttled or a proof that never holds.
        if (solves >= KEYLESS_MAX_SOLVES || !isRetryableProofRefusal(error)) throw error;
        refusal = error;
      }
    }
  }

  private async postKeylessSession(
    body: CreateKeylessSessionInput,
    headers: Record<string, string>,
    signal: AbortSignal | undefined,
  ): Promise<KeylessConnectSessionSummary> {
    const result = await this.send(
      "POST",
      "/api/v1/keyless/sessions",
      body,
      zKeylessSessionResponse,
      { ...headers, signal },
    );
    if (result.keyless.key !== undefined) this.keylessKeyValue = result.keyless.key;
    return result;
  }

  /** A call authorized by the secret key. A keyless client has none, and the
   * API refuses its dd_ks_ key everywhere but the keyless routes, so it fails
   * here without a request. */
  private async request<T>(
    method: string,
    path: string,
    body: unknown,
    schema: z.ZodType<T>,
    options: DoDomainCallOptions = {},
  ): Promise<T> {
    if (this.secretKey === null) {
      throw new DoDomainKeylessError(
        "keyless_mode",
        0,
        {
          message: `A keyless client can only create sessions and read keyless.status(). ${method} ${path} needs a secret key: claim the keyless app (the claimUrl on its sessions) and use its dd_sk_ key.`,
        },
        "KEYLESS_MODE",
      );
    }
    return this.send(method, path, body, schema, {
      authorization: `Bearer ${this.secretKey}`,
      signal: options.signal,
    });
  }

  private async send<T>(
    method: string,
    path: string,
    body: unknown,
    schema: z.ZodType<T>,
    options: { authorization?: string; signal?: AbortSignal; [header: string]: unknown },
  ): Promise<T> {
    const { signal, ...extra } = options;
    const headers: Record<string, string> = { "content-type": "application/json" };
    for (const [name, value] of Object.entries(extra)) {
      if (typeof value === "string") headers[name] = value;
    }
    const res = await this.fetchImpl(this.baseUrl + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      ...(signal ? { signal } : {}),
    });
    const text = await res.text();

    let json: unknown;
    try {
      json = text ? JSON.parse(text) : {};
    } catch {
      throw new DoDomainError("non_json_response", res.status, redactKeylessKeys(text));
    }

    if (!res.ok) throw errorFromResponse(res.status, json);

    // FIX(F-008): the response body used to be returned as `json as T` — an
    // unchecked type assertion, no runtime validation. Now validated against
    // the same core schema the server's route is typed against.
    const parsed = schema.safeParse(json);
    if (!parsed.success) {
      // The body is attached for debugging; a keyless start's carries the
      // dd_ks_ key, which never belongs in an error.
      throw new DoDomainError("invalid_response_shape", res.status, redactKeylessKeys(json));
    }
    return parsed.data;
  }
}

/** A keyless start solves at most this many proofs: the first challenge, and
 * one fresh one when the proved retry is refused as too easy or expired. */
const KEYLESS_MAX_SOLVES = 2;

/** A proved retry the API refused because the proof went stale, not because
 * it was wrong: worth exactly one fresh solve. */
function isRetryableProofRefusal(error: unknown): error is DoDomainKeylessError {
  if (!(error instanceof DoDomainKeylessError) || error.code !== "KEYLESS_PROOF_REQUIRED") {
    return false;
  }
  const reason = error.details?.reason;
  return reason === "proof_too_easy" || reason === "proof_expired";
}

/** Wait for `pending` to settle either way, or reject with the signal's reason
 * as soon as `signal` aborts, whichever comes first. */
function untilSettledOrAborted(
  pending: Promise<unknown>,
  signal: AbortSignal | undefined,
): Promise<void> {
  const settled = pending.then(
    () => undefined,
    () => undefined,
  );
  if (signal === undefined) return settled;
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise<void>((resolve, reject) => {
    const onAbort = () => reject(signal.reason);
    signal.addEventListener("abort", onAbort, { once: true });
    void settled.then(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    });
  });
}
