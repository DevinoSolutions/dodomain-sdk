// @dodomain/node — server SDK. Thin typed client over the DoDomain REST API.
// Usage:
//   const dodomain = new DoDomain({ secretKey: process.env.DODOMAIN_SECRET_KEY });
//   const session = await dodomain.sessions.create({ domain, records, returnUrl });

import { DODOMAIN_DEFAULT_ORIGIN } from "@dodomain/core/origin";
import {
  zCheckDomainInput,
  zCheckDomainResponse,
  zConnectionSummary,
  zCreateSessionInput,
  zCreateSessionResponse,
  zDeleteWebhookEndpointResponse,
  zDisconnectConnectionResponse,
  zIntegratorSession,
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

import type {
  CheckDomainInput,
  CheckDomainResult,
  Connection,
  CreateSessionInput,
  DeleteWebhookEndpointResult,
  DisconnectConnectionResult,
  IntegratorSession,
  ListAppsResult,
  ListConnectionsInput,
  ListConnectionsResult,
  ListWebhookEndpointsResult,
  ReverifyConnectionResult,
  RotateSecretKeyInput,
  RotateSecretKeyResult,
  Session,
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
  Connection,
  ConnectionStatus,
  CreateSessionInput,
  DeleteWebhookEndpointResult,
  DetectionConfidence,
  DetectionMethod,
  DetectionTier,
  DisconnectConnectionResult,
  DnsRecord,
  DnsRecordType,
  IntegratorSession,
  ListAppsResult,
  ListConnectionsInput,
  ListConnectionsResult,
  ListWebhookEndpointsResult,
  ProviderGuide,
  ReverifyConnectionResult,
  RotateSecretKeyInput,
  RotateSecretKeyResult,
  Session,
  SessionWarning,
  WebhookEndpoint,
  WebhookEndpointInput,
  WebhookEndpointWithSecret,
  WebhookEvent,
  WebhookEventType,
  WebhookEventWire,
} from "./public-types.ts";
// Back-compat aliases for the pre-F-008 public names — same types, second
// spelling, never a second copy.
export type {
  DnsRecord as SessionRecord,
  Session as CreateSessionResponse,
} from "./public-types.ts";

// FIX(F-010): re-exported so an integrator needs only this ONE package to
// both mint sessions AND verify the signed webhook. verifyWebhook is
// wire-format-agnostic (it only checks the HMAC signature over the raw body
// string), so this re-export carries no coupling to the webhook envelope
// shape (see D-003, unchanged). Typed via the local VerifyWebhook alias so
// the d.ts stays self-contained (signature pinned in schema-parity.check.ts).
export const verifyWebhook: VerifyWebhook = coreVerifyWebhook;

export interface DoDomainOptions {
  secretKey: string;
  /** Override the API base (defaults to DODOMAIN_DEFAULT_ORIGIN, https://app.dodomain.io). */
  baseUrl?: string;
  fetchImpl?: typeof fetch;
}

export class DoDomainError extends Error {
  readonly status: number;
  readonly body: unknown;
  constructor(message: string, status: number, body: unknown) {
    super(message);
    this.name = "DoDomainError";
    this.status = status;
    this.body = body;
  }
}

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
  private readonly secretKey: string;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: DoDomainOptions) {
    if (!opts.secretKey?.startsWith("dd_sk_")) {
      throw new Error("DoDomain: a secret key (dd_sk_…) is required");
    }
    this.secretKey = opts.secretKey;
    // FIX(F-010): was "https://api.dodomain.io" — that subdomain is not
    // registered/served; app.dodomain.io is the one origin that actually
    // serves both /api/v1/* and /connect/:token (see packages/core/src/origin.ts).
    this.baseUrl = (opts.baseUrl ?? DODOMAIN_DEFAULT_ORIGIN).replace(/\/$/, "");
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  readonly sessions = {
    create: async (input: CreateSessionInput): Promise<Session> => {
      // Validate the caller's own input against the SAME schema the server
      // enforces, before it ever crosses the network — a bad call fails fast
      // with a DoDomainError (status 0: no request was sent), not a round
      // trip just to get the identical 400 back.
      const parsedInput = zCreateSessionInput.safeParse(input);
      if (!parsedInput.success) {
        throw new DoDomainError("invalid_request", 0, parsedInput.error.flatten());
      }
      return this.request("POST", "/api/v1/sessions", parsedInput.data, zCreateSessionResponse);
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
     * `create`. An unknown id and another app's id both throw `status: 404`.
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

  private async request<T>(
    method: string,
    path: string,
    body: unknown,
    schema: z.ZodType<T>,
  ): Promise<T> {
    const res = await this.fetchImpl(this.baseUrl + path, {
      method,
      headers: {
        authorization: `Bearer ${this.secretKey}`,
        "content-type": "application/json",
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();

    let json: unknown;
    try {
      json = text ? JSON.parse(text) : {};
    } catch {
      // FIX(F-008): a non-JSON body (e.g. a proxy's 502 HTML page) used to
      // throw a raw SyntaxError here, escaping this SDK's own declared
      // DoDomainError contract. Every failure this SDK throws is now a
      // DoDomainError, never a raw platform error.
      throw new DoDomainError("non_json_response", res.status, text);
    }

    if (!res.ok) {
      const errBody = json as { error?: string };
      throw new DoDomainError(errBody.error ?? `HTTP ${res.status}`, res.status, json);
    }

    // FIX(F-008): the response body used to be returned as `json as T` — an
    // unchecked type assertion, no runtime validation. Now validated against
    // the same core schema the server's route is typed against.
    const parsed = schema.safeParse(json);
    if (!parsed.success) {
      throw new DoDomainError("invalid_response_shape", res.status, json);
    }
    return parsed.data;
  }
}
