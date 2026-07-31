// @dodomain/node — server SDK. Thin typed client over the DoDomain REST API.
// Usage:
//   const dodomain = new DoDomain({ secretKey: process.env.DODOMAIN_SECRET_KEY });
//   const session = await dodomain.sessions.create({ domain, records, returnUrl });

import { DODOMAIN_DEFAULT_ORIGIN } from "@dodomain/core/origin";
import { zCreateSessionInput, zCreateSessionResponse } from "@dodomain/core/schemas";
import { verifyWebhook as coreVerifyWebhook } from "@dodomain/core/webhook";
import type { z } from "zod";

import type { CreateSessionInput, Session, VerifyWebhook } from "./public-types.ts";

// PUBLISH (2026-07-31, discharges F-010's "revisit at publish time" flag):
// every type this entry EXPORTS comes from the import-free public-types.ts,
// so the emitted dist/index.d.ts is fully self-contained for an external
// `npm install @dodomain/node` consumer (rollup-dts kept bare
// @dodomain/core / zod imports when types came from core — tsup.config.ts
// has the full history). Runtime still validates against the core schemas
// (inlined into dist by noExternal), and schema-parity.check.ts pins the
// public types to those schemas at typecheck time (F-008: one schema, no
// silent drift).
export type { CreateSessionInput, DnsRecord, DnsRecordType, Session } from "./public-types.ts";
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
