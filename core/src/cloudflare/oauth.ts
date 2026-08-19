// Cloudflare OAuth 2.0 (Authorization Code + PKCE, confidential client).
//
// Flow:
//   1. generatePkce() -> {verifier, challenge}
//   2. buildAuthorizeUrl() -> send the user's browser to Cloudflare to consent
//   3. Cloudflare redirects back to redirect_uri with ?code=&state=
//   4. exchangeCode() -> POST the token endpoint (client_secret_basic + verifier)
//      to get a scoped access_token, which is then used for the DNS write.
//
// PKCE is layered on top of the confidential client (belt + suspenders): the
// authorization code is useless without BOTH the client secret and the verifier.

import { randomBytes, createHash } from "node:crypto";
import { CF_AUTHORIZE_URL, CF_TOKEN_URL, CF_SCOPES, type CfConfig } from "./config.ts";

export interface Pkce {
  verifier: string;
  challenge: string;
  method: "S256";
}

/** RFC 7636 PKCE pair. verifier is high-entropy; challenge = base64url(sha256(verifier)). */
export function generatePkce(): Pkce {
  const verifier = randomBytes(48).toString("base64url"); // 64-char unreserved string
  const challenge = createHash("sha256").update(verifier).digest().toString("base64url");
  return { verifier, challenge, method: "S256" };
}

export interface BuildAuthorizeInput {
  config: CfConfig;
  state: string;
  challenge: string;
  scopes?: readonly string[];
}

/** Build the Cloudflare authorize URL the user's browser is sent to for consent. */
export function buildAuthorizeUrl(input: BuildAuthorizeInput): string {
  const scopes = input.scopes ?? CF_SCOPES;
  const u = new URL(CF_AUTHORIZE_URL);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", input.config.clientId);
  u.searchParams.set("redirect_uri", input.config.redirectUri);
  u.searchParams.set("scope", scopes.join(" "));
  u.searchParams.set("state", input.state);
  u.searchParams.set("code_challenge", input.challenge);
  u.searchParams.set("code_challenge_method", "S256");
  return u.toString();
}

export interface CfTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
}

export class CfOAuthError extends Error {}

export interface ExchangeInput {
  config: CfConfig;
  code: string;
  codeVerifier: string;
  /** Injectable for tests; defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

/** Exchange the authorization code for a scoped access token (client_secret_basic). */
export async function exchangeCode(input: ExchangeInput): Promise<CfTokenResponse> {
  const { config, code, codeVerifier } = input;
  const doFetch = input.fetchImpl ?? fetch;
  const basic = Buffer.from(`${config.clientId}:${config.clientSecret}`).toString("base64");
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: config.redirectUri,
    code_verifier: codeVerifier,
  });
  const res = await doFetch(CF_TOKEN_URL, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${basic}`,
      accept: "application/json",
    },
    body: body.toString(),
  });
  const text = await res.text();
  let json: any;
  try {
    json = JSON.parse(text);
  } catch {
    throw new CfOAuthError(
      `token endpoint returned non-JSON (HTTP ${res.status}): ${text.slice(0, 200)}`,
    );
  }
  if (!res.ok || json.error) {
    throw new CfOAuthError(
      `token exchange failed (HTTP ${res.status}): ${json.error ?? text.slice(0, 200)}${json.error_description ? " — " + json.error_description : ""}`,
    );
  }
  if (!json.access_token) throw new CfOAuthError("token response missing access_token");
  return json as CfTokenResponse;
}
