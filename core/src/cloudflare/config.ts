// Cloudflare OAuth connector — configuration & endpoints.
//
// Framework-free (F-015 / PM-012): this module reads NO environment and touches
// no filesystem. It exports only URL constants, scopes, and the CfConfig shape —
// packages/core takes config as an ARGUMENT, never reads process.env itself. Each
// caller builds a CfConfig at its own composition root and validates it there
// (apps/web: env.ts via t3-env, resolved through apps/web/src/lib/cf-config.ts's
// resolveCfConfig). The client_secret is read server-side only by the caller and
// is never sent to the browser.
//
// Endpoints are taken from Cloudflare's OIDC discovery document
// (https://dash.cloudflare.com/.well-known/openid-configuration), verified live:
//   authorization_endpoint : https://dash.cloudflare.com/oauth2/auth
//   token_endpoint         : https://dash.cloudflare.com/oauth2/token
//   revocation_endpoint    : https://dash.cloudflare.com/oauth2/revoke
// PKCE S256 supported; token auth methods include client_secret_basic.

export const CF_AUTHORIZE_URL = "https://dash.cloudflare.com/oauth2/auth";
export const CF_TOKEN_URL = "https://dash.cloudflare.com/oauth2/token";
export const CF_REVOKE_URL = "https://dash.cloudflare.com/oauth2/revoke";
export const CF_API_BASE = "https://api.cloudflare.com/client/v4";

// Scopes (exact ids confirmed live against /client/v4/oauth/scopes):
//   zone.read  -> resolve the zone id for the domain
//   dns.write  -> create/delete the DNS record
export const CF_SCOPES = ["zone.read", "dns.write"] as const;

export interface CfConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}
