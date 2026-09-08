// Domain Connect PROTOCOL types — fields per draft-ietf-dconn-domainconnect-02
// and the spec settings/template definitions (verified 2026-06-25). The
// post-apply verification shapes (ExpectedRecord / VerificationResult) live in
// verify-types.ts: they are DNS-check types shared by every tier, not protocol.

/** DNS Provider settings JSON returned from /v2/{domain}/settings */
export interface DomainConnectProviderSettings {
  providerId: string;
  providerName: string;
  providerDisplayName?: string;
  urlSyncUX: string;
  urlAsyncUX?: string;
  urlAPI: string;
  urlControlPanel?: string;
  width?: number;
  height?: number;
  nameServers?: string[];
}

/** A constrained Domain Connect apply request (NOT arbitrary records). */
export interface DomainConnectRequest {
  domain: string;
  host?: string;
  template: { providerId: string; serviceId: string };
  /** Only the variables the chosen recipe defines. */
  variables: Record<string, string>;
  redirectUri: string;
}

/** Result of building an apply URL (kept structured so tests can verify the signed payload). */
export interface ApplyUrl {
  url: string;
  base: string;
  /** The exact query string that was signed (excludes `key` and `sig`), or the full query when unsigned. */
  payload: string;
  sig?: string;
  keyHost?: string;
}

export interface DomainConnectSession {
  id: string;
  state: string;
  domain: string;
  host?: string;
  template: { providerId: string; serviceId: string };
  createdAt: number;
  expiresAt: number;
}
