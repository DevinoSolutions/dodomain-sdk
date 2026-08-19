// Domain Connect discovery (synchronous flow).
//
// Steps (verified against spec + IETF draft-02, 2026-06-25):
//   1. Query TXT at `_domainconnect.<zone>`. The value is the host of the DNS
//      Provider's Domain Connect API. `discover()` is the single-zone
//      primitive; WHICH zone to call it on is `nearestZoneCut()` in
//      zone-walk.ts (see the Root Domain note below).
//   2. GET https://{host}/v2/{domain}/settings  -> DcSettings JSON.
//   3. Template support: GET {urlAPI}/v2/domainTemplates/providers/{providerId}/services/{serviceId}
//      -> 200 supported, 404 not supported.
//
// SECURITY: we NEVER accept an arbitrary provider endpoint as a fetch target with
// an attacker-controlled scheme. The discovered TXT value is treated as a *hostname*
// only; we build the https URL ourselves. All endpoints must be https.
//
// That closes SCHEME injection, NOT address reach: a host is still a host, so
// `127.0.0.1` / `10.0.0.5` / `169.254.169.254` / any internal name satisfies
// PREFIX_RE, and `isTemplateSupported` fetches a `urlAPI` that arrived in the
// provider's own JSON. `defaultFetchJson` below is therefore a TEST default
// only — it does no address vetting, no socket pinning, and follows redirects.
// Production callers inject `DiscoveryDeps.fetchJson` from apps/web's guarded
// transport (apps/web/src/lib/discovery-fetch.ts -> outbound-fetch.ts, the same
// guard webhook delivery uses); this library stays framework-free and can't own
// undici/node:dns policy itself. Enforced by scripts/check-discovery-guard-bans.sh.

import { resolveTxt } from "node:dns/promises";

import type { DcSettings } from "./types.ts";
import type { ZoneWalkDeps } from "./zone-walk.ts";

export class DiscoveryError extends Error {}

// The _domainconnect TXT value is a "URL prefix": a host with an OPTIONAL path
// (e.g. Cloudflare publishes `api.cloudflare.com/client/v4/dns/domainconnect`).
// We accept host + safe path, but reject any scheme, userinfo, traversal, query,
// fragment, or whitespace so we always build the https URL ourselves (no SSRF).
const PREFIX_RE = /^[a-z0-9.-]+(?:\/[a-z0-9._/-]*)?$/i;

/** Treat the discovered TXT value as a host(+path) prefix; reject scheme/injection. */
export function sanitizeProviderHost(raw: string): string {
  const v = raw.trim().replace(/\/+$/, "");
  if (
    !v ||
    v.includes("://") ||
    v.includes("..") ||
    v.includes("@") ||
    v.includes(" ") ||
    v.includes("?") ||
    v.includes("#") ||
    !PREFIX_RE.test(v)
  ) {
    throw new DiscoveryError(`Invalid _domainconnect prefix: ${JSON.stringify(raw)}`);
  }
  return v.toLowerCase();
}

export function assertHttps(url: string): string {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new DiscoveryError(`Not a valid URL: ${url}`);
  }
  if (u.protocol !== "https:") throw new DiscoveryError(`Endpoint must be https: ${url}`);
  return url;
}

export function settingsUrl(providerHost: string, domain: string): string {
  const host = sanitizeProviderHost(providerHost);
  return assertHttps(`https://${host}/v2/${encodeURIComponent(domain)}/settings`);
}

export function templateSupportUrl(urlAPI: string, providerId: string, serviceId: string): string {
  const base = assertHttps(urlAPI).replace(/\/+$/, "");
  return `${base}/v2/domainTemplates/providers/${encodeURIComponent(providerId)}/services/${encodeURIComponent(serviceId)}`;
}

/** Validate and normalise the settings JSON. Throws on missing/invalid required fields. */
export function parseSettings(json: unknown): DcSettings {
  if (typeof json !== "object" || json === null)
    throw new DiscoveryError("settings: not an object");
  const o = json as Record<string, unknown>;
  const req = (k: string): string => {
    const val = o[k];
    if (typeof val !== "string" || !val)
      throw new DiscoveryError(`settings: missing/invalid "${k}"`);
    return val;
  };
  const settings: DcSettings = {
    providerId: req("providerId"),
    providerName: req("providerName"),
    urlSyncUX: assertHttps(req("urlSyncUX")),
    urlAPI: assertHttps(req("urlAPI")),
  };
  if (typeof o.providerDisplayName === "string")
    settings.providerDisplayName = o.providerDisplayName;
  if (typeof o.urlAsyncUX === "string") settings.urlAsyncUX = o.urlAsyncUX;
  if (typeof o.urlControlPanel === "string") settings.urlControlPanel = o.urlControlPanel;
  if (Array.isArray(o.nameServers))
    settings.nameServers = o.nameServers.filter((x): x is string => typeof x === "string");
  return settings;
}

export interface DiscoveryDeps extends ZoneWalkDeps {
  resolveTxt?: (host: string) => Promise<string[][]>;
  fetchJson?: (url: string) => Promise<{ ok: boolean; status: number; json: unknown }>;
}

async function defaultFetchJson(url: string) {
  const r = await fetch(url, { headers: { accept: "application/json" } });
  let json: unknown = null;
  try {
    json = await r.json();
  } catch {
    /* non-json body */
  }
  return { ok: r.ok, status: r.status, json };
}

export interface DiscoveryResult {
  domain: string;
  providerHost: string;
  settings: DcSettings;
}

/** Full discovery: TXT lookup -> settings fetch -> parsed settings. */
export async function discover(domain: string, deps: DiscoveryDeps = {}): Promise<DiscoveryResult> {
  const txt = deps.resolveTxt ?? resolveTxt;
  const fetchJson = deps.fetchJson ?? defaultFetchJson;

  let records: string[][];
  try {
    records = await txt(`_domainconnect.${domain}`);
  } catch {
    throw new DiscoveryError(
      `No _domainconnect TXT for ${domain} (provider may not support Domain Connect)`,
    );
  }
  const flat = records.map((parts) => parts.join("")).filter(Boolean);
  if (!flat.length) throw new DiscoveryError(`Empty _domainconnect TXT for ${domain}`);

  const providerHost = sanitizeProviderHost(flat[0]!);
  const sUrl = settingsUrl(providerHost, domain);
  const res = await fetchJson(sUrl);
  // Per draft-02: a 404 means the provider does not host this zone, even though
  // the TXT resolved (e.g. stale record). Treat as "not supported".
  if (res.status === 404)
    throw new DiscoveryError(`Provider at ${providerHost} does not host zone ${domain} (404)`);
  if (!res.ok) throw new DiscoveryError(`settings fetch failed (${res.status}) for ${domain}`);
  const settings = parseSettings(res.json);
  return { domain, providerHost, settings };
}

// ── Which zone to discover on (the spec's "Root Domain") ──────────────────
//
// The spec's Root Domain is "a registered domain (e.g. example.com or
// example.co.uk), or ... a delegated zone in DNS", so the root is NOT always
// the PSL apex. Which zone that is has nothing to do with Domain Connect — it
// is the nearest delegation cut — so the walk lives in zone-walk.ts
// (`nearestZoneCut`) and is shared with the tier router (detect.ts).
//
// Callers resolve the zone FIRST and then call `discover(zone, deps)` on it.
// That split is deliberate rather than a convenience wrapper: apps/web has to
// validate a session's records against the owning zone in between the two
// steps, before any state transition (apps/web/src/lib/dc-config.ts
// `compileRecipeForOwningZone`). Discovery never falls back to a parent zone —
// a zone that doesn't speak Domain Connect means Domain Connect is unavailable
// for that host, because a parent's provider cannot write records it doesn't
// host.
//
// Reference-client note, recorded so the next session doesn't re-derive it:
// the service-provider reference client (Domain-Connect/domainconnect_python)
// does NOT walk — `identify_domain_root` is literally
// `return psl.privatesuffix(domain)`. We extend the root search to the
// delegated zones the spec's own Root Domain definition names, and keep its
// host/domain split semantics in the one place that needs them (dc-config.ts's
// `zoneRelativeHost`, which uses "@" for the apex as our templates require).

/** Returns true if the DNS Provider supports the given template (200), false on 404. */
export async function isTemplateSupported(
  urlAPI: string,
  providerId: string,
  serviceId: string,
  deps: DiscoveryDeps = {},
): Promise<boolean> {
  const fetchJson = deps.fetchJson ?? defaultFetchJson;
  const url = templateSupportUrl(urlAPI, providerId, serviceId);
  const res = await fetchJson(url);
  if (res.status === 200) return true;
  if (res.status === 404) return false;
  throw new DiscoveryError(`template support check returned ${res.status} for ${serviceId}`);
}
