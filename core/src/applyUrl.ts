// Build the synchronous-flow "apply template" URL.
//
//   {urlSyncUX}/v2/domainTemplates/providers/{providerId}/services/{serviceId}/apply
//     ?domain=...&host=...&<template variables>&redirect_uri=...&state=...&sig=...&key=...
//
// WHAT IS SIGNED (spec, unchanged and correct):
//   - When the template sets `syncPubKeyDomain`, the request MUST be signed.
//   - The signature covers the query string EXCLUDING BOTH `sig` AND `key`.
//     Spec, Security Considerations: "The digital signature will be generated on
//     the full query string only, excluding the sig and key parameters."
//     The DNS-provider reference implementation filters both by NAME —
//     Domain-Connect/DomainConnectApplyZone, domainconnectzone/DomainConnectImpl.py
//     `verify_sig` (":param qs: The query string without sig= or key=") over
//     `qsutil.qsfilter(qs, ['sig','key'])` — and the service-provider reference
//     client appends "&sig=…&key=…" only AFTER signing. Signing `key` into the
//     payload was the shipped bug fixed 2026-08-06 (PR #97); that fix is live and
//     was independently re-verified against the published `_dck1` key during the
//     Glauca E2E. DO NOT change the payload composition.
//
// EMISSION ORDER — PER DNS PROVIDER (was one fixed order until 2026-08-12):
//   The payload rule above is universal; the ORDER of `sig` and `key` is not.
//   The spec deliberately says nothing about it — Security Considerations only
//   requires the signature "be generated on the full query string only,
//   excluding the sig and key parameters", never where they sit — so two live
//   providers read the silence in mutually exclusive ways:
//     - Glauca HexDNS (AS207960) verifies POSITIONALLY:
//         hexdns_django/connect/views.py :: verify_signature
//           signed_data = request.META['QUERY_STRING'].rsplit("&sig=", 1)[0]
//       Everything before `&sig=` is their payload, so emitting `key` first put
//       `key=_dck1` inside it and every apply came back 403 "Invalid request
//       signature" — reproduced live, then fixed by moving ONLY `key` after
//       `sig` on the already-signed URL, which reached their consent page.
//       => needs "sig-then-key". This is the order the 2026-08-06 end-to-end
//       proof rode; it is load-bearing and stays the DEFAULT.
//     - Cloudflare requires `sig` LAST. This is NOT folklore: it is verbatim on
//       https://developers.cloudflare.com/dns/reference/domain-connect/
//       ("Signature: Required. It also must be the last query parameter.",
//       page last updated 2026-04-16, re-read 2026-08-12).
//       => needs "key-then-sig".
//   No single URL satisfies both, so the order is an ARGUMENT: the caller picks
//   it from the DNS provider it just discovered (apps/web's domain-connect
//   /start route passes `signatureEmissionOrderForDnsProvider(settings.providerId)`
//   — the DNS provider's id from the settings JSON, NOT our own service
//   providerId). Same shape as recipes.ts taking providerId as an argument;
//   core stays framework- and env-free. Name-filtering providers (the reference
//   implementation, and anything conformant) are order-insensitive and accept
//   either, so the default remains correct for every provider not in the table.
//   TODO(scope): the "key-then-sig" branch is unit-proven only. Cloudflare
//   hand-curates its Domain Connect allow-list and our templates still 404
//   there, so nothing has ever exercised sig-last against a live zone — re-prove
//   it end to end when Cloudflare onboards us. Nothing here enables Cloudflare.
//
// SECURITY: `redirect_uri` is validated against an allowlist to prevent open redirects.

import { assertHttps } from "./discovery.ts";
import { signQueryString } from "./sign.ts";
import type { ApplyUrl } from "./types.ts";

export class ApplyUrlError extends Error {}

/**
 * Where `sig` and `key` are emitted relative to each other on the signed apply
 * URL. Neither changes WHAT is signed (the payload always excludes both, by
 * name) — only the byte layout the provider then reads. See the file header for
 * why one order cannot serve every provider.
 */
export type SignatureEmissionOrder =
  /** `...&sig=...&key=...` — required by positional verifiers (Glauca HexDNS). */
  | "sig-then-key"
  /** `...&key=...&sig=...` — required by Cloudflare ("sig must be last"). */
  | "key-then-sig";

/**
 * What we emit for any provider that hasn't told us otherwise: the order proven
 * end to end against Glauca HexDNS on 2026-08-06. Conformant name-filtering
 * providers are order-insensitive, so this is safe for them too.
 */
export const DEFAULT_SIGNATURE_EMISSION_ORDER: SignatureEmissionOrder = "sig-then-key";

/**
 * DNS providers whose published rule contradicts the default. Keyed by the
 * `providerId` from the provider's OWN settings JSON (discovery.ts
 * `parseSettings`), not by our service-provider id.
 */
const SIGNATURE_EMISSION_ORDER_BY_DNS_PROVIDER: Readonly<Record<string, SignatureEmissionOrder>> = {
  // "Signature: Required. It also must be the last query parameter."
  // https://developers.cloudflare.com/dns/reference/domain-connect/
  "cloudflare.com": "key-then-sig",
};

/**
 * Pick the emission order for a DNS provider. Pure lookup over the table above
 * — no env, no I/O; the caller supplies the discovered providerId exactly like
 * recipes.ts is handed one.
 *
 * NOTE: a table entry is plumbing, never an onboarding claim. A provider still
 * has to serve our template (the support probe) before an apply URL is ever
 * built for it.
 */
export function signatureEmissionOrderForDnsProvider(
  dnsProviderId: string,
): SignatureEmissionOrder {
  return (
    SIGNATURE_EMISSION_ORDER_BY_DNS_PROVIDER[dnsProviderId.trim().toLowerCase()] ??
    DEFAULT_SIGNATURE_EMISSION_ORDER
  );
}

export interface BuildApplyUrlInput {
  urlSyncUX: string;
  providerId: string;
  serviceId: string;
  domain: string;
  host?: string;
  /** Constrained recipe variables only (compiled upstream from records[]). */
  variables: Record<string, string>;
  redirectUri: string;
  /** Optional CSRF state, bound to the session. */
  state?: string;
  /** Allowed redirect hosts (open-redirect protection). */
  allowedRedirectHosts: string[];
  /** Signing config — required when the template has syncPubKeyDomain. */
  signing?: {
    privateKeyPem: string;
    /** the TXT host label where the public key lives, e.g. "_dck1" */
    keyHost: string;
    /**
     * How to lay out `sig` and `key` for THIS provider. Omit to get
     * DEFAULT_SIGNATURE_EMISSION_ORDER; callers that know which DNS provider
     * they are talking to pass signatureEmissionOrderForDnsProvider(providerId).
     */
    emissionOrder?: SignatureEmissionOrder;
  };
}

function assertRedirectAllowed(redirectUri: string, allowed: string[]): void {
  let u: URL;
  try {
    u = new URL(redirectUri);
  } catch {
    throw new ApplyUrlError(`redirect_uri is not a valid URL`);
  }
  if (u.protocol !== "https:" && u.hostname !== "localhost" && u.hostname !== "127.0.0.1") {
    throw new ApplyUrlError(`redirect_uri must be https (or localhost for the POC)`);
  }
  if (!allowed.includes(u.hostname)) {
    throw new ApplyUrlError(`redirect_uri host "${u.hostname}" not in allowlist`);
  }
}

/** Ordered query encoding (the order is what gets signed). */
function encodePairs(pairs: Array<[string, string]>): string {
  return pairs.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join("&");
}

export function buildApplyUrl(input: BuildApplyUrlInput): ApplyUrl {
  assertHttps(input.urlSyncUX);
  assertRedirectAllowed(input.redirectUri, input.allowedRedirectHosts);

  const base = `${input.urlSyncUX.replace(/\/+$/, "")}/v2/domainTemplates/providers/${encodeURIComponent(
    input.providerId,
  )}/services/${encodeURIComponent(input.serviceId)}/apply`;

  const pairs: Array<[string, string]> = [["domain", input.domain]];
  if (input.host) pairs.push(["host", input.host]);
  for (const [k, v] of Object.entries(input.variables)) pairs.push([k, v]);
  pairs.push(["redirect_uri", input.redirectUri]);
  if (input.state) pairs.push(["state", input.state]);

  if (input.signing) {
    // Sign FIRST (payload excludes both key and sig — see the file header), then
    // append the two in whichever order this provider needs. Signing never
    // depends on the order: the payload is identical either way, so the same
    // signature is valid for both layouts.
    const payload = encodePairs(pairs);
    const sig = signQueryString(input.signing.privateKeyPem, payload);
    const sigParam = `sig=${encodeURIComponent(sig)}`;
    const keyParam = `key=${encodeURIComponent(input.signing.keyHost)}`;
    const order = input.signing.emissionOrder ?? DEFAULT_SIGNATURE_EMISSION_ORDER;
    // "key-then-sig" = Cloudflare's sig-last rule; "sig-then-key" = the
    // positional-verifier (Glauca) rule and our default.
    const trailer =
      order === "key-then-sig" ? `&${keyParam}&${sigParam}` : `&${sigParam}&${keyParam}`;
    return {
      url: `${base}?${payload}${trailer}`,
      base,
      payload,
      sig,
      keyHost: input.signing.keyHost,
    };
  }

  const payload = encodePairs(pairs);
  return { url: `${base}?${payload}`, base, payload };
}

/**
 * The exact string a DNS Provider verifies: the built apply URL's query string
 * with `sig` and `key` removed BY NAME. This is deliberately the provider's
 * model rather than "everything before &sig=" — it mirrors
 * `qsutil.qsfilter(qs, ['sig','key'])` in Domain-Connect/DomainConnectApplyZone,
 * so a verification written against this helper is a verification against a real
 * provider. Order-insensitive by construction, like the reference.
 */
export function payloadFromUrl(url: string): string {
  return url
    .slice(url.indexOf("?") + 1)
    .split("&")
    .filter((pair) => {
      const name = pair.split("=")[0];
      return name !== "sig" && name !== "key";
    })
    .join("&");
}
