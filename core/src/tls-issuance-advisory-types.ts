// TLS-issuance advisory vocabulary — the shapes tls-issuance-advisories.ts
// PRODUCES and schemas.ts DESCRIBES (zTlsIssuanceAdvisory).
//
// Zero-import and zod-free on purpose, the message-types.ts precedent: the
// engine that produces these reaches node:dns through verify.ts, and
// schemas.ts is bundled into CLIENT components (origins-card.tsx imports it),
// so the two may only share a file that pulls in neither. Adding an import
// here drags node:dns into every browser bundle that touches a core schema.
//
// WHAT AN ADVISORY IS. A connect session asks a domain to publish an A/AAAA/
// CNAME that hands web traffic to the integrator, and the integrator then
// issues a TLS certificate for that name. Two pre-existing DNS records the
// VERIFY step never looks at can make that issuance fail AFTER the connect
// reads "verified": a CAA set that does not name the integrator's CA, and an
// ACME challenge record left behind by whatever vendor last served the name.
// An advisory names one of those, with the published bytes as evidence. It is
// advice about the step AFTER ours — it never flips a verified record to
// failed, and the verify engine never reads it.

export const TLS_ISSUANCE_ADVISORY_CODES = [
  /** A CAA set governs the name and its `issue` tags do NOT include the app's configured CA. */
  "caa_excludes_issuer",
  /** A CAA set governs the name, and the app has no CA configured to judge it against. */
  "caa_restricts_issuance",
  /** `_acme-challenge.<host>` already holds a TXT or CNAME — a previous vendor's DNS-01 leftovers. */
  "stale_acme_challenge",
  /** The check itself could not complete (nameservers unreachable, SERVFAIL, timeout). Unknown ≠ clean. */
  "tls_issuance_unchecked",
] as const;

export type TlsIssuanceAdvisoryCode = (typeof TLS_ISSUANCE_ADVISORY_CODES)[number];

export const TLS_ISSUANCE_ADVISORY_SEVERITIES = ["warning", "info"] as const;

export type TlsIssuanceAdvisorySeverity = (typeof TLS_ISSUANCE_ADVISORY_SEVERITIES)[number];

// A `type` alias rather than an `interface` on purpose: Prisma's Json input
// type wants an implicit index signature, which object-literal types carry
// and interfaces do not — the column write in apps/web's session-state.ts
// would otherwise need a cast.
export type TlsIssuanceAdvisory = {
  code: TlsIssuanceAdvisoryCode;
  /**
   * `warning` = a record that will plausibly break issuance for THIS
   * integrator; `info` = something the reader should know but that we could
   * not turn into a verdict (a CAA set with no CA to judge it against, or a
   * check that did not complete).
   */
  severity: TlsIssuanceAdvisorySeverity;
  /** The session record's host the advisory is about (the name the certificate is for). */
  fqdn: string;
  /** The name the evidence was read at: the CAA owner (may be a parent), or `_acme-challenge.<fqdn>`. */
  evidenceFqdn: string;
  /** The published values behind the verdict, verbatim — CAA tag values, TXT strings, or a `CNAME <target>` line. */
  evidence: string[];
  /** One human-readable sentence; the UI surfaces render this and the code, never a switch of their own. */
  note: string;
};

/**
 * The ONE normalization of a CA issuer-domain (the value CAA `issue` tags
 * carry before any `;` parameter, and what `App.tlsIssuerCa` stores): lower-
 * cased, trailing dot stripped, surrounding whitespace dropped. Both the write
 * boundary (zAppTlsIssuerCaInput) and the engine's comparison go through here
 * so "LetsEncrypt.org." and "letsencrypt.org" can never be judged differently.
 * RFC 8659 §4.2: the issuer-domain-name is compared case-insensitively.
 */
export function normalizeCaIssuerDomain(value: string): string {
  return value.trim().replace(/\.$/, "").toLowerCase();
}

/**
 * Loosely mirrors RFC 8659's issuer-domain-name grammar (a hostname), used by
 * the write boundary. Deliberately no TLD list: CAs publish issuer domains like
 * `pki.goog`, `letsencrypt.org`, `sectigo.com`, `amazon.com`.
 */
export const CA_ISSUER_DOMAIN_PATTERN =
  /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
