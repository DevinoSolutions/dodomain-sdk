// Post-apply DNS verification types — the shapes verify.ts produces and
// records.ts / record-diff.ts consume. Tier-agnostic: manual, Cloudflare and
// Domain Connect sessions all verify through these. Split out of the former
// types.ts (naming batch 3) so the Domain Connect protocol types
// (domain-connect-types.ts) are not mistaken for the verify vocabulary.

import type { RecordType } from "./record-capabilities.ts";

/** A single expected DNS record for post-apply verification. */
export interface ExpectedRecord {
  type: RecordType;
  /** fully-qualified host, e.g. status.customer.com */
  fqdn: string;
  /**
   * expected value (target / txt data / ip / mx exchange). Matching is exact
   * (F-011/PM-018): case-sensitive for TXT (verification tokens are
   * case-significant); case- and trailing-dot-insensitive for the
   * hostname-valued types (CNAME/MX exchange).
   */
  expect: string;
  /**
   * MX preference (F-002 hop 1). Cloudflare requires it on write; when present,
   * verify.ts matches on exchange AND priority — a record applied with the wrong
   * preference no longer "verifies". Absent on non-MX types.
   */
  priority?: number;
}

export interface VerificationResult {
  fqdn: string;
  type: string;
  present: boolean;
  authoritativeFound: string[];
  publicFound: string[];
  note: string;
  /**
   * F-011: distinguishes a confirmed absence from an indeterminate DNS
   * failure — a SERVFAIL/timeout no longer masquerades as "not there yet".
   * `present` stays fail-closed in every case (an error/indeterminate lookup
   * never sets it true); `outcome` is the richer signal for logs/UI.
   *   - "verified": present on both authoritative and public DNS.
   *   - "propagating": present on authoritative DNS; public resolvers haven't caught up.
   *   - "absent": the authoritative nameservers answered — the record genuinely isn't there (yet).
   *   - "indeterminate": the authoritative check itself failed (a DNS error, or the
   *     zone's nameservers couldn't be resolved at all) — retry, don't treat as absent.
   *   - "domain_not_found": the DOMAIN doesn't resolve at all — its apex NS query and the
   *     public resolver BOTH answered NXDOMAIN/NODATA (unregistered, misspelled, or no
   *     nameservers set). Terminal until the user fixes the domain: retrying can't help,
   *     which is exactly what made it a bug to bucket this with "indeterminate".
   */
  outcome: "verified" | "propagating" | "absent" | "indeterminate" | "domain_not_found";
  /**
   * The DNS error code behind an unconfirmed authoritative check: the record query's own
   * code or "NS_RESOLUTION_FAILED" when outcome is "indeterminate", and the apex NS query's
   * NXDOMAIN-class code (ENOTFOUND/ENODATA) when outcome is "domain_not_found".
   */
  authoritativeError?: string;
  /** DNS error code when the public-resolver lookup itself failed. Informational only — never gates `present`. */
  publicError?: string;
}
