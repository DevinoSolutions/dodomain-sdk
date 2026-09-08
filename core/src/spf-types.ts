// SPF checker vocabulary — the shapes spf.ts PRODUCES and schemas.ts
// DESCRIBES (zPublicSpfResponse). Zero-import and zod-free, the
// tls-issuance-advisory-types.ts / message-types.ts precedent: spf.ts reaches
// node:dns, and schemas.ts is bundled into client components, so the two may
// only share a file that pulls in neither.

export type SpfQualifier = "+" | "-" | "~" | "?";

export const SPF_MECHANISMS = ["all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"] as const;
export type SpfMechanismName = (typeof SPF_MECHANISMS)[number];

export type SpfTerm =
  | {
      kind: "mechanism";
      qualifier: SpfQualifier;
      name: SpfMechanismName;
      /** The `:value` / `/cidr` tail, verbatim (`_spf.google.com`, `192.0.2.0/24`), or null when absent. */
      argument: string | null;
      raw: string;
    }
  | { kind: "modifier"; name: string; value: string; raw: string }
  | { kind: "unknown"; raw: string };

export const SPF_ISSUE_CODES = [
  /** No `v=spf1` TXT record at the name — receivers treat the domain as having no SPF policy. */
  "no_record",
  /** More than one `v=spf1` record — RFC 7208 §3.2: receivers MUST permerror. */
  "multiple_records",
  /** A term that is neither a known mechanism nor a modifier — permerror at receivers. */
  "unknown_term",
  /** Terms after `all` are never evaluated. */
  "terms_after_all",
  /** `+all` (or bare `all`): every sender on earth passes. */
  "all_pass",
  /** `?all`: neutral — SPF makes no statement, so DMARC alignment gains nothing. */
  "all_neutral",
  /** No `all` and no `redirect=`: the implicit result for unmatched senders is neutral. */
  "no_all",
  /** `ptr` is deprecated (RFC 7208 §5.5) and slow; receivers may ignore it. */
  "ptr_mechanism",
  /** The recursive DNS-lookup count exceeds 10 — receivers permerror the WHOLE record. */
  "lookup_limit_exceeded",
  /** `redirect=` alongside an `all` mechanism is ignored by receivers (RFC 7208 §6.1). */
  "redirect_ignored",
  /** An include:/redirect= target publishes no SPF record — include ⇒ permerror. */
  "include_target_missing",
  /** A record longer than the 450-byte practical ceiling many resolvers/receivers choke on. */
  "record_too_long",
  /** A DNS read needed to finish the analysis did not complete — the numbers above are a lower bound. */
  "unchecked",
] as const;

export type SpfIssueCode = (typeof SPF_ISSUE_CODES)[number];

export const SPF_ISSUE_SEVERITIES = ["error", "warning", "info"] as const;
export type SpfIssueSeverity = (typeof SPF_ISSUE_SEVERITIES)[number];

export type SpfIssue = {
  code: SpfIssueCode;
  severity: SpfIssueSeverity;
  /** The domain whose record the issue is about (an included domain for nested faults). */
  domain: string;
  /** The offending term, verbatim, when there is one. */
  term: string | null;
  note: string;
};

export type SpfAnalysis = {
  domain: string;
  /** Every `v=spf1` TXT string found at `domain`, verbatim. Empty when none. */
  records: string[];
  /** The parsed terms of the FIRST record (the one receivers would evaluate when exactly one exists). */
  terms: SpfTerm[];
  /** The `all` qualifier in effect, or null when the record has no `all`. */
  allQualifier: SpfQualifier | null;
  /** DNS-querying terms counted recursively through include:/redirect=. A lower bound when `complete` is false. */
  dnsLookups: number;
  /** false when some DNS read the count depended on did not complete. */
  complete: boolean;
  /** Every include:/redirect= domain visited, in evaluation order (deduplicated). */
  visited: string[];
  issues: SpfIssue[];
};

/** RFC 7208 §4.6.4: at most 10 terms that cause a DNS query, across the whole evaluation. Lives here (not spf.ts) so the landing page can print it without the node:dns engine. */
export const SPF_DNS_LOOKUP_LIMIT = 10;
