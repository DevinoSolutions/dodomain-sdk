// The keyless SANDBOX (T-18114, part B of T-18036): reserved `.test` hostnames
// a developer can start a connect session for without owning a domain. A
// sandbox session never queries DNS, never calls a provider and never applies
// a one-click change: its detection and every verify answer come from the
// fixed table below. It is not metered against any plan or keyless allowance.
//
// THE home for which hostnames are sandbox names and what each one simulates
// (scripts/check-sandbox-bans.sh keeps the names and the mode derivation
// here). The mode is derived from the session's DOMAIN, server-side, once, at
// creation (apps/web lib/connect-session-create.ts stores it on the row; no
// path changes a session's domain or mode afterwards). Never from a request
// flag, a header or an app setting.
//
// Matching is EXACT on the domain as the create route stored it (the create
// schema already trims it and refuses a trailing root dot): no lowercasing, no
// suffix match, no punycode decoding. `Verified.Test`, `verified.test.`,
// `verified.test.evil.com`, `xverified.test` and any lookalike are NOT sandbox
// names; they take the normal path (a keyless call refuses any other `.test`).
import type { ProviderMatch } from "./detect.ts";
import type { ExpectedRecord, VerificationResult } from "./verify-types.ts";

/** What a sandbox hostname simulates. */
export type SandboxScenario = "verified" | "pending" | "slow" | "wrong_record" | "unsupported";

/** A session's mode, stored on ConnectSession.mode (Prisma enum ConnectSessionMode). */
export type ConnectSessionMode = "live" | "sandbox";
export const CONNECT_SESSION_MODES = [
  "live",
  "sandbox",
] as const satisfies readonly ConnectSessionMode[];

/**
 * The reserved sandbox hostnames, exactly as a caller sends them, and what
 * each one does:
 *   - verified.test      verifies on the first check;
 *   - pending.test       never verifies (stays pending until it expires);
 *   - slow.test          verifies once SANDBOX_SLOW_VERIFY_AFTER_MS have passed
 *                        since the session was created (a few polls);
 *   - wrong-record.test  every check finds a record with the WRONG value;
 *   - unsupported.test   detection finds no supported provider, so the flow
 *                        shows the manual records; it verifies on the first
 *                        check, as if the records were added by hand.
 */
export const SANDBOX_DOMAINS: Readonly<Record<string, SandboxScenario>> = Object.freeze({
  "verified.test": "verified",
  "pending.test": "pending",
  "slow.test": "slow",
  "wrong-record.test": "wrong_record",
  "unsupported.test": "unsupported",
});

/** The reserved names, in table order (docs, error copy, tests). */
export const SANDBOX_DOMAIN_NAMES: readonly string[] = Object.freeze(Object.keys(SANDBOX_DOMAINS));

/** How long after creation a `slow.test` session starts verifying. */
export const SANDBOX_SLOW_VERIFY_AFTER_MS = 20_000;

/** The note every simulated result carries, so nobody mistakes it for DNS. */
export const SANDBOX_NOTE = "Sandbox session: simulated result, no DNS query was made.";

/**
 * The scenario a session domain simulates, or null for every other domain.
 * An own-property lookup on the exact string: `Object.hasOwn` keeps a
 * prototype key (`constructor`, `__proto__`) from ever matching.
 */
export function sandboxScenarioFor(domain: string): SandboxScenario | null {
  return Object.hasOwn(SANDBOX_DOMAINS, domain) ? (SANDBOX_DOMAINS[domain] ?? null) : null;
}

/** Whether a session domain is one of the reserved sandbox names (exact match). */
export function isSandboxDomain(domain: string): boolean {
  return sandboxScenarioFor(domain) !== null;
}

/** The mode a NEW session for `domain` gets. Called once, at creation. */
export function connectSessionModeFor(domain: string): ConnectSessionMode {
  return isSandboxDomain(domain) ? "sandbox" : "live";
}

/** Whether a stored session mode is the sandbox. THE comparison: apps/web never
 * spells the literal itself (scripts/check-rc-sandbox-bans.sh bans a quoted
 * `sandbox` there, so the RevenueCat environment check and this one cannot be
 * confused). */
export function isSandboxMode(mode: ConnectSessionMode): boolean {
  return mode === "sandbox";
}

/** The provider label a sandbox detection reports (scenarios other than unsupported). */
export const SANDBOX_PROVIDER_LABEL = "DoDomain sandbox";

/**
 * The detection a sandbox session reports instead of walking DNS: always the
 * guided manual tier (no one-click for a sandbox session), on the session
 * domain as its own zone, with no nameservers. `unsupported.test` reports the
 * same "unknown provider" fallback a real unmatched domain gets.
 */
export function sandboxDetection(
  scenario: SandboxScenario,
  domain: string,
): Omit<ProviderMatch, "domainConnect" | "domainConnectSettings"> {
  if (scenario === "unsupported") {
    return {
      provider: "unknown",
      label: "your DNS provider",
      tier: 3,
      method: "guided",
      confidence: "low",
      zone: domain,
      nameServers: [],
    };
  }
  return {
    provider: "sandbox",
    label: SANDBOX_PROVIDER_LABEL,
    tier: 3,
    method: "guided",
    confidence: "high",
    zone: domain,
    nameServers: [],
  };
}

/** The wrong value `wrong-record.test` "finds", per record type (documentation ranges). */
function wrongValueFor(type: string): string {
  switch (type) {
    case "A":
      return "192.0.2.123";
    case "AAAA":
      return "2001:db8::123";
    case "CNAME":
      return "wrong-target.invalid";
    case "MX":
      return "wrong-mail.invalid";
    default:
      return "dodomain-sandbox-wrong-value";
  }
}

/**
 * The verify results a sandbox session gets instead of DNS, one per expected
 * record, in the shape core's verifyRecords returns. Pure: `createdAt` and
 * `now` decide `slow.test`; nothing else reads the clock.
 */
export function simulateSandboxVerification(
  scenario: SandboxScenario,
  expected: readonly ExpectedRecord[],
  clock: { createdAt: Date; now: Date },
): VerificationResult[] {
  const passes =
    scenario === "verified" ||
    scenario === "unsupported" ||
    (scenario === "slow" &&
      clock.now.getTime() - clock.createdAt.getTime() >= SANDBOX_SLOW_VERIFY_AFTER_MS);
  return expected.map((record) => {
    if (passes) {
      return {
        fqdn: record.fqdn,
        type: record.type,
        present: true,
        authoritativeFound: [record.expect],
        publicFound: [record.expect],
        note: SANDBOX_NOTE,
        outcome: "verified",
      };
    }
    const found = scenario === "wrong_record" ? [wrongValueFor(record.type)] : [];
    return {
      fqdn: record.fqdn,
      type: record.type,
      present: false,
      authoritativeFound: found,
      publicFound: found,
      note: SANDBOX_NOTE,
      outcome: "absent",
    };
  });
}
