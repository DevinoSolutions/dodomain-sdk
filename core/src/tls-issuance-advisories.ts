// TLS-issuance advisories — CAA + stale `_acme-challenge` detection for the
// names a connect session hands to the integrator (OPPORTUNITIES Tier-1 #3).
//
// Verification proves the records the integrator ASKED for are live. It says
// nothing about whether the integrator can then issue a certificate for the
// name, and two pre-existing records decide exactly that:
//
//   CAA (RFC 8659)    the domain owner's list of CAs allowed to issue. A CAA
//                     set that names Sectigo alone makes a Let's Encrypt
//                     issuance fail — after our flow already said "connected".
//   _acme-challenge   a DNS-01 token or delegation CNAME the PREVIOUS vendor
//                     left behind. A CA validating DNS-01 reads the stale token
//                     (or follows the stale CNAME to a host that no longer
//                     answers) and refuses.
//
// Both are read through verify.ts's resolver path (the zone walk, the
// authoritative pin, the bounded timeouts, the injectable seams) so an advisory
// reports what the zone's OWN nameservers publish, not a cached recursive view.
//
// HONESTY RULES (the same ones the verify engine lives by):
//   - An advisory NEVER changes a verify verdict. This module is called beside
//     verification, its output travels as a separate `advisories` field, and
//     nothing in verify.ts imports it.
//   - Unknown ≠ clean. A lookup that could not complete yields a
//     `tls_issuance_unchecked` advisory rather than an empty list, so a
//     consumer can tell "we looked and found nothing" from "we could not look".
//   - Evidence is quoted verbatim. The published bytes ARE the diagnostic.
//
// CAA SEMANTICS IMPLEMENTED (RFC 8659 §3, §4.2):
//   - The relevant RRset is the first non-empty CAA set found climbing from the
//     host to the registrable apex, inclusive. CNAME/DNAME following is the
//     resolver's job, as the RFC intends.
//   - Only `issue` tags restrict a non-wildcard name; a set holding only
//     `iodef`/`issuewild`/contact tags restricts nothing. `issue ";"` (empty
//     issuer) forbids every CA.
//   - The issuer-domain is the value before any `;` parameter, compared
//     case-insensitively (normalizeCaIssuerDomain).
//   - NOT implemented: the "critical flag on an unknown tag ⇒ must not issue"
//     clause — node:dns drops unknown tags before we see them (see the
//     DnsResolver.resolveCaa doc in verify.ts). Wildcard names (`issuewild`) are
//     not something a connect session ever requests.
//
// Names ABOVE the owning zone cut (a session on a delegated subzone whose CAA
// lives at the parent) are read through the public recursive resolver — the
// pinned authoritative resolver answers a parent-zone name with a referral,
// which c-ares reports as ENOTFOUND, which would read as "no CAA". The split is
// on `zone` from resolveZoneAuthority and is exact: at or below the cut,
// authoritative; above it, recursive.

import { NODATA, NOTFOUND } from "node:dns";
import { apexOf } from "./apex.ts";
import { isTlsTerminatingRecordType } from "./record-capabilities.ts";
import {
  normalizeCaIssuerDomain,
  type TlsIssuanceAdvisory,
} from "./tls-issuance-advisory-types.ts";
import {
  resolveZoneAuthority,
  type CaaAnswer,
  type DnsResolver,
  type VerifyDeps,
} from "./verify.ts";
import type { ExpectedRecord } from "./verify-types.ts";

/** The label RFC 8555 §8.4 fixes for DNS-01 challenge records. */
const ACME_CHALLENGE_LABEL = "_acme-challenge";

type ReadOutcome<T> =
  | { kind: "answers"; answers: T }
  | { kind: "absent" }
  | {
      kind: "error";
      code: string;
    };

// ENOTFOUND/ENODATA are ANSWERS ("nothing at this name/type"); anything else is
// the check failing — the identical classification verify.ts's lookup() makes,
// so an advisory and a verify result never disagree about what a code means.
async function read<T>(query: () => Promise<T>): Promise<ReadOutcome<T>> {
  try {
    return { kind: "answers", answers: await query() };
  } catch (e) {
    const code = (e as NodeJS.ErrnoException)?.code ?? "UNKNOWN";
    if (code === NOTFOUND || code === NODATA) return { kind: "absent" };
    return { kind: "error", code };
  }
}

function canonicalHost(fqdn: string): string {
  return fqdn.trim().replace(/\.$/, "").toLowerCase();
}

/** `host`, its parent, … down to (and including) `apex`. A host outside its own apex yields just itself. */
function climbToApex(host: string, apex: string): string[] {
  const names: string[] = [];
  let current = host;
  for (;;) {
    names.push(current);
    if (current === apex) break;
    const dot = current.indexOf(".");
    if (dot === -1) break;
    current = current.slice(dot + 1);
  }
  return names;
}

function isAtOrBelow(name: string, zone: string): boolean {
  return name === zone || name.endsWith(`.${zone}`);
}

function unchecked(fqdn: string, evidenceFqdn: string, reason: string): TlsIssuanceAdvisory {
  return {
    code: "tls_issuance_unchecked",
    severity: "info",
    fqdn,
    evidenceFqdn,
    evidence: [],
    note: `Could not check CAA or ACME challenge records for ${fqdn} (${reason}) — issuance may still be blocked by DNS you can't see here.`,
  };
}

/** The CAA `issue` tag values of one RRset, verbatim (`"letsencrypt.org; validationmethods=dns-01"`). */
function issueTagValues(answers: CaaAnswer[]): string[] {
  return answers.flatMap((a) => (typeof a.issue === "string" ? [a.issue] : []));
}

/** RFC 8659 §4.2: the issuer-domain-name is everything before the first `;`. Empty means "nobody". */
function issuerDomainOf(issueTag: string): string {
  const semicolon = issueTag.indexOf(";");
  return normalizeCaIssuerDomain(semicolon === -1 ? issueTag : issueTag.slice(0, semicolon));
}

/**
 * The advisory (if any) one CAA RRset produces for `fqdn`, judged against the
 * integrator's configured CA. Exported for the deterministic unit test — the
 * pure half of this module, no DNS.
 */
export function judgeCaaAnswers(
  fqdn: string,
  caaOwner: string,
  answers: CaaAnswer[],
  tlsIssuerCa: string | null,
): TlsIssuanceAdvisory | null {
  const issueTags = issueTagValues(answers);
  // Only `issue` restricts a non-wildcard name (§4.2). iodef/issuewild alone: unrestricted.
  if (issueTags.length === 0) return null;
  const evidence = issueTags.map((tag) => `issue "${tag}"`);
  const owner = caaOwner === fqdn ? fqdn : `${caaOwner} (inherited by ${fqdn})`;

  if (tlsIssuerCa === null) {
    return {
      code: "caa_restricts_issuance",
      severity: "info",
      fqdn,
      evidenceFqdn: caaOwner,
      evidence,
      note: `A CAA policy at ${owner} limits which certificate authorities may issue for this name. Make sure it includes the CA that will issue the certificate.`,
    };
  }

  const permitted = new Set(issueTags.map(issuerDomainOf).filter((d) => d !== ""));
  if (permitted.has(normalizeCaIssuerDomain(tlsIssuerCa))) return null;

  return {
    code: "caa_excludes_issuer",
    severity: "warning",
    fqdn,
    evidenceFqdn: caaOwner,
    evidence,
    note:
      permitted.size === 0
        ? `A CAA policy at ${owner} forbids every certificate authority (an empty issuer), so no certificate can be issued for this name until it is changed to allow ${tlsIssuerCa}.`
        : `A CAA policy at ${owner} allows only ${[...permitted].join(", ")} to issue certificates — ${tlsIssuerCa} is not on it, so issuance for this name will fail until a CAA record for ${tlsIssuerCa} is added.`,
  };
}

async function caaAdvisoryFor(
  fqdn: string,
  zone: string,
  authoritative: DnsResolver,
  publicResolver: DnsResolver,
  tlsIssuerCa: string | null,
): Promise<TlsIssuanceAdvisory | null> {
  for (const name of climbToApex(fqdn, apexOf(fqdn))) {
    const resolver = isAtOrBelow(name, zone) ? authoritative : publicResolver;
    const outcome = await read(() => resolver.resolveCaa(name));
    if (outcome.kind === "error") return unchecked(fqdn, name, `CAA lookup ${outcome.code}`);
    if (outcome.kind === "absent" || outcome.answers.length === 0) continue;
    return judgeCaaAnswers(fqdn, name, outcome.answers, tlsIssuerCa);
  }
  return null;
}

async function acmeChallengeAdvisoryFor(
  fqdn: string,
  authoritative: DnsResolver,
): Promise<TlsIssuanceAdvisory | null> {
  const challengeName = `${ACME_CHALLENGE_LABEL}.${fqdn}`;

  // CNAME first: a DNS-01 delegation (`_acme-challenge.host CNAME acme.old-vendor.com`)
  // is the shape a departed vendor most often leaves, and a TXT query on a
  // CNAME'd name would only chase it.
  const cname = await read(() => authoritative.resolveCname(challengeName));
  if (cname.kind === "error") {
    return unchecked(fqdn, challengeName, `challenge CNAME lookup ${cname.code}`);
  }
  if (cname.kind === "answers" && cname.answers.length > 0) {
    return {
      code: "stale_acme_challenge",
      severity: "warning",
      fqdn,
      evidenceFqdn: challengeName,
      evidence: cname.answers.map((target) => `CNAME ${target}`),
      note: `${challengeName} is delegated to another provider. A certificate authority validating this name over DNS follows that delegation, so issuance fails unless that provider still answers for it — remove the CNAME if it belongs to a previous vendor.`,
    };
  }

  const txt = await read(() => authoritative.resolveTxt(challengeName));
  if (txt.kind === "error") {
    return unchecked(fqdn, challengeName, `challenge TXT lookup ${txt.code}`);
  }
  if (txt.kind === "absent") return null;
  const values = txt.answers.map((parts) => parts.join(""));
  if (values.length === 0) return null;
  return {
    code: "stale_acme_challenge",
    severity: "warning",
    fqdn,
    evidenceFqdn: challengeName,
    evidence: values,
    note: `${challengeName} already holds ${values.length === 1 ? "a validation token" : `${values.length} validation tokens`} from an earlier certificate request. A stale token can make a new DNS-01 validation fail — remove it if it isn't for the certificate you're about to issue.`,
  };
}

/**
 * Compute the TLS-issuance advisories for one session's expected records.
 *
 * Only the hosts of TLS-terminating records (A/AAAA/CNAME —
 * `isTlsTerminatingRecordType`) are inspected; a TXT ownership token or an MX
 * never gets a certificate. Each distinct host is read once even when a
 * session carries an A and an AAAA for it. Results are ordered by host, then
 * CAA before ACME, so the same DNS state always renders the same list.
 *
 * `tlsIssuerCa` is the integrator's CA issuer-domain (`App.tlsIssuerCa`), or
 * null when they have not told us — in which case a CAA set is reported as
 * `caa_restricts_issuance` (info) rather than judged.
 *
 * Never throws for a DNS outcome; a failed lookup becomes
 * `tls_issuance_unchecked` (unknown ≠ clean). A throw from here is a
 * programming error, and callers report it as one.
 */
export async function detectTlsIssuanceAdvisories(
  records: ExpectedRecord[],
  tlsIssuerCa: string | null,
  deps: VerifyDeps = {},
): Promise<TlsIssuanceAdvisory[]> {
  const hosts = [
    ...new Set(
      records.filter((r) => isTlsTerminatingRecordType(r.type)).map((r) => canonicalHost(r.fqdn)),
    ),
  ].sort();

  const perHost = await Promise.all(
    hosts.map(async (host): Promise<TlsIssuanceAdvisory[]> => {
      const { zone, publicResolver, authoritative } = await resolveZoneAuthority(host, deps);
      if (authoritative.kind !== "resolver") {
        return [unchecked(host, zone, `nameservers ${authoritative.kind}`)];
      }
      const caa = await caaAdvisoryFor(
        host,
        zone,
        authoritative.resolver,
        publicResolver,
        tlsIssuerCa,
      );
      const acme = await acmeChallengeAdvisoryFor(host, authoritative.resolver);
      return [caa, acme].filter((a): a is TlsIssuanceAdvisory => a !== null);
    }),
  );
  return perHost.flat();
}
