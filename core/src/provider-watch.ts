import { templateServiceIdForDnsProvider } from "./domain-connect-templates.ts";
import { z } from "./zod-runtime.ts";

// The nightly Domain Connect provider-watch SNAPSHOT — the shape
// scripts/ci/dc-provider-watch.mjs writes to docs/domain-connect/
// provider-watch.json and apps/landing's /state-of-domain-connect renders.
//
// The writer is a zero-dependency .mjs (the workflow runs it without a pnpm
// install), so it cannot import this schema; this file is the READER's pin.
// packages/core/test/provider-watch.test.ts parses the committed snapshot
// with it, so a writer/reader drift fails `pnpm --filter @dodomain/core test`
// in CI rather than the landing build at 05:10 UTC. Client-safe (zod only),
// exposed as "@dodomain/core/provider-watch".

/** ISO date, `YYYY-MM-DD` — the day a provider was first seen serving a template. */
const zIsoDate = z.string().regex(/^\d{4}-\d{2}-\d{2}$/);

/**
 * What ONE provider's Domain Connect API said about ONE of our templates:
 *   served      — 200: the provider serves the template (support detected;
 *                 NOT the same as a real apply having been proven — the page
 *                 keeps that ledger separately);
 *   not_served  — 404 (or another non-200) with a passing control probe;
 *   regressed   — a pair the watch knows as supported no longer answers 200;
 *   unchecked   — the provider's control probe failed, so the watch was blind
 *                 there tonight; says nothing about support either way.
 */
export const zProviderWatchTemplateState = z.enum([
  "served",
  "not_served",
  "regressed",
  "unchecked",
]);

export const zProviderWatchTemplate = z.object({
  state: zProviderWatchTemplateState,
  /** The HTTP status the template probe returned; null when the probe did not run or did not complete. */
  status: z.union([z.number().int(), z.string()]).nullable(),
  /** The day support was first probed; carried forward across snapshots. Null when never served. */
  firstSeen: zIsoDate.nullable(),
  /** The `version` in the provider's 200 body, when it carried one. */
  servedVersion: z.number().int().nullable(),
  /** true = servedVersion differs from the registry master's (Templates#1570 shape); null when not served or unreadable. */
  versionDrift: z.boolean().nullable(),
});

export const zProviderWatchProvider = z.object({
  name: z.string().min(1),
  urlAPI: z.string().url(),
  /** The control probe — proves the API answers before any 404 is believed. */
  control: z.object({
    /** `providerId/serviceId` of the control template: google.com/domain-verification
     * unless the provider does not serve it (Host Europe: wix.com/website). Absent in
     * snapshots written before 2026-10-19, which always used the google.com one. */
    template: z.string().min(1).optional(),
    ok: z.boolean(),
    status: z.union([z.number().int(), z.string()]),
  }),
  templates: z.record(z.string(), zProviderWatchTemplate),
});

export const zProviderWatchSnapshot = z.object({
  schemaVersion: z.literal(1),
  /** When the probe that produced this state ran. */
  probedAt: z.string().datetime(),
  /** The GitHub Actions run, when produced by the workflow; null from a local run. */
  run: z.object({ id: z.string(), url: z.string().url() }).nullable(),
  ourTemplates: z.object({ providerId: z.string(), serviceIds: z.array(z.string().min(1)) }),
  registry: z.object({
    /** Where the reference versions came from: the registry master, or our submitted copy when GitHub was unreachable. */
    source: z.enum(["registry", "local"]),
    versions: z.record(z.string(), z.number().int()),
  }),
  providers: z.array(zProviderWatchProvider),
});

export type ProviderWatchSnapshot = z.infer<typeof zProviderWatchSnapshot>;
export type ProviderWatchTemplate = z.infer<typeof zProviderWatchTemplate>;

/* The proven-apply ledger — a REAL signed apply accepted by the provider, the
   record written, verified against the authoritative nameservers, on a zone
   DoDomain controls. Dated and sourced (.claude/rules/domain-connect-tier2.md
   and docs/domain-connect-provider-onboarding.md carry the evidence). A
   provider serving a template (the matrix) is a weaker claim than this; the
   two are never merged into one green mark. Lives here, beside the snapshot
   reader, because /state-of-domain-connect and the conversion guide both
   state it. */
export const PROVEN_APPLIES: ReadonlyArray<{
  provider: string;
  serviceId: string;
  date: string;
  note: string;
}> = [
  {
    provider: "Glauca",
    serviceId: "domain-verification",
    date: "2026-08-06",
    note: "Signed apply accepted, TXT written by HexDNS, verified on all four authoritative nameservers, session completed and webhook delivered.",
  },
  {
    provider: "Glauca",
    serviceId: "custom-subdomain-cname",
    date: "2026-08-12",
    note: "Same zone, CNAME template, after Glauca fixed their CNAME apply bug (AS207960/hexdns#9), which had 500'd every CNAME apply until then.",
  },
  {
    provider: "Cloudflare",
    serviceId: "domain-verification",
    date: "2026-09-25",
    note: "Signed apply accepted on Cloudflare's consent page, TXT written to a Cloudflare-hosted zone and live within 30 seconds, session verified. Cloudflare switched all five DoDomain templates to live mode for every customer the same day.",
  },
  {
    provider: "Cloudflare",
    serviceId: "custom-subdomain-cname",
    date: "2026-09-25",
    note: "Same zone, CNAME template: the first live exercise of the key-before-signature URL order Cloudflare requires.",
  },
  {
    provider: "Cloudflare",
    serviceId: "custom-subdomain-cname-with-verification",
    date: "2026-09-26",
    note: "CNAME plus the ownership TXT under the same host, both written in one approval, verified on the authoritative nameservers, session verified.",
  },
  {
    provider: "Cloudflare",
    serviceId: "apex-a-with-verification",
    date: "2026-09-26",
    note: "Apex A plus the ownership TXT. Cloudflare listed the zone's existing apex A for removal and asked for the zone name to be typed before applying; both records verified, session verified.",
  },
  {
    provider: "Cloudflare",
    serviceId: "email-authentication",
    date: "2026-09-26",
    note: "Every group applied and verified: DKIM as CNAME and as TXT, DMARC, and the SPF merge, where Cloudflare folded our include into the zone's existing SPF record and kept its other terms.",
  },
  {
    provider: "Vercel",
    serviceId: "custom-subdomain-cname",
    date: "2026-10-20",
    note: "Signed apply approved on Vercel's own consent prompt in the domain's dashboard page, CNAME written to a Vercel DNS zone, session verified; repeated on four fresh subdomains the next day.",
  },
  {
    provider: "Glauca",
    serviceId: "custom-subdomain-cname-with-verification",
    date: "2026-10-22",
    note: "Same HexDNS zone: CNAME plus the ownership TXT under the same host, both written in one approval, served by all four authoritative nameservers, session verified.",
  },
  {
    provider: "Glauca",
    serviceId: "email-authentication",
    date: "2026-10-22",
    note: "Every group applied and verified: the SPF merge, DKIM as CNAME and as TXT, and DMARC. HexDNS replaced the zone's default no-mail SPF and DMARC records, leaving exactly one of each.",
  },
  {
    provider: "Glauca",
    serviceId: "apex-a-with-verification",
    date: "2026-10-23",
    note: "Apex A plus the ownership TXT on a second HexDNS zone delegated from a Cloudflare-hosted parent. Glauca's consent page listed exactly the two records with nothing to delete; both served by all four authoritative nameservers, session verified.",
  },
  {
    provider: "GoDaddy",
    serviceId: "custom-subdomain-cname",
    date: "2026-11-04",
    note: "Signed apply approved on GoDaddy's consent page for a GoDaddy-registered zone on GoDaddy DNS, CNAME served by both authoritative nameservers about five minutes later, session verified.",
  },
  {
    provider: "GoDaddy",
    serviceId: "email-authentication",
    date: "2026-11-06",
    note: "SPF merge, DKIM CNAME and DMARC applied in one approval on a second GoDaddy-registered zone; GoDaddy replaced its default DMARC and wrote SPF through its own _spfm include, which verify follows. All three records found on the authoritative nameservers, session verified.",
  },
  {
    provider: "GoDaddy",
    serviceId: "custom-subdomain-cname-with-verification",
    date: "2026-11-12",
    note: "Applied through the -v2 sibling GoDaddy loads for this template (ownership value under verification, since GoDaddy reserves the name token): CNAME plus the ownership TXT under the same host in one approval, both served by the authoritative nameservers, session verified.",
  },
  {
    provider: "GoDaddy",
    serviceId: "apex-a-with-verification",
    date: "2026-11-12",
    note: "Apex A plus the ownership TXT through the -v2 sibling. GoDaddy's consent page unhooked its default parking record and touched nothing else, the zone's SPF included; both records served, session verified.",
  },
  {
    provider: "GoDaddy",
    serviceId: "domain-verification",
    date: "2026-11-12",
    note: "Ownership TXT alone through the -v2 sibling, on a zone that already held another ownership value at the same name; GoDaddy kept both, and the session verified.",
  },
];

/* --- Per-provider verdicts (T-5811) -------------------------------------------
   ONE home for "what does this provider's measured state mean for a DoDomain
   customer": the /domain-connect/<provider> pages read it, and every sentence
   it returns is built from the snapshot and PROVEN_APPLIES above, never from
   hand-written per-provider copy. A provider fact the data does not carry
   cannot be produced here. */

export type ProviderWatchProvider = z.infer<typeof zProviderWatchProvider>;

/** What one template means for a customer at one provider:
 *   one_click        served AND a real apply proven on a zone we control;
 *   served_unproven  served and offered by the flow, no proven apply: never called one-click;
 *   not_served       the provider answered the control probe and 404'd the template;
 *   regressed        was served, no longer answers 200;
 *   unchecked        the control probe failed, so no verdict. */
export type TemplateVerdict =
  "one_click" | "served_unproven" | "not_served" | "regressed" | "unchecked";

export interface TemplateVerdictRow {
  serviceId: string;
  verdict: TemplateVerdict;
  /** `YYYY-MM-DD` of the proven apply, when there is one. */
  provenDate: string | null;
  template: ProviderWatchTemplate | null;
}

/**
 * The settings-JSON `providerId` of a watched provider whose applies DoDomain
 * sends to a DNS-provider sibling (core domain-connect-templates.ts
 * `templateServiceIdForDnsProvider`). Hand-kept, like WATCH_PROVIDER_GUIDE: the
 * watch names a provider's API, the sibling table names its settings providerId.
 * "GoDaddy reseller" is absent on purpose: its providerId is unknown, so core
 * still sends it the originals (the TODO(scope) beside that table).
 */
export const WATCH_PROVIDER_DNS_PROVIDER_ID: Readonly<Record<string, string>> = {
  GoDaddy: "godaddy.com",
};

/**
 * The snapshot cell that says whether a customer at this provider can one-click
 * a registry template: the cell of the serviceId DoDomain actually SENDS there.
 * At GoDaddy that is the `-v2` sibling of each `token` template (GoDaddy refuses
 * the originals' applies though it serves them), so a verdict never claims an
 * apply the connect flow will not offer. Null when the snapshot has no such cell.
 */
export function watchedTemplateCell(
  provider: ProviderWatchProvider,
  serviceId: string,
): ProviderWatchTemplate | null {
  const dnsProviderId = WATCH_PROVIDER_DNS_PROVIDER_ID[provider.name];
  const sentServiceId =
    dnsProviderId === undefined
      ? serviceId
      : templateServiceIdForDnsProvider(dnsProviderId, serviceId);
  return provider.templates[sentServiceId] ?? null;
}

export function templateVerdictRows(
  provider: ProviderWatchProvider,
  serviceIds: readonly string[],
  proven: ReadonlyArray<{ provider: string; serviceId: string; date: string }> = PROVEN_APPLIES,
): TemplateVerdictRow[] {
  return serviceIds.map((serviceId) => {
    const template = watchedTemplateCell(provider, serviceId);
    const provenDate =
      proven.find((p) => p.provider === provider.name && p.serviceId === serviceId)?.date ?? null;
    let verdict: TemplateVerdict;
    if (template === null || template.state === "unchecked") verdict = "unchecked";
    else if (template.state === "served") verdict = provenDate ? "one_click" : "served_unproven";
    else verdict = template.state;
    return { serviceId, verdict, provenDate, template };
  });
}

export type ProviderVerdictKind =
  "one_click_all" | "one_click_some" | "served_unproven" | "manual" | "unchecked";

export interface ProviderVerdict {
  kind: ProviderVerdictKind;
  rows: TemplateVerdictRow[];
  total: number;
  oneClick: number;
  servedUnproven: number;
  /** Templates not served there: set up with guided manual records. */
  manual: number;
  headline: string;
}

/** The provider-level verdict. A provider whose every template is unchecked has
 * no verdict at all; otherwise one-click is claimed only for proven applies. */
export function providerVerdict(
  provider: ProviderWatchProvider,
  serviceIds: readonly string[],
  proven?: ReadonlyArray<{ provider: string; serviceId: string; date: string }>,
): ProviderVerdict {
  const rows = templateVerdictRows(provider, serviceIds, proven);
  const total = rows.length;
  const count = (v: TemplateVerdict) => rows.filter((r) => r.verdict === v).length;
  const oneClick = count("one_click");
  const servedUnproven = count("served_unproven");
  const unchecked = count("unchecked");
  const manual = total - oneClick - servedUnproven - unchecked;

  // What the connect flow does where a template is SERVED but no apply is proven:
  // it OFFERS the provider's one-click approval (apps/web/src/lib/
  // domain-connect-config.ts has no proof gate) and falls back to guided manual
  // records if the apply fails. DoDomain just does not PROMISE it, so the copy
  // says offered-not-proven, never "uses manual records".
  const unprovenSentence = `The connect flow offers the provider's one-click approval for ${servedUnproven === 1 ? "it" : "these"}, but DoDomain has not yet proven an end-to-end apply on this provider, so it does not promise it; if an apply fails the flow falls back to guided manual records verified the same way.`;
  const manualSentence =
    manual === total
      ? "Setup uses guided manual records, verified against the authoritative nameservers."
      : `The other ${manual} ${manual === 1 ? "uses" : "use"} guided manual records, verified against the authoritative nameservers.`;

  let kind: ProviderVerdictKind;
  let headline: string;
  if (unchecked === total) {
    kind = "unchecked";
    headline = "The last control probe failed, so there is no verdict for this provider yet.";
  } else if (oneClick === total) {
    kind = "one_click_all";
    headline = `One-click setup on all ${total} DoDomain templates, each apply proven on a real zone.`;
  } else if (oneClick > 0) {
    kind = "one_click_some";
    headline = [
      `One-click setup is proven on ${oneClick} of ${total} DoDomain templates.`,
      servedUnproven > 0
        ? `${servedUnproven} more ${servedUnproven === 1 ? "is" : "are"} served there with no end-to-end apply proven yet. ${unprovenSentence}`
        : "",
      manual > 0 ? manualSentence : "",
    ]
      .filter(Boolean)
      .join(" ");
  } else if (servedUnproven > 0) {
    kind = "served_unproven";
    headline = [
      `Serves ${servedUnproven} of ${total} DoDomain templates. ${unprovenSentence}`,
      manual > 0 ? manualSentence : "",
    ]
      .filter(Boolean)
      .join(" ");
  } else {
    kind = "manual";
    headline = `Its Domain Connect API answers, but it does not serve DoDomain's templates today. ${manualSentence}`;
  }
  return { kind, rows, total, oneClick, servedUnproven, manual, headline };
}

/** Which dedicated manual-setup guide (packages/core/src/guides.ts provider id)
 * belongs to a watched provider, where one exists. Hand-kept because the watch
 * names a provider's Domain Connect API and the guide names its DNS panel;
 * packages/core/test/provider-watch.test.ts pins every value to a real guide.
 * "1&1", "GoDaddy reseller" and "Danego DNS" have no guide of their own and are
 * left out. */
export const WATCH_PROVIDER_GUIDE: Readonly<Record<string, string>> = {
  GoDaddy: "godaddy",
  IONOS: "ionos",
  Cloudflare: "cloudflare",
  Vercel: "vercel",
  NameSilo: "namesilo",
  "Squarespace Domains": "squarespace",
  "WordPress.com": "wordpress",
};
