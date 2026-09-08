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
  /** The google.com/domain-verification control probe — proves the API answers before any 404 is believed. */
  control: z.object({ ok: z.boolean(), status: z.union([z.number().int(), z.string()]) }),
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
