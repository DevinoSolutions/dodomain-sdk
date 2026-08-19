// Record helpers shared by the API + connect flow: turn a session's simple
// record list into fully-qualified ExpectedRecords for verification.

import { z } from "zod";

import type { ExpectedRecord } from "./types.ts";
import { isRecordType, RECORD_TYPES } from "./record-capabilities.ts";

// Re-exported so `@dodomain/core/records` (the client-safe subpath) is the one
// place both the record helpers AND the record-type capability source are
// available from (F-002 §9 — "no second hardcoded DNS record-type list").
export * from "./record-capabilities.ts";

// F-008: the ONE zod schema for the record SHAPE (the 5-type enum + fields) —
// replaces the 3 independently hand-copied shapes the finding named (this
// package's own SessionRecord interface, apps/web's RecordSchema, the node
// SDK's DnsRecord). `type` is derived from RECORD_TYPES (not a re-typed
// literal union) so the shape schema can never itself drift from the
// capability source it sits beside in this file. This schema is SHAPE only —
// it does NOT encode "which types are writable" or "MX requires a priority";
// those are F-002's capability call (record-capabilities.ts's
// isTier1Writable/requiresPriority), composed by callers (see
// apps/web/src/app/api/v1/sessions/route.ts), never re-forked here.
export const zRecord = z.object({
  type: z.enum(RECORD_TYPES),
  host: z.string().min(1),
  value: z.string().min(1),
  priority: z.number().int().optional(),
  ttl: z.number().int().optional(),
});

export const zRecords = z.array(zRecord);

// The exported NAME is preserved (was a hand-written interface) so every
// existing `import type { SessionRecord }` consumer (apply.ts, verify route,
// cf/callback route, the hosted connect page) is unaffected — only its
// definition changed, from a hand-copy to a schema-derived type.
export type SessionRecord = z.infer<typeof zRecord>;

export function fqdnFor(host: string, domain: string): string {
  const h = host.trim();
  if (h === "@" || h === "" || h === domain) return domain;
  if (h.endsWith(`.${domain}`)) return h;
  return `${h}.${domain}`;
}

// Inverse of fqdnFor over the registrable ZONE (issue #41): the name a user
// types in their DNS provider's Name/Host field, given the fully-qualified
// name verification checks. "@" = the zone apex; a fqdn outside the zone has
// no relative form and comes back unchanged (fully qualified). The hosted
// connect flow renders record names through this so the display can never
// drift from what POST /verify checks — session hosts are relative to the
// SESSION domain (fqdnFor above), but provider DNS UIs operate on the zone:
// fqdn "status-e2e.devino.ca" in zone "devino.ca" → "status-e2e", never "@"
// (which at the provider would mis-target the ZONE apex).
export function zoneRelativeName(fqdn: string, zone: string): string {
  const f = fqdn.trim().replace(/\.$/, "");
  if (f === zone) return "@";
  if (f.endsWith(`.${zone}`)) return f.slice(0, -(zone.length + 1));
  return f;
}

// ── Create-time record composition (F3, BioFlow live-E2E 2026-08-12) ────────
// Until this existed, the fqdn a session would actually be verified at was
// computed NOWHERE the integrator could see it: POST /sessions echoed only the
// token, and `fqdnFor` first ran at verify time. An integrator who sent
// `domain: "links.acme.com"` together with `host: "links"` got a 200, a working
// connect link, and only discovered `links.links.acme.com` when verification
// failed against a record they had correctly created at `links.acme.com`. Both
// helpers below are pure and compose `fqdnFor` — they never re-derive the
// composition rule, so what the create response promises and what verify checks
// cannot drift.

/** One requested record paired with the fully-qualified name verification will
 * check for it. `host` is echoed verbatim (what the caller sent) so the mapping
 * from their input to our composed name is legible in one object. */
export interface ComposedRecord {
  type: SessionRecord["type"];
  host: string;
  fqdn: string;
}

/** The composed view of a session's records — what DoDomain will monitor. */
export function composeRecords(records: SessionRecord[], domain: string): ComposedRecord[] {
  return records.map((r) => ({ type: r.type, host: r.host, fqdn: fqdnFor(r.host, domain) }));
}

/** A non-fatal advisory about a record the API accepted. Additive by
 * construction: `code` is the field to branch on, `message` is prose for a log. */
export interface RecordHostWarning {
  code: "duplicate_host_label";
  message: string;
  host: string;
  fqdn: string;
}

/**
 * True when composing `host` under `domain` REPEATS a label — the host's
 * trailing label (the one that ends up adjacent to the domain) equals the
 * domain's leading label, e.g. host "links" under domain "links.acme.com" →
 * "links.links.acme.com".
 *
 * WARN, NOT REJECT (deliberate, see the route): the doubled name is a perfectly
 * legal DNS name and `fqdnFor` has always composed it, so a 422 here would
 * change the meaning of a request shape this API has accepted since day one —
 * on a repo whose merges deploy straight to production, for a live integrator.
 * Nothing in the code or docs distinguishes an intentional
 * "links.links.acme.com" from the mistake, so the honest move is to say what
 * we composed and let the caller decide.
 *
 * Non-composing hosts are never flagged: "@"/""/the domain itself resolve to
 * the apex, and an already-fully-qualified host is returned unchanged — in
 * neither case does a label get repeated.
 */
function duplicatesLeadingLabel(host: string, domain: string): boolean {
  const h = host.trim();
  if (h === "" || h === "@" || h === domain) return false;
  if (h.endsWith(`.${domain}`)) return false;
  const adjacent = h.split(".").at(-1)?.toLowerCase();
  const leading = domain.split(".")[0]?.toLowerCase();
  return adjacent !== undefined && adjacent === leading;
}

/** Advisories for a session's records — empty when nothing is suspicious. */
export function recordHostWarnings(records: SessionRecord[], domain: string): RecordHostWarning[] {
  return records
    .filter((r) => duplicatesLeadingLabel(r.host, domain))
    .map((r) => {
      const fqdn = fqdnFor(r.host, domain);
      return {
        code: "duplicate_host_label" as const,
        message: `host "${r.host}" repeats the leading label of domain "${domain}" — this session will be verified at "${fqdn}". Use host "@" if you meant "${domain}".`,
        host: r.host,
        fqdn,
      };
    });
}

// FIX(F-002): filters via the single capability source (isRecordType) instead of
// a hand-rolled 5-way `||` — dedups what used to be an independently-drifting
// list. Carries `priority` through to the ExpectedRecord (hop 1 of the MX-priority
// fix) so verify.ts can match on preference, not just exchange.
export function toExpectedRecords(records: SessionRecord[], domain: string): ExpectedRecord[] {
  return records
    .filter((r) => isRecordType(r.type))
    .map((r) => ({
      type: r.type,
      fqdn: fqdnFor(r.host, domain),
      expect: r.value,
      ...(r.priority !== undefined ? { priority: r.priority } : {}),
    }));
}
