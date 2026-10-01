// THE one home for "how long may a single DNS query take, and how many tries".
//
// node:dns' module-level helpers (`resolveNs`, `resolveTxt`, …) run on c-ares'
// own defaults, and those defaults are not a bound anyone should ship behind a
// web request. MEASURED on 2026-09-09, one `resolveNs` at a black-holed
// nameserver (192.0.2.1, RFC 5737):
//
//   node:dns defaults          30.20 s to ETIMEOUT
//   this module's 5 s × 2      15.10 s to ETIMEOUT
//
// Three of the former in a row — a two-candidate zone walk plus one discovery
// TXT — is a minute and a half of a request thread spent learning nothing,
// which is how the landing provider detector came to hang past Playwright's
// 120 s ceiling in CI (browser-e2e run 34295696219 and three siblings,
// 2026-09-09 00:59–01:45Z).
//
// 5 s × 2 tries is what verify.ts has shipped since it was written, for exactly
// this reason; this module is where that pair now LIVES, so the zone walk and
// Domain Connect discovery — which had no bound at all — inherit it instead of
// growing a fourth and fifth copy of the same two numbers.
//
// These are DEFAULTS, overridable per call through each module's deps: packages/core
// takes config as ARGUMENTS and never reads process.env (scripts/check-core-config-bans.sh).

import { Resolver } from "node:dns/promises";

/** Per-try budget for one DNS query. Long enough for a slow authoritative
 * server on another continent, short enough that a dead one is not mistaken
 * for a slow one. */
export const DEFAULT_DNS_TIMEOUT_MS = 5000;

/** Tries per query. Two absorbs a single lost UDP datagram — the failure mode
 * a retry actually fixes. Note that c-ares DOUBLES the timeout on each retry,
 * so the pair bounds one query at ~15 s (5 + 10), not 10 s; the measurement
 * above is that number. A caller that cannot afford 15 s must impose its own
 * ceiling over the whole operation — apps/web's preflight engine does. */
export const DEFAULT_DNS_TRIES = 2;

/** A `node:dns/promises` Resolver on the system nameservers, bounded by the
 * numbers above (or the caller's). */
export function boundedResolver(
  timeoutMs: number = DEFAULT_DNS_TIMEOUT_MS,
  tries: number = DEFAULT_DNS_TRIES,
): Resolver {
  return new Resolver({ timeout: timeoutMs, tries });
}

let shared: Resolver | undefined;

/**
 * The process-wide bounded Resolver, for the module-level DEFAULTS that used to
 * call node:dns' unbounded helpers directly (zone-walk.ts, discovery.ts).
 *
 * Memoized rather than built per call: those defaults stand in for node's own
 * process-default resolver, which is likewise one long-lived c-ares channel, so
 * a singleton keeps the socket/channel behaviour they replaced. Built lazily so
 * importing core never opens a channel — a unit test that injects its own
 * `resolveNs`/`resolveTxt` must not touch DNS at all.
 */
export function sharedBoundedResolver(): Resolver {
  shared ??= boundedResolver();
  return shared;
}
