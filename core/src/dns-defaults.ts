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

import { createSocket } from "node:dgram";
import { Resolver } from "node:dns/promises";
import { isIPv6 } from "node:net";
import type { AddressRecordType } from "./record-capabilities.ts";

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

/** The engine previously delegated alias following to c-ares and exposed no
 * chain-depth limit. Explicit inspection stops after ten CNAME queries; this
 * adds a request bound without changing any existing DNS timeout or retry. */
export const CNAME_CHAIN_MAX_DEPTH = 10;

interface DnsAddressWithTtl {
  address: string;
  ttl: number;
}

export interface DnsTtlResolver {
  resolveWithTtl(host: string, type: AddressRecordType): Promise<DnsAddressWithTtl[]>;
}

/** A `node:dns/promises` Resolver on the system nameservers, bounded by the
 * numbers above (or the caller's). */
export function boundedResolver(
  timeoutMs: number = DEFAULT_DNS_TIMEOUT_MS,
  tries: number = DEFAULT_DNS_TRIES,
): Resolver & DnsTtlResolver {
  const resolver = new Resolver({ timeout: timeoutMs, tries });
  return Object.assign(resolver, {
    resolveWithTtl: (host: string, type: AddressRecordType) =>
      type === "A"
        ? resolver.resolve4(host, { ttl: true })
        : resolver.resolve6(host, { ttl: true }),
  });
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

/**
 * ONE raw DNS exchange over UDP: send `packet` to `server`:53, resolve with the
 * first datagram that server sends back, reject with code `ETIMEOUT` after
 * `timeoutMs`. A single try; the caller owns retries (ns-delegation.ts spends
 * DEFAULT_DNS_TRIES of these, each on the next parent server, so its query step
 * is bounded at timeout × tries, under the ~15 s one c-ares query costs).
 *
 * Why a raw socket at all (T-10301): c-ares cannot read a REFERRAL. Asked
 * directly, a parent (TLD) server answers an NS query for a child zone with the
 * child's NS in the AUTHORITY section and no answer, which node:dns surfaces as
 * ENODATA (measured 2026-10-29 against a.gtld-servers.net, verify.ts's NS
 * branch). Reading the delegation from the parent is the only way to see a
 * nameserver move before a recursive resolver's 24 h NS cache expires, so the
 * query is built and parsed by hand (ns-delegation.ts) and only the socket
 * lives here, beside the resolver bounds it shares. Lives in THIS file so
 * scripts/check-dns-bounds-bans.sh can keep every DNS socket in packages/core
 * behind these numbers (it bans node:dgram elsewhere too).
 */
export function udpExchange(
  server: string,
  packet: Uint8Array,
  timeoutMs: number = DEFAULT_DNS_TIMEOUT_MS,
): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const socket = createSocket(isIPv6(server) ? "udp6" : "udp4");
    let settled = false;
    const finish = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.close();
      fn();
    };
    const timer = setTimeout(
      () =>
        finish(() =>
          reject(
            Object.assign(new Error(`DNS query to ${server} timed out after ${timeoutMs} ms`), {
              code: "ETIMEOUT",
            }),
          ),
        ),
      timeoutMs,
    );
    socket.on("error", (error) => finish(() => reject(error)));
    socket.on("message", (message, remote) => {
      // Only the server we asked may answer; anything else is ignored (an
      // off-path datagram is not a reply, and the ID check in the caller is
      // the second filter).
      if (remote.address !== server) return;
      finish(() => resolve(new Uint8Array(message)));
    });
    socket.send(packet, 53, server, (error) => {
      if (error) finish(() => reject(error));
    });
  });
}
