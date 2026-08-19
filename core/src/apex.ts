// Single PSL-backed apex/registrable-domain util (F-011 / PM-008). Both
// verify.ts (the zone whose authoritative NS get queried) and detect.ts (the
// zone whose NS drive provider/tier detection) import `apexOf` from here — a
// naive "last two labels" guess used to be duplicated in both files and
// mis-zoned `.co.uk`-class domains (e.g. "status.customer.co.uk" guessed
// apex "co.uk", the REGISTRY's zone, not "customer.co.uk"). Backed by
// `tldts` (Public Suffix List data) so multi-label public suffixes (.co.uk,
// .com.au, ...) resolve to the correct registrable domain.
//
// CI-grep enforced: scripts/check-apex-bans.sh bans re-introducing a private
// `zoneOf`/`apexOf` declaration, or the `.slice(-2)` last-two-labels guess it
// replaced, anywhere in packages/core/src outside this one file.
import { getDomain } from "tldts";

/**
 * The registrable domain (eTLD+1) for a fully-qualified host, e.g.
 * "status.customer.co.uk" -> "customer.co.uk", "a.b.example.com" ->
 * "example.com". Falls back to the (trimmed/lowercased) input itself when
 * `tldts` finds no registrable label under the matched public suffix — a
 * bare suffix ("co.uk" itself) or an unrecognised single-label host
 * ("localhost"). That fallback is a strict improvement over the naive guess
 * it replaces: it only triggers on inputs that were never a normal
 * `sub.domain.tld` shape to begin with.
 */
export function apexOf(fqdn: string): string {
  const host = fqdn.trim().replace(/\.$/, "").toLowerCase();
  return getDomain(host) ?? host;
}
