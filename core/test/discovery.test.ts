import { test } from "node:test";
import assert from "node:assert/strict";
import {
  parseSettings,
  settingsUrl,
  templateSupportUrl,
  sanitizeProviderHost,
  discover,
  isTemplateSupported,
  DiscoveryError,
  type DiscoveryDeps,
} from "../src/discovery.ts";
import { nearestZoneCut } from "../src/zone-walk.ts";

test("parseSettings accepts a valid settings object", () => {
  const s = parseSettings({
    providerId: "virtucondomains.example",
    providerName: "Virtucon Domains",
    urlSyncUX: "https://domainconnect.virtucondomains.example",
    urlAPI: "https://api.domainconnect.virtucondomains.example",
    nameServers: ["ns01.example", "ns02.example"],
  });
  assert.equal(s.providerId, "virtucondomains.example");
  assert.deepEqual(s.nameServers, ["ns01.example", "ns02.example"]);
});

test("parseSettings rejects missing required fields", () => {
  assert.throws(() => parseSettings({ providerId: "x" }), DiscoveryError);
});

test("parseSettings rejects non-https endpoints", () => {
  assert.throws(
    () =>
      parseSettings({
        providerId: "x",
        providerName: "X",
        urlSyncUX: "http://insecure.example",
        urlAPI: "https://api.example",
      }),
    DiscoveryError,
  );
});

test("sanitizeProviderHost accepts host AND host+path prefix, rejects injection", () => {
  assert.equal(sanitizeProviderHost("connect.ionos.com"), "connect.ionos.com");
  // Cloudflare publishes a host+path prefix (real value on devino.ca):
  assert.equal(
    sanitizeProviderHost("api.cloudflare.com/client/v4/dns/domainconnect"),
    "api.cloudflare.com/client/v4/dns/domainconnect",
  );
  assert.throws(() => sanitizeProviderHost("https://evil.example/path"), DiscoveryError);
  assert.throws(() => sanitizeProviderHost("a..b"), DiscoveryError);
  assert.throws(() => sanitizeProviderHost("host.example@evil.com"), DiscoveryError);
  assert.throws(() => sanitizeProviderHost("host.example/p?x=1"), DiscoveryError);
});

test("settingsUrl & templateSupportUrl build canonical paths", () => {
  assert.equal(
    settingsUrl("connect.example", "customer.com"),
    "https://connect.example/v2/customer.com/settings",
  );
  // host+path prefix (Cloudflare style):
  assert.equal(
    settingsUrl("api.cloudflare.com/client/v4/dns/domainconnect", "devino.ca"),
    "https://api.cloudflare.com/client/v4/dns/domainconnect/v2/devino.ca/settings",
  );
  assert.equal(
    templateSupportUrl("https://api.example/", "dodomain.io", "custom-subdomain-cname"),
    "https://api.example/v2/domainTemplates/providers/dodomain.io/services/custom-subdomain-cname",
  );
});

test("discover() resolves TXT -> settings (mocked deps)", async () => {
  const res = await discover("customer.com", {
    resolveTxt: async (host) => {
      assert.equal(host, "_domainconnect.customer.com");
      return [["connect.example"]];
    },
    fetchJson: async (url) => {
      assert.equal(url, "https://connect.example/v2/customer.com/settings");
      return {
        ok: true,
        status: 200,
        json: {
          providerId: "example",
          providerName: "Example",
          urlSyncUX: "https://sync.example",
          urlAPI: "https://api.example",
        },
      };
    },
  });
  assert.equal(res.providerHost, "connect.example");
  assert.equal(res.settings.providerId, "example");
});

test("discover() throws when provider returns 404 (stale TXT / zone not hosted)", async () => {
  await assert.rejects(
    () =>
      discover("customer.com", {
        resolveTxt: async () => [["connect.example"]],
        fetchJson: async () => ({ ok: false, status: 404, json: null }),
      }),
    DiscoveryError,
  );
});

test("isTemplateSupported maps 200->true, 404->false", async () => {
  const yes = await isTemplateSupported("https://api.example", "p", "s", {
    fetchJson: async () => ({ ok: true, status: 200, json: null }),
  });
  const no = await isTemplateSupported("https://api.example", "p", "s", {
    fetchJson: async () => ({ ok: false, status: 404, json: null }),
  });
  assert.equal(yes, true);
  assert.equal(no, false);
});

// ── discovery on the zone that OWNS the records ─────────────────────────────
//
// The spec's Root Domain is "a registered domain (e.g. example.com or
// example.co.uk), OR a delegated zone in DNS", and discovery "must work on the
// root domain (zone) only. Bear in mind that zones can be delegated to other
// users". The apply call's `domain` is likewise "the root domain (the
// registered domain or delegated zone)". A PSL-apex-only lookup therefore
// dead-ends on every delegated subzone.
//
// The fixtures below are the LIVE case probed 2026-08-06 (dig via 1.1.1.1):
//   mrneon.online       NS doug/riya.ns.cloudflare.com
//                       _domainconnect TXT "api.cloudflare.com/client/v4/dns/domainconnect"
//   dc.mrneon.online    NS ns1..ns4.as207960.net              <- a real zone cut
//                       _domainconnect CNAME -> TXT "dns.glauca.digital/connect"
//   status.dc.mrneon.online   NXDOMAIN (no cut, no TXT)
// Cloudflare 404s our two templates; Glauca serves both. So a session on
// status.dc.mrneon.online must resolve the root dc.mrneon.online.

const GLAUCA_SETTINGS = {
  providerId: "glauca",
  providerName: "Glauca Digital",
  urlSyncUX: "https://dns.glauca.digital/domain-connect",
  urlAPI: "https://dns.glauca.digital/connect",
};
const CLOUDFLARE_SETTINGS = {
  providerId: "cloudflare",
  providerName: "Cloudflare",
  urlSyncUX: "https://dash.cloudflare.com/domainconnect",
  urlAPI: "https://api.cloudflare.com/client/v4/dns/domainconnect",
};

interface WalkLog {
  ns: string[];
  txt: string[];
  settings: string[];
}

function newLog(): WalkLog {
  return { ns: [], txt: [], settings: [] };
}

/** Offline resolver stubs: `cuts` are the names that own an NS RRset (zone
 * apexes), `txt` maps a queried `_domainconnect.<name>` to its prefix value. */
function walkDeps(
  log: WalkLog,
  cuts: string[],
  txt: Record<string, string>,
  settings: Record<string, unknown> = {},
): DiscoveryDeps {
  const cutSet = new Set(cuts);
  return {
    resolveNs: async (host) => {
      log.ns.push(host);
      if (!cutSet.has(host)) throw new Error(`ENODATA ${host}`);
      return ["ns1.stub.example"];
    },
    resolveTxt: async (host) => {
      log.txt.push(host);
      const value = txt[host];
      if (value === undefined) throw new Error(`ENOTFOUND ${host}`);
      return [[value]];
    },
    fetchJson: async (url) => {
      log.settings.push(url);
      const body = Object.entries(settings).find(([host]) => url.includes(host))?.[1];
      if (body === undefined) return { ok: false, status: 404, json: null };
      return { ok: true, status: 200, json: body };
    },
  };
}

/** The live delegated-subzone fixture (mrneon.online / dc.mrneon.online). */
function mrneonDeps(log: WalkLog): DiscoveryDeps {
  return walkDeps(
    log,
    ["dc.mrneon.online", "mrneon.online"],
    {
      "_domainconnect.dc.mrneon.online": "dns.glauca.digital/connect",
      "_domainconnect.mrneon.online": "api.cloudflare.com/client/v4/dns/domainconnect",
    },
    {
      "dns.glauca.digital/connect/v2/dc.mrneon.online/settings": GLAUCA_SETTINGS,
      "api.cloudflare.com/client/v4/dns/domainconnect/v2/mrneon.online/settings":
        CLOUDFLARE_SETTINGS,
    },
  );
}

/**
 * Exactly what production does: resolve the owning zone, then discover on it.
 * Kept as a two-step composition rather than one core helper because apps/web
 * must compile (and possibly reject) the session's records against that zone in
 * between, BEFORE any state transition — see apps/web/src/lib/dc-config.ts
 * `compileRecipeForOwningZone` and the /domain-connect/start route.
 */
async function discoverOwningZone(fqdn: string, deps: DiscoveryDeps) {
  const { zone } = await nearestZoneCut(fqdn, deps);
  return discover(zone, deps);
}

test("owning-zone discovery: a host under a DELEGATED SUBZONE resolves that subzone, not the PSL apex", async () => {
  const log = newLog();
  const res = await discoverOwningZone("status.dc.mrneon.online", mrneonDeps(log));

  assert.equal(res.domain, "dc.mrneon.online", "the delegated zone is the Domain Connect root");
  assert.equal(res.settings.providerId, "glauca");
  assert.equal(res.providerHost, "dns.glauca.digital/connect");
  assert.ok(
    !log.settings.some((u) => u.includes("cloudflare")),
    "the apex provider must never be consulted once the delegated zone answers",
  );
});

test("owning-zone discovery: a candidate with no zone cut of its own is skipped without a TXT query", async () => {
  const log = newLog();
  await discoverOwningZone("status.dc.mrneon.online", mrneonDeps(log));

  assert.deepEqual(log.ns, ["status.dc.mrneon.online", "dc.mrneon.online"]);
  assert.deepEqual(
    log.txt,
    ["_domainconnect.dc.mrneon.online"],
    "status.dc.* owns no NS RRset, so it is not a zone and is never probed",
  );
});

test("owning-zone discovery: the apex is the FLOOR — a bare sub-domain still discovers the registrable apex", async () => {
  const log = newLog();
  const res = await discoverOwningZone("www.mrneon.online", mrneonDeps(log));

  assert.equal(res.domain, "mrneon.online");
  assert.equal(res.settings.providerId, "cloudflare");
});

test("owning-zone discovery: a session ON a delegated zone's own apex resolves that zone", async () => {
  const res = await discoverOwningZone("dc.mrneon.online", mrneonDeps(newLog()));

  assert.equal(res.domain, "dc.mrneon.online");
  assert.equal(res.settings.providerId, "glauca");
});

test("owning-zone discovery: an apex-only provider is unchanged — same root, same settings as discover()", async () => {
  const log = newLog();
  const deps = walkDeps(
    log,
    ["customer.com"],
    { "_domainconnect.customer.com": "connect.example" },
    { "connect.example/v2/customer.com/settings": GLAUCA_SETTINGS },
  );
  const res = await discoverOwningZone("shop.customer.com", deps);

  assert.equal(res.domain, "customer.com");
  assert.equal(res.settings.providerId, "glauca");
});

test("owning-zone discovery: nothing answers -> fail-closed with the APEX's error (today's behaviour, unchanged)", async () => {
  const log = newLog();
  const deps = walkDeps(log, ["customer.com"], {});
  await assert.rejects(
    () => discoverOwningZone("status.customer.com", deps),
    (e: unknown) =>
      e instanceof DiscoveryError &&
      /No _domainconnect TXT for customer\.com/.test((e as Error).message),
  );
});

test("owning-zone discovery: a delegated zone whose settings 404 FAILS — it never borrows the apex's provider", async () => {
  // Spec: "The Service Provider must handle the condition when a query for the
  // _domainconnect TXT record succeeds, but a call to query for the JSON
  // fails." Handling it means Domain Connect is unavailable here, NOT retrying
  // at customer.com: that provider does not host stale.customer.com, so an
  // apply addressed to it could never write the record.
  const log = newLog();
  const deps = walkDeps(
    log,
    ["stale.customer.com", "customer.com"],
    {
      "_domainconnect.stale.customer.com": "gone.example",
      "_domainconnect.customer.com": "connect.example",
    },
    { "connect.example/v2/customer.com/settings": CLOUDFLARE_SETTINGS },
  );

  await assert.rejects(() => discoverOwningZone("a.stale.customer.com", deps), DiscoveryError);
  assert.deepEqual(
    log.settings,
    ["https://gone.example/v2/stale.customer.com/settings"],
    "only the owning zone is asked; the apex provider (connect.example) is never consulted",
  );
  assert.deepEqual(log.txt, ["_domainconnect.stale.customer.com"]);
});

test("owning-zone discovery: the walk never climbs past the registrable apex into the public suffix", async () => {
  const log = newLog();
  const deps = walkDeps(log, [], {});
  await assert.rejects(() => discoverOwningZone("a.b.customer.co.uk", deps), DiscoveryError);

  assert.ok(!log.ns.includes("co.uk"), "co.uk is the REGISTRY's zone, never a customer root");
  assert.ok(!log.txt.includes("_domainconnect.co.uk"));
  assert.deepEqual(log.txt, ["_domainconnect.customer.co.uk"], "only the apex floor is queried");
});

test("owning-zone discovery: a very deep hostname is bounded but still reaches the apex floor", async () => {
  const log = newLog();
  const deep = "a.b.c.d.e.f.g.h.i.j.k.customer.com";
  const deps = walkDeps(
    log,
    ["customer.com"],
    { "_domainconnect.customer.com": "connect.example" },
    { "connect.example/v2/customer.com/settings": GLAUCA_SETTINGS },
  );
  const res = await discoverOwningZone(deep, deps);

  assert.equal(res.domain, "customer.com");
  assert.ok(log.ns.length <= 8, `walk must stay bounded, probed ${log.ns.length} candidates`);
});
