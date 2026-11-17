// Deterministic DNS fixtures: these tests never use the network.
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { test } from "node:test";
import { CNAME_CHAIN_MAX_DEPTH } from "../src/dns-defaults.ts";
import { compareDnsSnapshot, diagnoseVerification, followCnameChain } from "../src/dns-tools.ts";
import { lookupRecordAcrossResolvers, type DnsLookupDeps } from "../src/dns-lookup.ts";
import {
  isRecordType,
  LOOKUP_RECORD_TYPES,
  type LookupRecordType,
} from "../src/record-capabilities.ts";
import {
  zPublicCnameChainResponse,
  zPublicDnsDiffInput,
  zPublicDnsDiffResponse,
  zPublicVerifyDiagnoserResponse,
} from "../src/schemas.ts";
import type { DnsResolver } from "../src/verify.ts";
import { listProviderGuides } from "../src/guides.ts";

type FakeAnswers = Record<string, string[] | Error>;
const error = (code: string) => Object.assign(new Error(code), { code });

function fakeResolver(answers: FakeAnswers, asked: string[] = [], ttl?: number): DnsResolver {
  const read = async (type: string, host: string): Promise<string[]> => {
    asked.push(`${type} ${host}`);
    const value = answers[`${type} ${host}`];
    if (value instanceof Error) throw value;
    if (value !== undefined) return value;
    if (type === "NS" && (host === "example.com" || host === "target.net"))
      return ["amy.ns.cloudflare.com"];
    return [];
  };
  return {
    resolveNs: (host) => read("NS", host),
    resolveCname: (host) => read("CNAME", host),
    resolve4: (host) => read("A", host),
    resolve6: (host) => read("AAAA", host),
    resolveTxt: async (host) => (await read("TXT", host)).map((value) => [value]),
    resolveMx: async (host) =>
      (await read("MX", host)).map((value) => ({ priority: 10, exchange: value })),
    resolveCaa: async (host) =>
      (await read("CAA", host)).map((value) => ({ critical: 0, issue: value })),
    ...(ttl === undefined
      ? {}
      : {
          resolveWithTtl: async (host: string, type: "A" | "AAAA") =>
            (await read(type, host)).map((address) => ({ address, ttl })),
        }),
  };
}

function fakeDeps(
  authoritative: FakeAnswers = {},
  publicAnswers = authoritative,
  ttl?: number,
): DnsLookupDeps & { asked: string[] } {
  const asked: string[] = [];
  return {
    asked,
    resolver: fakeResolver({}),
    authoritativeResolverFor: async () => ({
      kind: "resolver",
      resolver: fakeResolver(authoritative, asked, ttl),
    }),
    publicResolverFor: () => fakeResolver(publicAnswers, [], ttl),
  };
}

test("CNAME chain follows each target across zones and reaches an address terminal", async () => {
  const deps = fakeDeps({
    "CNAME www.example.com": ["Alias.target.net."],
    "CNAME alias.target.net": ["edge.target.net"],
    "A edge.target.net": ["192.0.2.1"],
  });
  const result = await followCnameChain("WWW.example.com.", deps);
  assert.equal(result.outcome, "complete");
  assert.deepEqual(
    result.chain.map((hop) => hop.target),
    ["alias.target.net", "edge.target.net"],
  );
  assert.equal(result.terminalName, "edge.target.net");
  assert.deepEqual(result.addresses, ["192.0.2.1"]);
  assert.equal(result.apexCname, false);
  zPublicCnameChainResponse.parse(result);
});

test("CNAME loop is a repeated canonical name, including case and trailing-dot differences", async () => {
  const deps = fakeDeps({
    "CNAME www.example.com": ["alias.example.com"],
    "CNAME alias.example.com": ["WWW.EXAMPLE.COM."],
  });
  const result = await followCnameChain("www.example.com", deps);
  assert.equal(result.outcome, "loop");
  assert.equal(result.chain.length, 2);
  assert.equal(deps.asked.filter((query) => query.startsWith("CNAME")).length, 2);
});

test("CNAME inspection flags a published apex CNAME using the PSL-backed apex", async () => {
  const result = await followCnameChain(
    "example.co.uk",
    fakeDeps({ "CNAME example.co.uk": ["edge.target.net"] }),
  );
  assert.equal(result.apexCname, true);
  assert.equal(result.chain[0]?.apex, true);
});

test("an alias-influenced lookup zone is not evidence that a CNAME host is an apex", async () => {
  const deps = {
    ...fakeDeps({ "CNAME www.example.com": ["example.com"] }),
    zone: "www.example.com",
  };
  const chain = await followCnameChain("www.example.com", deps);
  assert.equal(chain.chain[0]?.apex, false);
  assert.equal(chain.apexCname, false);
  const diagnostic = await diagnoseVerification(
    { name: "www.example.com", target: "different.target.net" },
    deps,
  );
  assert.equal(diagnostic.reason, "wrong_target");
});

test("a cross-provider alias is read from its source authority before following the target", async () => {
  const zones: string[] = [];
  const aliases = { "CNAME www.example.com": ["edge.target.net"] };
  const deps: DnsLookupDeps = {
    resolver: fakeResolver({
      ...aliases,
      // A recursive NS lookup followed the alias to the target provider.
      "NS www.example.com": ["ns.other-provider.net"],
      "NS example.com": ["ns.source-provider.net"],
      "NS target.net": ["ns.other-provider.net"],
    }),
    authoritativeResolverFor: async (zone) => {
      zones.push(zone);
      return {
        kind: "resolver",
        resolver: fakeResolver(
          zone === "example.com" ? aliases : { "A edge.target.net": ["192.0.2.9"] },
        ),
      };
    },
    publicResolverFor: () => fakeResolver({ ...aliases, "A edge.target.net": ["192.0.2.9"] }),
  };
  const result = await followCnameChain("www.example.com", deps);
  assert.equal(zones[0], "example.com");
  assert.equal(zones.includes("www.example.com"), false);
  assert.deepEqual(result.chain, [
    { name: "www.example.com", target: "edge.target.net", apex: false },
  ]);
  assert.deepEqual(result.addresses, ["192.0.2.9"]);
});

test("CNAME inspection stops at the engine cap without querying the next target", async () => {
  const answers: FakeAnswers = {};
  for (let index = 0; index <= CNAME_CHAIN_MAX_DEPTH; index += 1)
    answers[`CNAME hop${index}.example.com`] = [`hop${index + 1}.example.com`];
  const deps = fakeDeps(answers);
  const result = await followCnameChain("hop0.example.com", deps);
  assert.equal(result.outcome, "depth_limit");
  assert.equal(result.chain.length, CNAME_CHAIN_MAX_DEPTH);
  assert.equal(deps.asked.includes(`CNAME hop${CNAME_CHAIN_MAX_DEPTH}.example.com`), false);
});

test("apex address answers flag only suspected flattening, never a hidden target", async () => {
  const result = await followCnameChain(
    "example.com",
    fakeDeps({ "A example.com": ["192.0.2.1"] }),
  );
  assert.equal(result.flattening, "suspected");
  assert.deepEqual(result.chain, []);
  assert.equal(result.proxyProvider, null);
});

test("CNAME chains retain suspected flattening at a terminal proxy or apex", async () => {
  for (const terminal of [
    { name: "edge.target.net", address: "104.16.1.2", provider: "cloudflare" },
    { name: "target.net", address: "192.0.2.1", provider: null },
  ]) {
    const result = await followCnameChain(
      "www.example.com",
      fakeDeps({
        "CNAME www.example.com": [terminal.name],
        [`A ${terminal.name}`]: [terminal.address],
      }),
    );
    assert.equal(result.chain.length, 1);
    assert.equal(result.terminalName, terminal.name);
    assert.equal(result.flattening, "suspected");
    assert.equal(result.proxyProvider, terminal.provider);
  }
});

test("a chain ending at a delegated apex with addresses reports suspected flattening", async () => {
  const deps = fakeDeps({
    "CNAME www.example.com": ["delegated.example.com"],
    "A delegated.example.com": ["192.0.2.7"],
  });
  deps.resolver = fakeResolver({ "NS delegated.example.com": ["ns.delegated-provider.net"] });
  const result = await followCnameChain("www.example.com", deps);
  assert.equal(result.chain[0]?.apex, false);
  assert.equal(result.apexCname, false);
  assert.equal(result.terminalName, "delegated.example.com");
  assert.equal(result.flattening, "suspected");
});

test("CNAME DNS failures remain errors instead of missing records or flattened chains", async () => {
  const result = await followCnameChain(
    "www.example.com",
    fakeDeps({ "CNAME www.example.com": error("ETIMEOUT") }),
  );
  assert.equal(result.outcome, "error");
  assert.equal(result.error, "ETIMEOUT");
  assert.equal(result.flattening, "unknown");
});

test("diagnoser accepts a hostname trailing dot and links the detected provider's existing guide", async () => {
  const result = await diagnoseVerification(
    { name: "www.example.com", target: "edge.target.net." },
    fakeDeps({ "CNAME www.example.com": ["edge.target.net"] }),
  );
  assert.equal(result.reason, "verified");
  assert.equal(result.provider.id, "cloudflare");
  assert.equal(result.fixUrl, "/docs/guides/dns-providers/cloudflare");
  zPublicVerifyDiagnoserResponse.parse(result);
});

test("diagnoser reports propagation only when authoritative matches and a completed public view differs", async () => {
  const result = await diagnoseVerification(
    { name: "www.example.com", target: "edge.target.net" },
    fakeDeps(
      { "CNAME www.example.com": ["edge.target.net"] },
      { "CNAME www.example.com": ["old.target.net"] },
    ),
  );
  assert.equal(result.reason, "propagation");
  assert.equal(result.fixUrl, "/guides/dns-propagation-times");
});

test("diagnoser proves a wrong host by finding the target at the auto-appended name", async () => {
  const result = await diagnoseVerification(
    { name: "www.example.com", target: "edge.target.net" },
    fakeDeps({ "CNAME www.example.com.example.com": ["edge.target.net"] }),
  );
  assert.equal(result.reason, "wrong_host");
  assert.equal(result.wrongHost, "www.example.com.example.com");
});

test("diagnoser trailing-dot failure uses the verifier's exact TXT token comparison", async () => {
  const result = await diagnoseVerification(
    { name: "_verify.example.com", target: "token123", type: "TXT" },
    fakeDeps({ "TXT _verify.example.com": ["token123."] }),
  );
  assert.equal(result.reason, "trailing_dot");
});

test("diagnoser identifies a CNAME target with the zone appended without rejecting a valid root dot", async () => {
  const result = await diagnoseVerification(
    { name: "www.example.com", target: "edge.target.net" },
    fakeDeps({ "CNAME www.example.com": ["edge.target.net.example.com."] }),
  );
  assert.equal(result.reason, "trailing_dot");
  assert.match(result.message, /has example\.com appended/);
  assert.match(result.message, /may have treated it as relative/);
});

test("diagnoser does not blame unrelated TXT records for a missing verification token", async () => {
  const result = await diagnoseVerification(
    { name: "_verify.example.com", target: "token123", type: "TXT" },
    fakeDeps({ "TXT _verify.example.com": ["some-other-vendor=token"] }),
  );
  assert.equal(result.reason, "absent");
});

test("diagnoser fix links are generated only for providers with existing documentation", async () => {
  for (const guide of listProviderGuides()) {
    assert.equal(
      existsSync(
        new URL(
          `../../../apps/docs/content/docs/guides/dns-providers/${guide.provider}.mdx`,
          import.meta.url,
        ),
      ),
      true,
      guide.provider,
    );
  }
  const deps = fakeDeps();
  deps.resolver = fakeResolver({ "NS example.com": ["ns.unmapped.invalid"] });
  const result = await diagnoseVerification(
    { name: "www.example.com", target: "edge.target.net" },
    deps,
  );
  assert.equal(result.fixUrl, "/docs/guides/dns-providers");
  assert.equal(result.provider.id, "unknown");
});

test("diagnoser recognizes known proxy edges without claiming their hidden origin matches", async () => {
  const result = await diagnoseVerification(
    { name: "www.example.com", target: "edge.target.net" },
    fakeDeps({ "A www.example.com": ["104.16.1.2"] }),
  );
  assert.equal(result.reason, "proxied");
  assert.equal(result.proxyProvider, "cloudflare");
});

test("diagnoser distinguishes an absent apex CNAME from an absent subdomain", async () => {
  const result = await diagnoseVerification(
    { name: "example.com", target: "edge.target.net" },
    fakeDeps(),
  );
  assert.equal(result.reason, "apex");
});

test("diagnoser identifies an absent CNAME at a delegated apex without advising a standard CNAME", async () => {
  const deps = fakeDeps();
  deps.resolver = fakeResolver({ "NS delegated.example.com": ["ns.delegated-provider.net"] });
  const result = await diagnoseVerification(
    { name: "delegated.example.com", target: "edge.target.net" },
    deps,
  );
  assert.equal(result.zone, "delegated.example.com");
  assert.equal(result.lookup.authoritative.outcome, "absent");
  assert.equal(result.reason, "apex");
  assert.match(result.message, /cannot coexist/);
});

test("diagnoser reports a different authoritative target as wrong_target", async () => {
  const result = await diagnoseVerification(
    { name: "www.example.com", target: "edge.target.net" },
    fakeDeps({ "CNAME www.example.com": ["wrong.target.net"] }),
  );
  assert.equal(result.reason, "wrong_target");
});

test("diagnoser reports absent only after a completed authoritative lookup with no matching target", async () => {
  const result = await diagnoseVerification(
    { name: "www.example.com", target: "edge.target.net" },
    fakeDeps(),
  );
  assert.equal(result.reason, "absent");
  assert.equal(result.wrongHost, null);
});

test("diagnoser preserves authoritative and public lookup failures as indeterminate", async () => {
  for (const deps of [
    fakeDeps({ "CNAME www.example.com": error("ESERVFAIL") }),
    fakeDeps(
      { "CNAME www.example.com": ["edge.target.net"] },
      { "CNAME www.example.com": error("ETIMEOUT") },
    ),
  ]) {
    const result = await diagnoseVerification(
      { name: "www.example.com", target: "edge.target.net" },
      deps,
    );
    assert.equal(result.reason, "indeterminate");
  }
});

test("DNS diff reports added, removed, changed and TTL-only records against the expected snapshot", async () => {
  const result = await compareDnsSnapshot(
    [
      { name: "extra.example.com", type: "A", value: "192.0.2.1" },
      { name: "gone.example.com", type: "A", value: "192.0.2.3" },
      { name: "changed.example.com", type: "A", value: "192.0.2.4" },
      { name: "ttl.example.com", type: "A", value: "192.0.2.6", ttl: 3600 },
    ],
    fakeDeps(
      {
        "A extra.example.com": ["192.0.2.1", "192.0.2.2"],
        "A changed.example.com": ["192.0.2.5"],
        "A ttl.example.com": ["192.0.2.6"],
      },
      undefined,
      300,
    ),
  );
  assert.deepEqual(
    result.changes.map((change) => change.kind),
    ["added", "removed", "changed", "ttl_only"],
  );
  assert.equal(result.unchanged, 1);
  assert.equal(result.changes[3]?.actual?.ttl, 300);
  assert.equal(result.changes[3]?.expected?.ttl, 3600);
  zPublicDnsDiffResponse.parse(result);
});

test("DNS diff leaves unsupported TTL unknown and never invents a TTL-only change", async () => {
  const result = await compareDnsSnapshot(
    [{ name: "www.example.com", type: "CNAME", value: "edge.target.net.", ttl: 300 }],
    fakeDeps({ "CNAME www.example.com": ["EDGE.target.net"] }),
  );
  assert.equal(result.ttlUnavailable, 1);
  assert.equal(result.unchanged, 1);
  assert.deepEqual(result.changes, []);
  assert.equal(result.snapshots[0]?.authoritative.records?.[0]?.ttl, null);
});

test("DNS diff does not turn authoritative errors into removals", async () => {
  const result = await compareDnsSnapshot(
    [{ name: "www.example.com", type: "A", value: "192.0.2.1" }],
    fakeDeps({ "A www.example.com": error("ETIMEOUT") }),
  );
  assert.equal(result.complete, false);
  assert.deepEqual(result.changes, []);
});

test("DNS diff deduplicates rows and queries once per name/type while preserving TXT case", async () => {
  const deps = fakeDeps({ "TXT _verify.example.com": ["token"] });
  const expected = { name: "_verify.example.com", type: "TXT" as const, value: "TOKEN" };
  const result = await compareDnsSnapshot([expected, expected], deps);
  assert.equal(result.changes[0]?.kind, "changed");
  assert.equal(result.expected.length, 1);
  assert.equal(deps.asked.filter((query) => query === "TXT _verify.example.com").length, 1);
});

test("DNS diff enforces the 25-record cap before any resolver work and rejects malformed rows", async () => {
  const row = { name: "www.example.com", type: "A" as const, value: "192.0.2.1" };
  const deps = fakeDeps();
  await assert.rejects(
    compareDnsSnapshot(
      Array.from({ length: 26 }, () => row),
      deps,
    ),
    RangeError,
  );
  assert.deepEqual(deps.asked, []);
  assert.equal(
    zPublicDnsDiffInput.safeParse({ expected: Array.from({ length: 26 }, () => row) }).success,
    false,
  );
  assert.equal(
    zPublicDnsDiffInput.safeParse({ expected: [{ ...row, name: "https://example.com" }] }).success,
    false,
  );
});

test("aborted DNS tool compositions do not schedule a lookup", async () => {
  const controller = new AbortController();
  controller.abort();
  const deps = { ...fakeDeps(), signal: controller.signal };
  await assert.rejects(followCnameChain("www.example.com", deps), { name: "AbortError" });
  await assert.rejects(
    compareDnsSnapshot([{ name: "www.example.com", type: "A", value: "192.0.2.1" }], deps),
    { name: "AbortError" },
  );
  assert.deepEqual(deps.asked, []);
});

test("a deadline during the first CNAME query prevents the next chain hop", async () => {
  const controller = new AbortController();
  let queries = 0;
  const deps = fakeDeps({ "CNAME www.example.com": ["next.example.com"] });
  deps.signal = controller.signal;
  deps.authoritativeResolverFor = async () => ({
    kind: "resolver",
    resolver: {
      ...fakeResolver({}),
      resolveCname: async () => {
        queries += 1;
        controller.abort();
        return ["next.example.com"];
      },
    },
  });
  await assert.rejects(followCnameChain("www.example.com", deps), { name: "AbortError" });
  assert.equal(queries, 1);
});

test("DNS lookup reads NS and CAA, which connect sessions now accept too (one type list)", async () => {
  for (const type of ["NS", "CAA"] as const satisfies readonly LookupRecordType[]) {
    const result = await lookupRecordAcrossResolvers(
      "example.com",
      type,
      fakeDeps({ "CAA example.com": ["letsencrypt.org"] }),
    );
    assert.equal(result.authoritative.outcome, "answers");
    assert.equal(result.consistent, true);
    assert.equal(isRecordType(type), true);
    assert.equal(LOOKUP_RECORD_TYPES.includes(type), true);
    if (type === "CAA")
      assert.deepEqual(result.authoritative.answers, ['0 issue "letsencrypt.org"']);
  }
});

test("CAA DNS answers ignore Node transport metadata and serialize only supported CAA tags", async () => {
  const resolver: DnsResolver = {
    ...fakeResolver({}),
    resolveCaa: async () => [
      { type: "CAA", critical: 0, issue: "pki.goog", iodef: "mailto:security@example.com" },
    ],
  };
  const result = await lookupRecordAcrossResolvers("example.com", "CAA", {
    resolver: fakeResolver({}),
    authoritativeResolverFor: async () => ({ kind: "resolver", resolver }),
    publicResolverFor: () => resolver,
  });
  assert.deepEqual(result.authoritative.answers, [
    '0 issue "pki.goog"',
    '0 iodef "mailto:security@example.com"',
  ]);
  assert.equal(result.consistent, true);
});

test("DNS lookup consistency keeps TXT tokens case-sensitive", async () => {
  const result = await lookupRecordAcrossResolvers(
    "_verify.example.com",
    "TXT",
    fakeDeps({ "TXT _verify.example.com": ["TOKEN"] }, { "TXT _verify.example.com": ["token"] }),
  );
  assert.equal(result.consistent, false);
});
