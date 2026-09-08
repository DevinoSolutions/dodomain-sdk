// Offline tests for the DNS lookup / propagation engine. The authoritative
// leg is driven through verify.ts's seams (a canned AuthoritativeResolution),
// the public legs through `publicResolverFor` — no socket anywhere.

import assert from "node:assert/strict";
import { test } from "node:test";

import { lookupRecordAcrossResolvers, PUBLIC_RESOLVERS } from "../src/dns-lookup.ts";
import type { AuthoritativeResolution, DnsResolver } from "../src/verify.ts";

function dnsError(code: string): Error {
  return Object.assign(new Error(code), { code });
}

function fakeResolver(overrides: Partial<DnsResolver>): DnsResolver {
  const notImplemented = (name: string) => async () => {
    throw new Error(`fakeResolver: ${name} not stubbed for this test`);
  };
  return {
    resolveNs: overrides.resolveNs ?? notImplemented("resolveNs"),
    resolve4: overrides.resolve4 ?? notImplemented("resolve4"),
    resolve6: overrides.resolve6 ?? notImplemented("resolve6"),
    resolveCname: overrides.resolveCname ?? notImplemented("resolveCname"),
    resolveMx: overrides.resolveMx ?? notImplemented("resolveMx"),
    resolveTxt: overrides.resolveTxt ?? notImplemented("resolveTxt"),
    resolveCaa: overrides.resolveCaa ?? notImplemented("resolveCaa"),
  };
}

/** Public resolvers keyed by address, each answering CNAME with the given value (or throwing). */
function publicResolvers(byAddress: Record<string, string[] | Error>) {
  const asked: string[] = [];
  return {
    asked,
    publicResolverFor: (address: string): DnsResolver =>
      fakeResolver({
        resolveCname: async () => {
          asked.push(address);
          const value = byAddress[address];
          if (value === undefined) throw dnsError("ENODATA");
          if (value instanceof Error) throw value;
          return value;
        },
      }),
  };
}

const authoritativeAnswering = (answers: string[]): AuthoritativeResolution => ({
  kind: "resolver",
  resolver: fakeResolver({ resolveCname: async () => answers }),
});

test("every view agrees with the authoritative answer → consistent:true, one view per public resolver", async () => {
  const pub = publicResolvers({
    "1.1.1.1": ["edge.integrator.app."],
    "8.8.8.8": ["EDGE.integrator.app"],
    "9.9.9.9": ["edge.integrator.app"],
  });
  const result = await lookupRecordAcrossResolvers("www.customer.com", "CNAME", {
    resolver: fakeResolver({}),
    zone: "customer.com",
    authoritativeResolverFor: async () => authoritativeAnswering(["edge.integrator.app"]),
    publicResolverFor: pub.publicResolverFor,
  });
  assert.equal(result.zone, "customer.com");
  assert.equal(result.authoritative.outcome, "answers");
  assert.deepEqual(result.authoritative.answers, ["edge.integrator.app"]);
  assert.deepEqual(
    result.public.map((v) => [v.resolver, v.address, v.outcome]),
    PUBLIC_RESOLVERS.map((r) => [r.name, r.address, "answers"]),
  );
  // Trailing dot and case are display differences, not disagreement.
  assert.equal(result.consistent, true);
  assert.deepEqual([...pub.asked].sort(), ["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
});

test("a public resolver still serving the OLD value → consistent:false, the stale view named verbatim", async () => {
  const pub = publicResolvers({
    "1.1.1.1": ["edge.integrator.app"],
    "8.8.8.8": ["old-vendor.example.net"],
    "9.9.9.9": ["edge.integrator.app"],
  });
  const result = await lookupRecordAcrossResolvers("www.customer.com", "CNAME", {
    resolver: fakeResolver({}),
    zone: "customer.com",
    authoritativeResolverFor: async () => authoritativeAnswering(["edge.integrator.app"]),
    publicResolverFor: pub.publicResolverFor,
  });
  assert.equal(result.consistent, false);
  const google = result.public.find((v) => v.resolver === "Google");
  assert.deepEqual(google?.answers, ["old-vendor.example.net"]);
});

test("a public resolver whose lookup FAILED is reported as error and neither agrees nor disagrees", async () => {
  const pub = publicResolvers({
    "1.1.1.1": ["edge.integrator.app"],
    "8.8.8.8": dnsError("ETIMEOUT"),
    "9.9.9.9": ["edge.integrator.app"],
  });
  const result = await lookupRecordAcrossResolvers("www.customer.com", "CNAME", {
    resolver: fakeResolver({}),
    zone: "customer.com",
    authoritativeResolverFor: async () => authoritativeAnswering(["edge.integrator.app"]),
    publicResolverFor: pub.publicResolverFor,
  });
  const google = result.public.find((v) => v.resolver === "Google");
  assert.equal(google?.outcome, "error");
  assert.equal(google?.error, "ETIMEOUT");
  // The two views that completed agree, so the verdict is still true — the
  // failed one is visible in its own row, not hidden inside the boolean.
  assert.equal(result.consistent, true);
});

test("an absent authoritative record with public resolvers still caching it → consistent:false (the removal has not propagated)", async () => {
  const pub = publicResolvers({
    "1.1.1.1": ["edge.integrator.app"],
    "8.8.8.8": dnsError("ENODATA"),
    "9.9.9.9": dnsError("ENOTFOUND"),
  });
  const result = await lookupRecordAcrossResolvers("www.customer.com", "CNAME", {
    resolver: fakeResolver({}),
    zone: "customer.com",
    authoritativeResolverFor: async () => ({
      kind: "resolver",
      resolver: fakeResolver({
        resolveCname: async () => {
          throw dnsError("ENODATA");
        },
      }),
    }),
    publicResolverFor: pub.publicResolverFor,
  });
  assert.equal(result.authoritative.outcome, "absent");
  assert.equal(result.consistent, false);
  assert.deepEqual(
    result.public.map((v) => v.outcome),
    ["answers", "absent", "absent"],
  );
});

test("when the zone's nameservers cannot be reached the authoritative view is an error and consistent is null — unknown, not false", async () => {
  const pub = publicResolvers({
    "1.1.1.1": ["edge.integrator.app"],
    "8.8.8.8": ["edge.integrator.app"],
    "9.9.9.9": ["edge.integrator.app"],
  });
  const result = await lookupRecordAcrossResolvers("www.customer.com", "CNAME", {
    resolver: fakeResolver({}),
    zone: "customer.com",
    authoritativeResolverFor: async () => ({ kind: "ns_error", code: "ESERVFAIL" }),
    publicResolverFor: pub.publicResolverFor,
  });
  assert.equal(result.authoritative.outcome, "error");
  assert.equal(result.authoritative.error, "ESERVFAIL");
  assert.equal(result.consistent, null);
});

test("the name is canonicalized (trailing dot, case) before any lookup", async () => {
  const seen: string[] = [];
  const result = await lookupRecordAcrossResolvers("WWW.Customer.com.", "CNAME", {
    resolver: fakeResolver({}),
    zone: "customer.com",
    authoritativeResolverFor: async () => ({
      kind: "resolver",
      resolver: fakeResolver({
        resolveCname: async (host) => {
          seen.push(host);
          return ["edge.integrator.app"];
        },
      }),
    }),
    publicResolverFor: () => fakeResolver({ resolveCname: async () => ["edge.integrator.app"] }),
  });
  assert.equal(result.fqdn, "www.customer.com");
  assert.deepEqual(seen, ["www.customer.com"]);
});
