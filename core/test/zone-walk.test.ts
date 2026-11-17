import assert from "node:assert/strict";
import { NODATA, NOTFOUND } from "node:dns";
import { Resolver } from "node:dns/promises";
import { test } from "node:test";
import { nearestZoneCut } from "../src/zone-walk.ts";

test("an NS answer reached through a CNAME is skipped for the enclosing zone", async () => {
  const queries: string[] = [];
  const result = await nearestZoneCut("WWW.Example.com.", {
    resolveNs: async (host) => {
      queries.push(`NS ${host}`);
      return host === "www.example.com" ? ["ns.target.net"] : ["NS.SOURCE.NET"];
    },
    resolveCname: async (host) => {
      queries.push(`CNAME ${host}`);
      return ["target.net"];
    },
  });
  assert.deepEqual(result, {
    zone: "example.com",
    nameServers: ["ns.source.net"],
    nameServerSource: "recursive",
  });
  assert.deepEqual(queries, ["NS www.example.com", "CNAME www.example.com", "NS example.com"]);
});

for (const code of [NOTFOUND, NODATA]) {
  test(`a positive NS answer with ${code} on CNAME is a real zone cut`, async () => {
    const queries: string[] = [];
    const result = await nearestZoneCut("delegated.example.com", {
      resolveNs: async (host) => {
        queries.push(`NS ${host}`);
        return ["ns.source.net"];
      },
      resolveCname: async (host) => {
        queries.push(`CNAME ${host}`);
        throw Object.assign(new Error(code), { code });
      },
    });
    assert.deepEqual(result, {
      zone: "delegated.example.com",
      nameServers: ["ns.source.net"],
      nameServerSource: "recursive",
    });
    assert.deepEqual(queries, ["NS delegated.example.com", "CNAME delegated.example.com"]);
  });
}

for (const code of ["ETIMEOUT", "ESERVFAIL", "EREFUSED", undefined]) {
  test(`an inconclusive CNAME lookup (${code ?? "uncoded"}) keeps the cut, as before the alias check, and never throws`, async () => {
    const queried: string[] = [];
    const result = await nearestZoneCut("delegated.example.com", {
      resolveNs: async (host) => {
        queried.push(host);
        return ["NS.SOURCE.NET"];
      },
      resolveCname: async () => {
        throw Object.assign(new Error("alias lookup failed"), { code });
      },
    });
    assert.deepEqual(result, {
      zone: "delegated.example.com",
      nameServers: ["ns.source.net"],
      nameServerSource: "recursive",
    });
    assert.deepEqual(queried, ["delegated.example.com"]);
  });
}

test("NS-negative candidates and the registrable apex cost no CNAME query", async () => {
  const queried: string[] = [];
  const result = await nearestZoneCut("missing.empty.example.com", {
    resolveNs: async (host) => {
      queried.push(host);
      if (host === "missing.empty.example.com")
        throw Object.assign(new Error(NODATA), { code: NODATA });
      return host === "example.com" ? ["ns.source.net"] : [];
    },
    resolveCname: async () => {
      assert.fail("no positive subzone NS answer to check");
    },
  });
  assert.deepEqual(result, {
    zone: "example.com",
    nameServers: ["ns.source.net"],
    nameServerSource: "recursive",
  });
  assert.deepEqual(queried, ["missing.empty.example.com", "empty.example.com", "example.com"]);
});

test("an injected NS resolver without CNAME never uses the real DNS resolver", async (t) => {
  // Guard both real query methods, including errors nsOf would otherwise swallow.
  const realNs = t.mock.method(Resolver.prototype, "resolveNs", async () => {
    throw new Error("unexpected real NS query");
  });
  const realCname = t.mock.method(Resolver.prototype, "resolveCname", async () => {
    throw new Error("unexpected real CNAME query");
  });
  const result = await nearestZoneCut("delegated.example.com", {
    resolveNs: async () => ["ns.source.net"],
  });
  assert.deepEqual(result, {
    zone: "delegated.example.com",
    nameServers: ["ns.source.net"],
    nameServerSource: "recursive",
  });
  assert.equal(realNs.mock.callCount(), 0);
  assert.equal(realCname.mock.callCount(), 0);
});

test("the default bounded resolver checks aliases before accepting a positive NS answer", async (t) => {
  // Prototype fakes exercise production dependency selection without opening sockets.
  const ns = t.mock.method(Resolver.prototype, "resolveNs", async (host: string) =>
    host === "www.example.com" ? ["ns.target.net"] : ["ns.source.net"],
  );
  const cname = t.mock.method(Resolver.prototype, "resolveCname", async () => ["target.net"]);
  // The parent-delegation leg is pinned (it would open a UDP socket); the
  // recursive legs stay the real default resolver, which is what this pins.
  assert.deepEqual(
    await nearestZoneCut("www.example.com", { parentNs: async () => ["ns.source.net"] }),
    {
      zone: "example.com",
      nameServers: ["ns.source.net"],
      nameServerSource: "parent",
    },
  );
  assert.equal(ns.mock.callCount(), 2);
  assert.equal(cname.mock.callCount(), 1);
});

test("alias-aware zone discovery preserves the eight-candidate bound and apex floor", async () => {
  const names: string[] = [];
  const aliases: string[] = [];
  const result = await nearestZoneCut("a.b.c.d.e.f.g.h.i.j.example.com", {
    resolveNs: async (host) => {
      names.push(host);
      return ["ns.target.net"];
    },
    resolveCname: async (host) => {
      aliases.push(host);
      return ["target.net"];
    },
  });
  assert.equal(result.zone, "example.com");
  assert.equal(names.length, 8);
  assert.equal(aliases.length, 7);
  assert.equal(names.at(-1), "example.com");
});
