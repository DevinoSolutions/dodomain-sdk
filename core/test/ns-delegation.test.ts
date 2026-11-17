// Parent-delegation NS lookup (ns-delegation.ts, T-10301). Every case runs on
// injected seams: the parent's NS/A lookups and the UDP exchange are fakes that
// answer with hand-built DNS messages, so no socket is opened.

import { test } from "node:test";
import assert from "node:assert/strict";
import { NODATA, NOTFOUND } from "node:dns";

import {
  encodeNsQuery,
  parentDelegatedNs,
  parseDnsMessage,
  type DelegationDeps,
} from "../src/ns-delegation.ts";

// ——— a tiny DNS message builder for fixtures (RFC 1035 wire format) ———

function name(n: string): number[] {
  const out: number[] = [];
  for (const label of n.split("."))
    out.push(label.length, ...Array.from(label, (c) => c.charCodeAt(0)));
  out.push(0);
  return out;
}

const u16 = (v: number): number[] => [v >> 8, v & 0xff];

interface FixtureRR {
  owner: number[];
  type: number;
  rdata: number[];
}

function nsRR(owner: number[], target: number[]): FixtureRR {
  return { owner, type: 2, rdata: target };
}

function message(opts: {
  id: number;
  rcode?: number;
  truncated?: boolean;
  question: string;
  answers?: FixtureRR[];
  authority?: FixtureRR[];
}): Uint8Array {
  const flags = 0x8000 | (opts.truncated ? 0x0200 : 0) | (opts.rcode ?? 0);
  const answers = opts.answers ?? [];
  const authority = opts.authority ?? [];
  const rr = (r: FixtureRR): number[] => [
    ...r.owner,
    ...u16(r.type),
    ...u16(1),
    0,
    0,
    0x0e,
    0x10,
    ...u16(r.rdata.length),
    ...r.rdata,
  ];
  return Uint8Array.from([
    ...u16(opts.id),
    ...u16(flags),
    ...u16(1),
    ...u16(answers.length),
    ...u16(authority.length),
    ...u16(0),
    ...name(opts.question),
    ...u16(2),
    ...u16(1),
    ...answers.flatMap(rr),
    ...authority.flatMap(rr),
  ]);
}

// The question name always starts at offset 12, so 0xc00c points back at it —
// the compression real TLD servers use for the authority owner name.
const QNAME_POINTER = [0xc0, 0x0c];

/** Deps where the parent ("xyz") has two servers and `exchange` is scripted per call. */
function parentDeps(
  replies: Array<(server: string, query: Uint8Array) => Uint8Array | Promise<Uint8Array>>,
  log: string[] = [],
): DelegationDeps {
  let call = 0;
  return {
    resolveNs: async (host) => {
      log.push(`NS ${host}`);
      if (host === "xyz") return ["x.nic.xyz", "y.nic.xyz"];
      throw Object.assign(new Error(NODATA), { code: NODATA });
    },
    resolve4: async (host) => [host === "x.nic.xyz" ? "192.0.2.1" : "192.0.2.2"],
    exchange: async (server, query) => {
      log.push(`Q ${server}`);
      const reply = replies[call++];
      if (!reply) throw new Error("unexpected extra exchange");
      return reply(server, query);
    },
    nextId: () => 0x1234,
  };
}

test("the NS query asks with recursion off, for type NS, and advertises EDNS0", () => {
  const q = encodeNsQuery("DoDomainDemo.xyz.", 0xabcd);
  assert.equal((q[0]! << 8) | q[1]!, 0xabcd);
  assert.equal(q[2]! & 0x01, 0, "RD bit must be clear: the parent must answer from its own data");
  const parsed = parseDnsMessage(
    Uint8Array.from([...q.subarray(0, 2), 0x80, 0x00, ...q.subarray(4)]),
  );
  assert.equal(parsed.questionName, "dodomaindemo.xyz");
  // QTYPE NS + QCLASS IN right after the 18-byte encoded name, then the OPT RR (type 41).
  const afterName = 12 + "dodomaindemo.xyz".length + 2;
  assert.deepEqual([...q.subarray(afterName, afterName + 4)], [0, 2, 0, 1]);
  assert.deepEqual([...q.subarray(afterName + 5, afterName + 7)], [0, 41]);
});

test("a referral's AUTHORITY section is read as the zone's current delegation, compressed names included", async () => {
  const log: string[] = [];
  const ns = await parentDelegatedNs(
    "dodomaindemo.xyz",
    parentDeps(
      [
        () =>
          message({
            id: 0x1234,
            question: "dodomaindemo.xyz",
            authority: [
              nsRR(QNAME_POINTER, name("curitiba.ns.porkbun.com")),
              nsRR(QNAME_POINTER, name("fortaleza.ns.porkbun.com")),
            ],
          }),
      ],
      log,
    ),
  );
  assert.deepEqual(ns, ["curitiba.ns.porkbun.com", "fortaleza.ns.porkbun.com"]);
  assert.deepEqual(log, ["NS xyz", "Q 192.0.2.1"]);
});

test("a parent that also hosts the child answers in ANSWER, and that counts as the delegation too", async () => {
  const ns = await parentDelegatedNs("dc.mrneon.online", {
    ...parentDeps([
      () =>
        message({
          id: 0x1234,
          question: "dc.mrneon.online",
          answers: [nsRR(QNAME_POINTER, name("ns1.as207960.net"))],
        }),
    ]),
    resolveNs: async (host) => {
      if (host === "mrneon.online") return ["doug.ns.cloudflare.com"];
      throw Object.assign(new Error(NODATA), { code: NODATA });
    },
  });
  assert.deepEqual(ns, ["ns1.as207960.net"]);
});

test("the parent zone is the nearest ancestor that owns NS, climbing past names that are not zone cuts", async () => {
  const log: string[] = [];
  await parentDelegatedNs(
    "a.b.dodomaindemo.xyz",
    parentDeps(
      [
        () =>
          message({
            id: 0x1234,
            question: "a.b.dodomaindemo.xyz",
            authority: [nsRR(QNAME_POINTER, name("ns1.example.net"))],
          }),
      ],
      log,
    ),
  );
  assert.deepEqual(log.slice(0, 3), ["NS b.dodomaindemo.xyz", "NS dodomaindemo.xyz", "NS xyz"]);
});

test("a parent NXDOMAIN is an answer: it throws ENOTFOUND without trying another server", async () => {
  const log: string[] = [];
  await assert.rejects(
    parentDelegatedNs(
      "nothere.xyz",
      parentDeps([() => message({ id: 0x1234, rcode: 3, question: "nothere.xyz" })], log),
    ),
    (e: NodeJS.ErrnoException) => e.code === NOTFOUND,
  );
  assert.equal(log.filter((l) => l.startsWith("Q ")).length, 1);
});

test("a parent that answers without any NS for the zone throws ENODATA, never an empty success", async () => {
  await assert.rejects(
    parentDelegatedNs(
      "dodomaindemo.xyz",
      parentDeps([
        () =>
          message({
            id: 0x1234,
            question: "dodomaindemo.xyz",
            // The parent's OWN NS in authority is not a delegation of the child.
            authority: [nsRR(name("xyz"), name("x.nic.xyz"))],
          }),
      ]),
    ),
    (e: NodeJS.ErrnoException) => e.code === NODATA,
  );
});

test("a timed-out parent server costs one try and the next parent server is asked", async () => {
  const log: string[] = [];
  const ns = await parentDelegatedNs(
    "dodomaindemo.xyz",
    parentDeps(
      [
        () => {
          throw Object.assign(new Error("timed out"), { code: "ETIMEOUT" });
        },
        () =>
          message({
            id: 0x1234,
            question: "dodomaindemo.xyz",
            authority: [nsRR(QNAME_POINTER, name("curitiba.ns.porkbun.com"))],
          }),
      ],
      log,
    ),
  );
  assert.deepEqual(ns, ["curitiba.ns.porkbun.com"]);
  assert.deepEqual(
    log.filter((l) => l.startsWith("Q ")),
    ["Q 192.0.2.1", "Q 192.0.2.2"],
  );
});

test("a reply carrying a different query ID is rejected, and exhausting the tries throws the last error", async () => {
  await assert.rejects(
    parentDelegatedNs(
      "dodomaindemo.xyz",
      parentDeps([
        () =>
          message({
            id: 0x9999,
            question: "dodomaindemo.xyz",
            authority: [nsRR(QNAME_POINTER, name("evil.example"))],
          }),
        () => {
          throw Object.assign(new Error("timed out"), { code: "ETIMEOUT" });
        },
      ]),
    ),
    (e: NodeJS.ErrnoException) => e.code === "ETIMEOUT",
  );
});

test("a malformed reply is an EFORMERR, not a crash and not a delegation", async () => {
  await assert.rejects(
    parentDelegatedNs("dodomaindemo.xyz", {
      ...parentDeps([() => Uint8Array.from([0x12, 0x34, 0x80]), () => Uint8Array.from([0x12])]),
    }),
    (e: NodeJS.ErrnoException) => e.code === "EFORMERR",
  );
});

test("a parent whose nameservers resolve to no address fails loudly with EPARENTUNRESOLVABLE", async () => {
  await assert.rejects(
    parentDelegatedNs("dodomaindemo.xyz", {
      ...parentDeps([]),
      resolve4: async () => {
        throw Object.assign(new Error("no A"), { code: "ETIMEOUT" });
      },
    }),
    (e: NodeJS.ErrnoException) => e.code === "EPARENTUNRESOLVABLE",
  );
});
