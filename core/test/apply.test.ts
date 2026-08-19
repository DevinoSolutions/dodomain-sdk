// Offline unit tests for the DI apply orchestrator (F-002 — the Critical fix).
// No network — every Cloudflare call is injected via ApplySessionRecordsDeps,
// mirroring the DI convention in detect.test.ts / cloudflare.test.ts. This is
// the machine-checkable proof that a session containing MX/AAAA can no longer
// false-finalize as "connected".

import { test } from "node:test";
import assert from "node:assert/strict";

import { applySessionRecords, type ApplySessionRecordsDeps } from "../src/cloudflare/apply.ts";
import type { SessionRecord } from "../src/records.ts";

const CTX = { token: "tok-1", zoneId: "zone-1", domain: "customer.com" };

interface CreateCall {
  type: string;
  name: string;
  content: string;
  priority?: number;
}

// `zone`/`live`/`mismatched` are keyed by "type:fqdn" so each fake can vary per
// record. `zone` maps a key to the record CONTENTS already on Cloudflare — the
// listRecords fake returns them, so the orchestrator's value-aware create gate
// is exercised for real (the pre-fix `findRecordId` fake only modeled presence).
// `live` = read-back value-matches (finalize-worthy). `mismatched` = PRESENT but
// the read-back value differs (present:true, match:false) — the D-001 case a
// presence-only gate wrongly finalized. Neither set ⇒ absent (present:false,
// match:false). `createCalls`/`listCalls`, when passed, record every invocation
// for assertion.
function fakeDeps(opts: {
  zone?: Map<string, Array<{ content: string; priority?: number }>>;
  live?: Set<string>;
  mismatched?: Set<string>;
  createCalls?: CreateCall[];
  listCalls?: string[];
}): ApplySessionRecordsDeps {
  const zone = opts.zone ?? new Map<string, Array<{ content: string; priority?: number }>>();
  const live = opts.live ?? new Set<string>();
  const mismatched = opts.mismatched ?? new Set<string>();
  return {
    listRecords: async (_token, _zoneId, type, name) => {
      opts.listCalls?.push(`${type}:${name}`);
      return (zone.get(`${type}:${name}`) ?? []).map((r, i) => ({
        id: `rec-existing-${i}`,
        content: r.content,
        priority: r.priority,
      }));
    },
    createRecord: async (_token, _zoneId, rec) => {
      opts.createCalls?.push({
        type: rec.type,
        name: rec.name,
        content: rec.content,
        priority: rec.priority,
      });
      return { id: "rec-new", type: rec.type, name: rec.name, content: rec.content };
    },
    verifyRecordViaApi: async (_token, _zoneId, type, name, expect) => {
      const key = `${type}:${name}`;
      const isLive = live.has(key);
      const isMismatch = mismatched.has(key);
      return {
        present: isLive || isMismatch,
        match: isLive,
        // live reads back the expected value; a mismatch reads back a DIFFERENT
        // value (so `.actual` is populated for the CONFLICT notice); absent → null.
        value: isLive ? expect : isMismatch ? `wrong-${expect}` : null,
        proxied: false,
      };
    },
  };
}

test("writes and verifies every requested record — no WRITABLE subset filter", async () => {
  const records: SessionRecord[] = [
    { type: "A", host: "@", value: "203.0.113.10" },
    { type: "MX", host: "@", value: "mx1.example.com", priority: 10 },
    { type: "AAAA", host: "@", value: "2001:db8::1" },
  ];
  const createCalls: CreateCall[] = [];
  const deps = fakeDeps({ live: new Set(["A:customer.com"]), createCalls });

  await applySessionRecords(records, CTX, deps);

  assert.equal(createCalls.length, 3, "createRecord called for all three requested types");
  assert.deepEqual(
    createCalls.map((c) => c.type),
    ["A", "MX", "AAAA"],
  );
});

test("regression: A live + MX/AAAA absent ⇒ allLive is false (no false-finalize)", async () => {
  const records: SessionRecord[] = [
    { type: "A", host: "@", value: "203.0.113.10" },
    { type: "MX", host: "@", value: "mx1.example.com", priority: 10 },
    { type: "AAAA", host: "@", value: "2001:db8::1" },
  ];
  const deps = fakeDeps({ live: new Set(["A:customer.com"]) }); // only A is live

  const out = await applySessionRecords(records, CTX, deps);

  assert.equal(out.allLive, false);
  assert.equal(out.results.find((r) => r.type === "A")?.present, true);
  assert.equal(out.results.find((r) => r.type === "MX")?.present, false);
  assert.equal(out.results.find((r) => r.type === "AAAA")?.present, false);
});

test("all requested records live ⇒ allLive is true", async () => {
  const records: SessionRecord[] = [
    { type: "CNAME", host: "www", value: "target.example.com" },
    { type: "TXT", host: "@", value: "v=spf1 include:_spf.example.com ~all" },
  ];
  const deps = fakeDeps({ live: new Set(["CNAME:www.customer.com", "TXT:customer.com"]) });

  const out = await applySessionRecords(records, CTX, deps);

  assert.equal(out.allLive, true);
  assert.ok(out.results.every((r) => r.present));
});

test("MX createRecord call carries priority (hop-3 wiring end-to-end)", async () => {
  const records: SessionRecord[] = [
    { type: "MX", host: "mail", value: "mx1.example.com", priority: 20 },
  ];
  const createCalls: CreateCall[] = [];
  const deps = fakeDeps({ createCalls });

  await applySessionRecords(records, CTX, deps);

  assert.equal(createCalls.length, 1);
  assert.equal(createCalls[0]!.priority, 20);
});

test("a non-MX record's createRecord call carries no priority", async () => {
  const records: SessionRecord[] = [{ type: "A", host: "@", value: "203.0.113.10" }];
  const createCalls: CreateCall[] = [];
  const deps = fakeDeps({ createCalls });

  await applySessionRecords(records, CTX, deps);

  assert.equal(createCalls[0]!.priority, undefined);
});

test("idempotency: an existing record with OUR value skips createRecord (preserves current behavior)", async () => {
  const records: SessionRecord[] = [{ type: "A", host: "@", value: "203.0.113.10" }];
  const createCalls: CreateCall[] = [];
  const deps = fakeDeps({
    zone: new Map([["A:customer.com", [{ content: "203.0.113.10" }]]]),
    live: new Set(["A:customer.com"]),
    createCalls,
  });

  const out = await applySessionRecords(records, CTX, deps);

  assert.equal(createCalls.length, 0, "createRecord NOT called — a matching record already exists");
  assert.equal(out.allLive, true);
});

test("defense-in-depth: an unsupported type is marked loudly not-live, never silently dropped", async () => {
  const records: SessionRecord[] = [
    { type: "NS" as unknown as SessionRecord["type"], host: "@", value: "ns1.example.com" },
  ];
  const createCalls: CreateCall[] = [];
  const deps = fakeDeps({ createCalls });

  const out = await applySessionRecords(records, CTX, deps);

  assert.equal(out.allLive, false);
  assert.equal(out.results.length, 1, "the record is present in results, not filtered out");
  assert.equal(out.results[0]!.writable, false);
  assert.equal(out.results[0]!.present, false);
  assert.equal(createCalls.length, 0, "never attempted to write an unwritable type");
});

test("zero requested records ⇒ allLive is false (no vacuous-truth finalize)", async () => {
  const out = await applySessionRecords([], CTX, fakeDeps({}));
  assert.equal(out.allLive, false);
  assert.deepEqual(out.results, []);
});

// ─────────────────────────────────────────────────────────────────────────
// D-001: tier-1 apply finalized on record PRESENCE, ignoring VALUE — so a
// pre-existing record with the WRONG value read as "connected". The gate is
// now `.match` (value-verified), not `.present`. These fail against the old
// `every((r) => r.present)` gate (a mismatched record is present:true).
// ─────────────────────────────────────────────────────────────────────────

test("D-001 regression: a present-but-WRONG-value record ⇒ allLive is false (gate is value-match, not presence)", async () => {
  const records: SessionRecord[] = [{ type: "CNAME", host: "www", value: "target.example.com" }];
  // Present on Cloudflare, but the live value is NOT what we asked for.
  const deps = fakeDeps({ mismatched: new Set(["CNAME:www.customer.com"]) });

  const out = await applySessionRecords(records, CTX, deps);

  assert.equal(out.allLive, false);
  const row = out.results.find((r) => r.type === "CNAME");
  assert.equal(
    row?.present,
    true,
    "present:true — the record exists (telemetry: wrong-value, not absent)",
  );
  assert.equal(
    row?.match,
    false,
    "match:false — its value disagrees; this is what blocks finalize",
  );
  assert.equal(row?.actual, "wrong-target.example.com", "the disagreeing live value is surfaced");
});

test("D-001 regression: a pre-existing MISMATCHED record is NOT overwritten and does NOT finalize (non-destructive)", async () => {
  const records: SessionRecord[] = [{ type: "A", host: "@", value: "203.0.113.10" }];
  const createCalls: CreateCall[] = [];
  const deps = fakeDeps({
    zone: new Map([["A:customer.com", [{ content: "198.51.100.99" }]]]), // exists with the WRONG value
    mismatched: new Set(["A:customer.com"]), // read-back disagrees too
    createCalls,
  });

  const out = await applySessionRecords(records, CTX, deps);

  assert.equal(
    createCalls.length,
    0,
    "non-destructive: the conflicting record is never overwritten",
  );
  assert.equal(out.allLive, false, "a wrong-valued pre-existing record blocks finalize");
  assert.equal(out.results[0]!.present, true);
  assert.equal(out.results[0]!.match, false);
});

// ─────────────────────────────────────────────────────────────────────────
// TXT coexistence: a TXT name is a bag of independent tokens (SPF, site
// verifications, ownership proofs). The pre-fix gate — "ANY record at
// type+name exists ⇒ skip create" — made an apex verification token
// permanently unwritable on any real apex (they all carry SPF), and the
// `result[0]` read-back could fail even a correctly-written token. These
// fail against the pre-fix findRecordId-presence gate.
// ─────────────────────────────────────────────────────────────────────────

test("TXT coexistence: pre-existing unrelated apex TXT records do NOT suppress creating our token", async () => {
  const records: SessionRecord[] = [
    { type: "TXT", host: "@", value: "dodomain-verify=tok-abc123" },
  ];
  const createCalls: CreateCall[] = [];
  const deps = fakeDeps({
    zone: new Map([
      [
        "TXT:customer.com",
        [
          { content: "v=spf1 include:_spf.example.com ~all" },
          { content: "google-site-verification=xyz" },
        ],
      ],
    ]),
    live: new Set(["TXT:customer.com"]), // read-back: ours is live among the others
    createCalls,
  });

  const out = await applySessionRecords(records, CTX, deps);

  assert.equal(createCalls.length, 1, "our TXT IS created beside the pre-existing ones");
  assert.equal(createCalls[0]!.content, "dodomain-verify=tok-abc123");
  assert.equal(out.allLive, true);
});

test("TXT coexistence: our token already present AMONG unrelated TXT records ⇒ no duplicate create", async () => {
  const records: SessionRecord[] = [
    { type: "TXT", host: "@", value: "dodomain-verify=tok-abc123" },
  ];
  const createCalls: CreateCall[] = [];
  const deps = fakeDeps({
    zone: new Map([
      [
        "TXT:customer.com",
        [
          { content: "v=spf1 include:_spf.example.com ~all" },
          { content: "dodomain-verify=tok-abc123" },
        ],
      ],
    ]),
    live: new Set(["TXT:customer.com"]),
    createCalls,
  });

  const out = await applySessionRecords(records, CTX, deps);

  assert.equal(createCalls.length, 0, "value-aware idempotency: ours already exists");
  assert.equal(out.allLive, true);
});

test("CNAME stays a singleton: a pre-existing different-valued CNAME is NOT added beside (conflict, not coexistence)", async () => {
  const records: SessionRecord[] = [{ type: "CNAME", host: "www", value: "target.example.com" }];
  const createCalls: CreateCall[] = [];
  const deps = fakeDeps({
    zone: new Map([["CNAME:www.customer.com", [{ content: "other.example.net" }]]]),
    mismatched: new Set(["CNAME:www.customer.com"]),
    createCalls,
  });

  const out = await applySessionRecords(records, CTX, deps);

  assert.equal(createCalls.length, 0, "no second CNAME is ever created at a name");
  assert.equal(out.allLive, false);
});

test("D-001: every record present with the CORRECT value ⇒ allLive is true", async () => {
  const records: SessionRecord[] = [
    { type: "A", host: "@", value: "203.0.113.10" },
    { type: "CNAME", host: "www", value: "target.example.com" },
  ];
  const deps = fakeDeps({ live: new Set(["A:customer.com", "CNAME:www.customer.com"]) });

  const out = await applySessionRecords(records, CTX, deps);

  assert.equal(out.allLive, true);
  assert.ok(
    out.results.every((r) => r.match && r.present),
    "all records match AND are present",
  );
});
