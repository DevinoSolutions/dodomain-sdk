import { test } from "node:test";
import assert from "node:assert/strict";

import { guideFor } from "../src/guides.ts";
import { zRecord, zRecords } from "../src/records.ts";
import {
  WEBHOOK_EVENT_PAYLOAD_SCHEMAS,
  WEBHOOK_EVENT_TYPES,
  zCheckDomainInput,
  zCheckDomainResponse,
  zConnectionDisconnectedPayload,
  zConnectionSummary,
  zConnectionFailedPayload,
  zConnectionVerifiedPayload,
  zCreateSessionInput,
  zCreateSessionResponse,
  zDetectSessionResponse,
  zDisconnectConnectionResponse,
  zIntegratorSession,
  zListConnectionsQuery,
  zListConnectionsResponse,
  zProviderGuide,
  zPublicSession,
  zReverifyConnectionResponse,
  zSessionAbandonedPayload,
  zSessionCompletedPayload,
  zWebhookEvent,
  zWebhookEventType,
  zWebhookEventWire,
} from "../src/schemas.ts";
import { MESSAGE_TYPES, zDoDomainMessage } from "../src/messages.ts";
import { signWebhook, verifyWebhook } from "../src/webhook.ts";

// ── zRecord / zRecords (F-008: the record SHAPE — capability is F-002's,
// not re-encoded here) ──────────────────────────────────────────────────────

test("zRecord accepts every RECORD_TYPES member with optional priority/ttl", () => {
  for (const type of ["A", "AAAA", "CNAME", "TXT", "MX"] as const) {
    const r = zRecord.parse({ type, host: "@", value: "x" });
    assert.equal(r.type, type);
  }
  const withExtras = zRecord.parse({
    type: "MX",
    host: "@",
    value: "mx1.example.com",
    priority: 10,
    ttl: 300,
  });
  assert.equal(withExtras.priority, 10);
  assert.equal(withExtras.ttl, 300);
});

test("zRecord rejects an unknown type and a missing host", () => {
  assert.equal(zRecord.safeParse({ type: "NS", host: "@", value: "x" }).success, false);
  assert.equal(zRecord.safeParse({ type: "TXT", value: "x" }).success, false);
  assert.equal(zRecord.safeParse({ type: "TXT", host: "", value: "x" }).success, false);
});

test("zRecords is an array of zRecord", () => {
  const out = zRecords.parse([{ type: "TXT", host: "@", value: "v=spf1" }]);
  assert.equal(out.length, 1);
  assert.equal(zRecords.safeParse("not-an-array").success, false);
});

// ── zCreateSessionInput (replaces web's local BodySchema + node's
// hand-typed CreateSessionInput) ────────────────────────────────────────────

const RECORDS = [{ type: "TXT", host: "@", value: "v" }];

test("zCreateSessionInput accepts a domain + records body, with or without the wire-compat recipe", () => {
  assert.equal(
    zCreateSessionInput.safeParse({ domain: "x.example.com", records: RECORDS }).success,
    true,
  );
  assert.equal(
    zCreateSessionInput.safeParse({ domain: "x.example.com", records: RECORDS, recipe: "sendly" })
      .success,
    true,
  );
});

// A recipe id is consumed by NOTHING (the tier-2 start route compiles a recipe
// from the session's records instead), so a recipe-only body used to mint a
// 201 + connectUrl that dead-ends for the end user. Records are the payload.
test("zCreateSessionInput rejects a recipe-only body — a recipe no longer substitutes for records", () => {
  assert.equal(
    zCreateSessionInput.safeParse({ domain: "x.example.com", recipe: "sendly" }).success,
    false,
  );
});

test("zCreateSessionInput rejects a body with no records at all", () => {
  assert.equal(zCreateSessionInput.safeParse({ domain: "x.example.com" }).success, false);
});

// The domain used to be optional and was repaired to "" by the route, which
// rendered an empty <h1> on the hosted page and failed detect later.
test("zCreateSessionInput requires a domain and rejects a malformed one instead of repairing it", () => {
  assert.equal(zCreateSessionInput.safeParse({ records: RECORDS }).success, false);
  for (const domain of [
    "",
    "  ",
    "localhost",
    "https://app.customer.com",
    "app.customer.com:8080",
    "app.customer.com.",
    "-lead.example.com",
    "trail-.example.com",
    `${"a".repeat(64)}.example.com`,
  ]) {
    assert.equal(
      zCreateSessionInput.safeParse({ domain, records: RECORDS }).success,
      false,
      `domain ${JSON.stringify(domain)} must be rejected`,
    );
  }
});

test("zCreateSessionInput accepts ordinary domain spellings (apex, deep subdomain, multi-label suffix, hyphens, mixed case)", () => {
  for (const domain of [
    "example.com",
    "app.customer.com",
    "a.b.c.customer.co.uk",
    "my-app.customer.com",
    "App.Customer.COM",
  ]) {
    assert.equal(
      zCreateSessionInput.safeParse({ domain, records: RECORDS }).success,
      true,
      `domain ${JSON.stringify(domain)} must be accepted`,
    );
  }
});

test("zCreateSessionInput accepts an http(s) returnUrl and rejects a malformed one", () => {
  assert.equal(
    zCreateSessionInput.safeParse({
      domain: "x.example.com",
      records: RECORDS,
      returnUrl: "https://example.com/done",
    }).success,
    true,
  );
  assert.equal(
    zCreateSessionInput.safeParse({
      domain: "x.example.com",
      records: RECORDS,
      returnUrl: "not-a-url",
    }).success,
    false,
  );
});

// returnUrl is rendered as an <a href> on the hosted connect page and echoed
// by the public session GET. A bare z.url() accepts these (zod 4.4.3), leaving
// only React's internal blocklist between an integrator-supplied string and an
// execution vector on our own origin.
test("zCreateSessionInput rejects a returnUrl with a non-http(s) scheme (javascript:/data:/vbscript:/file:)", () => {
  for (const returnUrl of [
    "javascript:alert(1)",
    "JavaScript:alert(1)",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "vbscript:msgbox(1)",
    "file:///etc/passwd",
  ]) {
    assert.equal(
      zCreateSessionInput.safeParse({ domain: "x.example.com", records: RECORDS, returnUrl })
        .success,
      false,
      `returnUrl ${JSON.stringify(returnUrl)} must be rejected`,
    );
  }
});

test("zCreateSessionInput rejects a returnUrl carrying embedded credentials or exceeding 2048 characters", () => {
  assert.equal(
    zCreateSessionInput.safeParse({
      domain: "x.example.com",
      records: RECORDS,
      returnUrl: "https://user:pw@example.com/done",
    }).success,
    false,
  );
  assert.equal(
    zCreateSessionInput.safeParse({
      domain: "x.example.com",
      records: RECORDS,
      returnUrl: `https://example.com/${"a".repeat(2100)}`,
    }).success,
    false,
  );
});

// ── zCreateSessionResponse / zPublicSession ─────────────────────────────────

test("zCreateSessionResponse accepts the exact POST /sessions server payload", () => {
  const payload = {
    id: "cuid123",
    token: "dd_sess_abc",
    expiresAt: new Date().toISOString(),
    connectUrl: "https://connect.dodomain.io/connect/dd_sess_abc",
    records: [{ type: "CNAME", host: "app", fqdn: "app.acme.com" }],
  };
  assert.deepEqual(zCreateSessionResponse.parse(payload), payload);
});

test("zCreateSessionResponse rejects a response missing a required field", () => {
  assert.equal(zCreateSessionResponse.safeParse({ id: "x", token: "dd_sess_abc" }).success, false);
});

// F3 (BioFlow live E2E 2026-08-12): the composed fqdns are part of the create
// CONTRACT, not a nicety — an integrator could previously only learn what would
// be monitored by failing verification later.
test("zCreateSessionResponse requires the composed records: what will be monitored is answered at create time", () => {
  const withoutRecords = {
    id: "cuid123",
    token: "dd_sess_abc",
    expiresAt: new Date().toISOString(),
    connectUrl: "https://connect.dodomain.io/connect/dd_sess_abc",
  };
  assert.equal(zCreateSessionResponse.safeParse(withoutRecords).success, false);
});

test("zCreateSessionResponse carries optional warnings, and a warning names the code, the host and the composed fqdn", () => {
  const payload = {
    id: "cuid123",
    token: "dd_sess_abc",
    expiresAt: new Date().toISOString(),
    connectUrl: "https://connect.dodomain.io/connect/dd_sess_abc",
    records: [{ type: "CNAME", host: "links", fqdn: "links.links.acme.com" }],
    warnings: [
      {
        code: "duplicate_host_label",
        message: 'host "links" repeats the leading label of domain "links.acme.com"',
        host: "links",
        fqdn: "links.links.acme.com",
      },
    ],
  };
  const parsed = zCreateSessionResponse.safeParse(payload);
  assert.ok(parsed.success);
  assert.equal(parsed.data.warnings?.[0]?.code, "duplicate_host_label");
  // Absent warnings is the normal case — a clean session must still parse.
  assert.equal(zCreateSessionResponse.safeParse({ ...payload, warnings: undefined }).success, true);
  // An invented warning code is rejected, so `code` stays a branchable vocabulary.
  assert.equal(
    zCreateSessionResponse.safeParse({
      ...payload,
      warnings: [{ ...payload.warnings[0], code: "made_up" }],
    }).success,
    false,
  );
});

test("zPublicSession accepts the exact GET /sessions/:token server payload, nulls included", () => {
  const payload = {
    id: "cuid123",
    domain: "example.com",
    records: [{ type: "TXT", host: "@", value: "v=spf1" }],
    recipe: null,
    status: "pending",
    tier: null,
    detectedProvider: null,
    returnUrl: null,
    expiresAt: new Date().toISOString(),
  };
  assert.deepEqual(zPublicSession.parse(payload), payload);
});

// ── Webhook event envelope (id = WebhookDelivery.id, per U2 §10.3) ──────────

test("zWebhookEventType only accepts the declared vocabulary", () => {
  assert.equal(zWebhookEventType.safeParse("connection.verified").success, true);
  assert.equal(zWebhookEventType.safeParse("connection.bogus").success, false);
});

test("WEBHOOK_EVENT_TYPES is the four PLAN-committed integrator events plus connection.disconnected (F3)", () => {
  assert.deepEqual([...WEBHOOK_EVENT_TYPES].sort(), [
    "connection.disconnected",
    "connection.failed",
    "connection.verified",
    "session.abandoned",
    "session.completed",
  ]);
  // The operational DLQ Event type is deliberately NOT an integrator webhook type.
  assert.equal(zWebhookEventType.safeParse("webhook.delivery_failed").success, false);
});

test("WEBHOOK_EVENT_PAYLOAD_SCHEMAS is total over the event vocabulary", () => {
  for (const type of WEBHOOK_EVENT_TYPES) {
    assert.ok(WEBHOOK_EVENT_PAYLOAD_SCHEMAS[type], `missing payload schema for "${type}"`);
  }
});

// ── Per-event payload schemas (validated in-tx by lib/webhook-events.ts) ─────

test("zConnectionVerifiedPayload requires domain+sessionId+connectionId; recovered is optional", () => {
  assert.equal(
    zConnectionVerifiedPayload.safeParse({
      domain: "acme.com",
      sessionId: "s1",
      connectionId: "c1",
    }).success,
    true,
  );
  assert.equal(
    zConnectionVerifiedPayload.safeParse({
      domain: "acme.com",
      sessionId: "s1",
      connectionId: "c1",
      recovered: true,
    }).success,
    true,
  );
  assert.equal(zConnectionVerifiedPayload.safeParse({ domain: "acme.com" }).success, false);
});

// F2 (BioFlow live E2E 2026-08-12): every event that ANNOUNCES a connection
// must name it with the id the connections API is keyed by
// (DELETE/reverify /api/v1/connections/:connectionId), so acting on the
// resource an event describes never needs a lookup by domain first.
test("every connection-scoped payload carries connectionId, the id the connections API is keyed by", () => {
  const withoutId = { domain: "acme.com", sessionId: "s1" };
  assert.equal(zConnectionVerifiedPayload.safeParse(withoutId).success, false);
  assert.equal(zSessionCompletedPayload.safeParse(withoutId).success, false);
  assert.equal(
    zConnectionDisconnectedPayload.safeParse({
      ...withoutId,
      fqdn: "www.acme.com",
      disconnectedAt: new Date().toISOString(),
    }).success,
    false,
  );
  assert.equal(
    zConnectionFailedPayload.safeParse({
      ...withoutId,
      fqdn: "www.acme.com",
      reason: "dns_drift",
      scope: "connection",
      records: [],
    }).success,
    false,
  );
});

// The one connection.* arm that legitimately has NO connection id: a connect
// ATTEMPT that failed mid-flow never created a DomainConnection row. Inventing
// an id there, or making the field required and emitting a placeholder, would
// be worse than its absence — so the arm stays without it, on purpose.
test("the session_failed arm carries no connectionId, because a failed attempt never created a connection", () => {
  const attempt = {
    domain: "acme.com",
    sessionId: "s1",
    reason: "session_failed" as const,
    scope: "session" as const,
    failedStep: "oauth_authorize" as const,
  };
  assert.equal(zConnectionFailedPayload.safeParse(attempt).success, true);
  const parsed = zConnectionFailedPayload.parse(attempt);
  assert.ok(!("connectionId" in parsed));
});

test("zConnectionFailedPayload (dns_drift arm) requires fqdn + the failing records list", () => {
  assert.equal(
    zConnectionFailedPayload.safeParse({
      domain: "acme.com",
      sessionId: "s1",
      connectionId: "c1",
      fqdn: "www.acme.com",
      reason: "dns_drift",
      scope: "connection",
      records: [{ fqdn: "www.acme.com", type: "CNAME" }],
    }).success,
    true,
  );
  // The dns_drift arm without its records evidence is rejected.
  assert.equal(
    zConnectionFailedPayload.safeParse({
      domain: "acme.com",
      sessionId: "s1",
      connectionId: "c1",
      fqdn: "www.acme.com",
      reason: "dns_drift",
      scope: "connection",
    }).success,
    false,
  );
});

// #45: `scope` is the machine-readable axis, pinned to its arm — an emitter
// cannot ship a drift event labelled session-scoped (or vice versa), which is
// exactly the mis-scoped handling the additive field exists to prevent.
test("zConnectionFailedPayload pins each arm's scope: dns_drift is connection-scoped, session_failed is session-scoped, and neither may claim the other", () => {
  const drift = {
    domain: "acme.com",
    sessionId: "s1",
    connectionId: "c1",
    fqdn: "www.acme.com",
    reason: "dns_drift" as const,
    records: [{ fqdn: "www.acme.com", type: "CNAME" }],
  };
  const attempt = {
    domain: "acme.com",
    sessionId: "s1",
    reason: "session_failed" as const,
    failedStep: "oauth_authorize" as const,
  };

  const parsedDrift = zConnectionFailedPayload.safeParse({ ...drift, scope: "connection" });
  assert.ok(parsedDrift.success);
  assert.equal(parsedDrift.data.scope, "connection");

  const parsedAttempt = zConnectionFailedPayload.safeParse({ ...attempt, scope: "session" });
  assert.ok(parsedAttempt.success);
  assert.equal(parsedAttempt.data.scope, "session");

  // Cross-labelled, missing, or invented scopes are all rejected in-tx at emit
  // time (WEBHOOK_EVENT_PAYLOAD_SCHEMAS) — a receiver can trust the field.
  assert.equal(zConnectionFailedPayload.safeParse({ ...drift, scope: "session" }).success, false);
  assert.equal(
    zConnectionFailedPayload.safeParse({ ...attempt, scope: "connection" }).success,
    false,
  );
  assert.equal(zConnectionFailedPayload.safeParse(drift).success, false);
  assert.equal(zConnectionFailedPayload.safeParse({ ...drift, scope: "domain" }).success, false);
});

// The compatibility promise #45 was constrained by: `reason` — the field
// existing integrators (Uptimely) discriminate on — keeps its exact values and
// stays the union's discriminant. If someone ever "tidies" the union onto
// `scope`, an unknown reason would start parsing and this fails.
test("zConnectionFailedPayload still discriminates on `reason`, whose values are unchanged by the added scope field", () => {
  assert.equal(
    zConnectionFailedPayload.safeParse({
      domain: "acme.com",
      sessionId: "s1",
      reason: "connection_removed",
      scope: "connection",
    }).success,
    false,
  );
});

test("zConnectionFailedPayload (session_failed arm, W6) requires failedStep and takes an optional error detail", () => {
  assert.equal(
    zConnectionFailedPayload.safeParse({
      domain: "acme.com",
      sessionId: "s1",
      reason: "session_failed",
      scope: "session",
      failedStep: "oauth_authorize",
    }).success,
    true,
  );
  assert.equal(
    zConnectionFailedPayload.safeParse({
      domain: "acme.com",
      sessionId: "s1",
      reason: "session_failed",
      scope: "session",
      failedStep: "record_write",
      error: "zone not found",
    }).success,
    true,
  );
  // session_failed without the failedStep discriminant detail is rejected.
  assert.equal(
    zConnectionFailedPayload.safeParse({
      domain: "acme.com",
      sessionId: "s1",
      reason: "session_failed",
      scope: "session",
    }).success,
    false,
  );
  // An unknown reason is rejected by the discriminated union.
  assert.equal(
    zConnectionFailedPayload.safeParse({
      domain: "acme.com",
      sessionId: "s1",
      reason: "meteor_strike",
    }).success,
    false,
  );
});

test("zConnectionDisconnectedPayload requires fqdn + an ISO disconnectedAt (F3)", () => {
  const ok = {
    domain: "acme.com",
    sessionId: "s1",
    connectionId: "c1",
    fqdn: "www.acme.com",
    disconnectedAt: new Date().toISOString(),
  };
  assert.equal(zConnectionDisconnectedPayload.safeParse(ok).success, true);
  assert.equal(
    zConnectionDisconnectedPayload.safeParse({ ...ok, disconnectedAt: "yesterday" }).success,
    false,
  );
  assert.equal(
    zConnectionDisconnectedPayload.safeParse({ ...ok, fqdn: undefined }).success,
    false,
    "fqdn identifies WHICH host stopped being monitored",
  );
});

test("zListConnectionsQuery defaults includeDisconnected to false and bounds the cursor (F3)", () => {
  const bare = zListConnectionsQuery.parse({});
  assert.equal(bare.includeDisconnected, false, "the default list is 'what is live'");
  assert.equal(bare.limit, 50);
  assert.equal(bare.cursor, undefined);
  assert.equal(zListConnectionsQuery.safeParse({ cursor: "" }).success, false);
  assert.equal(zListConnectionsQuery.safeParse({ includeDisconnected: "yes" }).success, false);
});

test("zListConnectionsResponse carries disconnectedAt + a nullable nextCursor (F3)", () => {
  const row = {
    id: "c1",
    appId: "a1",
    sessionId: "s1",
    domain: "acme.com",
    // `fqdn` is the session domain repeated — what the API has always sent
    // (this fixture used to read "www.acme.com", the value the NAME suggests
    // but the write side never produced). `recordFqdns` is the honest set.
    fqdn: "acme.com",
    recordFqdns: ["www.acme.com"],
    status: "active",
    verifiedAt: new Date().toISOString(),
    lastCheckedAt: null,
    brokenAt: null,
    disconnectedAt: null,
    createdAt: new Date().toISOString(),
  };
  assert.equal(
    zListConnectionsResponse.safeParse({ connections: [row], nextCursor: null }).success,
    true,
  );
  assert.equal(
    zListConnectionsResponse.safeParse({ connections: [row], nextCursor: "c1" }).success,
    true,
  );
  // status stays the two-value health vocabulary — "disconnected" is carried
  // by the timestamp, never as a third enum value (backward compatibility).
  assert.equal(
    zListConnectionsResponse.safeParse({
      connections: [{ ...row, status: "disconnected" }],
      nextCursor: null,
    }).success,
    false,
  );
  // Omitting a required field (the disconnectedAt the route must always send)
  // is a contract violation, not a silent undefined.
  const { disconnectedAt: _omitted, ...withoutDisconnectedAt } = row;
  assert.equal(
    zListConnectionsResponse.safeParse({
      connections: [withoutDisconnectedAt],
      nextCursor: null,
    }).success,
    false,
  );
});

test(
  "a connection reports every monitored record name in recordFqdns, since one session can " +
    "carry several — the reason the ambiguous `fqdn` was not repaired in place (2026-08-18)",
  () => {
    const row = {
      id: "c1",
      appId: "a1",
      sessionId: "s1",
      domain: "acme.com",
      fqdn: "acme.com",
      recordFqdns: ["www.acme.com", "acme.com"],
      status: "active",
      verifiedAt: new Date().toISOString(),
      lastCheckedAt: null,
      brokenAt: null,
      disconnectedAt: null,
      createdAt: new Date().toISOString(),
    };
    assert.equal(zConnectionSummary.safeParse(row).success, true);
    // A session whose records are missing reports an empty list, never a
    // fabricated name.
    assert.equal(zConnectionSummary.safeParse({ ...row, recordFqdns: [] }).success, true);
    // Required, like every other field the route always sends: a producer that
    // forgets it is a contract violation, not a silent undefined.
    const { recordFqdns: _dropped, ...withoutRecordFqdns } = row;
    assert.equal(zConnectionSummary.safeParse(withoutRecordFqdns).success, false);
    // Empty strings are not names.
    assert.equal(zConnectionSummary.safeParse({ ...row, recordFqdns: [""] }).success, false);
  },
);

test("zDisconnectConnectionResponse pins the DELETE body (F3)", () => {
  const ok = {
    id: "c1",
    disconnectedAt: new Date().toISOString(),
    alreadyDisconnected: false,
  };
  assert.equal(zDisconnectConnectionResponse.safeParse(ok).success, true);
  assert.equal(
    zDisconnectConnectionResponse.safeParse({ ...ok, disconnectedAt: null }).success,
    false,
    "a disconnect ALWAYS has an instant — the idempotent repeat returns the original",
  );
});

test("zSessionCompletedPayload / zSessionAbandonedPayload shapes", () => {
  assert.equal(
    zSessionCompletedPayload.safeParse({ domain: "acme.com", sessionId: "s1", connectionId: "c1" })
      .success,
    true,
  );
  assert.equal(
    zSessionAbandonedPayload.safeParse({
      domain: "acme.com",
      sessionId: "s1",
      lastStatus: "authorizing",
      expiredAt: new Date().toISOString(),
    }).success,
    true,
  );
  // A non-datetime expiredAt is rejected.
  assert.equal(
    zSessionAbandonedPayload.safeParse({
      domain: "acme.com",
      sessionId: "s1",
      lastStatus: "authorizing",
      expiredAt: "yesterday",
    }).success,
    false,
  );
});

test("zWebhookEvent requires id + type + occurredAt + data", () => {
  const parsed = zWebhookEvent.safeParse({ type: "connection.verified", data: {} });
  assert.equal(parsed.success, false); // missing id/occurredAt
});

test(
  "zWebhookEvent round-trips through signWebhook/verifyWebhook — the LIVE wire " +
    "envelope since the D-003 cutover (2026-08-06); the transport sends it via zWebhookEventWire",
  () => {
    const event = zWebhookEvent.parse({
      id: "whd_test123",
      type: "connection.verified",
      occurredAt: new Date().toISOString(),
      data: { domain: "acme.com", sessionId: "sess_1" },
    });
    const body = JSON.stringify(event);
    const now = 1_700_000_000_000;
    const sig = signWebhook("whsec_test", body, now);
    assert.ok(verifyWebhook("whsec_test", body, sig, 5 * 60 * 1000, now));
  },
);

test("zWebhookEventWire is the canonical envelope plus the deprecated `event` alias", () => {
  const canonical = {
    id: "whd_test123",
    type: "connection.verified" as const,
    occurredAt: new Date().toISOString(),
    data: { domain: "acme.com", sessionId: "sess_1" },
  };

  // The alias is required ON THE WIRE while pre-cutover receivers exist — a body
  // missing it would break Uptimely's zod schema (live since 2026-07-21). This
  // asserts the producer cannot "helpfully" drop it without failing here first.
  assert.equal(zWebhookEventWire.safeParse(canonical).success, false);

  const wire = zWebhookEventWire.parse({ ...canonical, event: "connection.verified" });
  assert.equal(wire.event, wire.type, "the alias never carries a second value");

  // The canonical envelope is a strict subset: anything the wire schema accepts,
  // the published zWebhookEvent contract accepts too.
  assert.equal(zWebhookEvent.safeParse(wire).success, true);
});

// ── postMessage contract ─────────────────────────────────────────────────────

test("zDoDomainMessage accepts a verified message (with optional domain) and a close message", () => {
  assert.equal(
    zDoDomainMessage.safeParse({ type: MESSAGE_TYPES.VERIFIED, domain: "acme.com" }).success,
    true,
  );
  assert.equal(zDoDomainMessage.safeParse({ type: MESSAGE_TYPES.VERIFIED }).success, true);
  assert.equal(zDoDomainMessage.safeParse({ type: MESSAGE_TYPES.CLOSE }).success, true);
});

test("zDoDomainMessage rejects an unknown message type", () => {
  assert.equal(zDoDomainMessage.safeParse({ type: "dodomain:bogus" }).success, false);
  assert.equal(zDoDomainMessage.safeParse({}).success, false);
});

// ── Provider-detection boundary schemas (detect + domains/check + reverify) ──

test("zProviderGuide accepts every real guideFor() output (known, unknown, %domain%-substituted)", () => {
  for (const provider of ["cloudflare", "godaddy", "namecheap", "squarespace", "route53"]) {
    const parsed = zProviderGuide.parse(guideFor(provider, "example.com"));
    assert.equal(parsed.provider, provider);
  }
  // Unknown provider → the generic guide, no dashboardUrl.
  const generic = zProviderGuide.parse(guideFor("definitely-not-a-provider"));
  assert.equal(generic.provider, "unknown");
  assert.equal(generic.dashboardUrl, undefined);
});

test("zCheckDomainInput trims and bounds the domain", () => {
  assert.equal(zCheckDomainInput.parse({ domain: " example.com " }).domain, "example.com");
  assert.equal(zCheckDomainInput.safeParse({ domain: "" }).success, false);
  assert.equal(zCheckDomainInput.safeParse({ domain: "   " }).success, false);
  assert.equal(zCheckDomainInput.safeParse({}).success, false);
  assert.equal(zCheckDomainInput.safeParse({ domain: "a".repeat(254) }).success, false);
});

test("zCheckDomainResponse accepts the route payload for both discovery outcomes", () => {
  const base = {
    domain: "shop.feastables.com",
    zone: "feastables.com",
    provider: "godaddy",
    label: "GoDaddy",
    tier: 2,
    method: "domain-connect",
    confidence: "high",
    nameServers: ["ns1.domaincontrol.com", "ns2.domaincontrol.com"],
    guide: guideFor("godaddy", "feastables.com"),
  };
  assert.equal(
    zCheckDomainResponse.safeParse({
      ...base,
      domainConnect: { discovered: true, providerId: "godaddy.com", providerName: "GoDaddy" },
    }).success,
    true,
  );
  assert.equal(
    zCheckDomainResponse.safeParse({ ...base, domainConnect: { discovered: false } }).success,
    true,
  );
  // tier outside 1|2|3 is a producer bug, not a passthrough.
  assert.equal(
    zCheckDomainResponse.safeParse({ ...base, tier: 4, domainConnect: { discovered: false } })
      .success,
    false,
  );
});

test("zDetectSessionResponse requires zone + domainConnectReady and allows a null domainConnect", () => {
  const payload = {
    provider: "unknown",
    label: "your DNS provider",
    zone: "example.com",
    tier: 3,
    method: "guided",
    confidence: "low",
    nameServers: [],
    domainConnect: null,
    // Tier-2 build: the fail-closed one-click readiness field is REQUIRED —
    // a producer that forgets it (⇒ the UI could never gate the CTA) fails
    // this schema, not just the connect page.
    domainConnectReady: false,
    guide: guideFor("unknown", "example.com"),
  };
  assert.equal(zDetectSessionResponse.safeParse(payload).success, true);
  const { zone: _zone, ...withoutZone } = payload;
  assert.equal(zDetectSessionResponse.safeParse(withoutZone).success, false);
  const { domainConnectReady: _ready, ...withoutReady } = payload;
  assert.equal(zDetectSessionResponse.safeParse(withoutReady).success, false);
});

test("zReverifyConnectionResponse pins the 202 body to {accepted:true}", () => {
  assert.equal(zReverifyConnectionResponse.safeParse({ accepted: true }).success, true);
  assert.equal(zReverifyConnectionResponse.safeParse({ accepted: false }).success, false);
  assert.equal(zReverifyConnectionResponse.safeParse({}).success, false);
});

// ── zIntegratorSession — GET /api/v1/sessions/:id (integrator-authed) ───────
// The session-lifecycle read integrators had no server-side answer for. The
// cases below pin the three fields that make it worth adding at all.

const integratorSession = {
  id: "cmsqmhr020001lk077pezjgl1",
  appId: "app_1",
  domain: "customer.com",
  records: [{ type: "CNAME", host: "app", fqdn: "app.customer.com" }],
  recipe: null,
  status: "verifying",
  tier: 3,
  detectedProvider: "cloudflare",
  connectionId: null,
  createdAt: "2026-08-16T09:00:00.000Z",
  expiresAt: "2026-08-17T09:00:00.000Z",
  expired: true,
};

test("zIntegratorSession accepts the full session-lifecycle read, expired sessions included — reading a session AFTER expiry is the whole point of this arm", () => {
  const parsed = zIntegratorSession.parse(integratorSession);
  assert.equal(parsed.expired, true);
  assert.equal(parsed.connectionId, null);
  assert.equal(parsed.records[0]?.fqdn, "app.customer.com");
});

test("zIntegratorSession requires the derived `expired` flag — a producer that omits it leaves the caller doing the client-side timestamp math this endpoint exists to replace", () => {
  const { expired: _expired, ...withoutExpired } = integratorSession;
  assert.equal(zIntegratorSession.safeParse(withoutExpired).success, false);
});

test("zIntegratorSession carries COMPOSED records (fqdn), not the raw request echo zPublicSession returns", () => {
  const rawEcho = {
    ...integratorSession,
    records: [{ type: "CNAME", host: "app", value: "cname.sendly.io" }],
  };
  assert.equal(zIntegratorSession.safeParse(rawEcho).success, false);
});

test("zIntegratorSession names the connection once one exists, so a session.completed receiver can reach the connections API without a second lookup", () => {
  const parsed = zIntegratorSession.parse({ ...integratorSession, connectionId: "conn_1" });
  assert.equal(parsed.connectionId, "conn_1");
});
