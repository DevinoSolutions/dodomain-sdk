import assert from "node:assert/strict";
import { test } from "node:test";

import { DoDomain, DoDomainError } from "../src/index.ts";
import type { Connection, WebhookEvent, WebhookEventWire } from "../src/index.ts";

// The `connections` namespace (2026-08-17): list / get / delete / reverify.
// Same injected-fetch unit style as sdk.test.ts — no network. What these pin is
// the two things a partner who drops their hand-rolled fetch is trusting us
// for: the exact request we put on the wire (method, path, query), and that a
// body which is NOT what the route documents fails LOUDLY instead of arriving
// as a plausible-looking object.

const VALID_KEY = "dd_sk_test_123";

const CONNECTION: Connection = {
  id: "conn_1",
  appId: "app_1",
  sessionId: "sess_1",
  domain: "acme.com",
  // What the server ACTUALLY sends: `fqdn` is the session domain again (this
  // fixture used to read "app.acme.com", the value the name suggests but the
  // API never sent — prod E2E wave 2, 2026-08-18), and the record names live
  // in `recordFqdns`.
  fqdn: "acme.com",
  recordFqdns: ["app.acme.com"],
  status: "active",
  verifiedAt: "2026-08-17T09:00:00.000Z",
  lastCheckedAt: "2026-08-17T09:30:00.000Z",
  brokenAt: null,
  disconnectedAt: null,
  createdAt: "2026-08-17T08:00:00.000Z",
};

interface SeenRequest {
  url: string;
  method: string;
  authorization: string | null;
}

/** Records what the SDK actually sent, and replies with `body` at `status`. */
function recordingFetch(
  seen: SeenRequest[],
  body: unknown,
  status = 200,
): { fetchImpl: typeof fetch } {
  const fetchImpl: typeof fetch = async (input, init) => {
    if (typeof input !== "string") throw new Error("SDK must call fetch with a string URL");
    const headers = new Headers(init?.headers);
    seen.push({
      url: input,
      method: init?.method ?? "GET",
      authorization: headers.get("authorization"),
    });
    return new Response(JSON.stringify(body), { status });
  };
  return { fetchImpl };
}

function client(fetchImpl: typeof fetch): DoDomain {
  return new DoDomain({ secretKey: VALID_KEY, fetchImpl });
}

test("connections.list sends GET /api/v1/connections with no query string when no filters are passed", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(seen, { connections: [CONNECTION], nextCursor: null });

  const page = await client(fetchImpl).connections.list();

  assert.equal(seen[0]?.url, "https://app.dodomain.io/api/v1/connections");
  assert.equal(seen[0]?.method, "GET");
  assert.equal(seen[0]?.authorization, `Bearer ${VALID_KEY}`);
  assert.deepEqual(page.connections, [CONNECTION]);
  assert.equal(page.nextCursor, null);
});

test("connections.list puts only the filters the caller passed on the wire, never SDK-side defaults", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(seen, { connections: [], nextCursor: null });

  await client(fetchImpl).connections.list({ domain: "acme.com", limit: 2 });

  const query = new URL(seen[0]?.url ?? "").searchParams;
  assert.equal(query.get("domain"), "acme.com");
  assert.equal(query.get("limit"), "2");
  assert.equal(query.get("includeDisconnected"), null, "an omitted filter must not be sent");
  assert.equal(query.get("cursor"), null);
  assert.equal(query.get("appId"), null);
});

test("connections.list forwards the paging cursor and the includeDisconnected flag as sent", async () => {
  const seen: SeenRequest[] = [];
  const disconnected: Connection = { ...CONNECTION, disconnectedAt: "2026-08-17T10:00:00.000Z" };
  const { fetchImpl } = recordingFetch(seen, {
    connections: [disconnected],
    nextCursor: "conn_1",
  });

  const page = await client(fetchImpl).connections.list({
    cursor: "conn_0",
    includeDisconnected: true,
  });

  const query = new URL(seen[0]?.url ?? "").searchParams;
  assert.equal(query.get("cursor"), "conn_0");
  assert.equal(query.get("includeDisconnected"), "true");
  assert.equal(page.nextCursor, "conn_1", "nextCursor is what a caller pages forward with");
  assert.equal(page.connections[0]?.disconnectedAt, "2026-08-17T10:00:00.000Z");
});

test("connections.list rejects an out-of-range limit client-side, before any network call", async () => {
  let called = false;
  const fetchImpl = (async () => {
    called = true;
    return new Response("{}", { status: 200 });
  }) as unknown as typeof fetch;

  await assert.rejects(
    () => client(fetchImpl).connections.list({ limit: 101 }),
    (err: unknown) => {
      assert.ok(err instanceof DoDomainError);
      assert.equal(err.message, "invalid_request");
      assert.equal(err.status, 0, "status 0 signals no request was ever sent");
      return true;
    },
  );
  assert.equal(called, false, "an invalid filter must never reach fetch");
});

test("connections.list throws invalid_response_shape when the body is missing nextCursor", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(seen, { connections: [CONNECTION] });

  await assert.rejects(
    () => client(fetchImpl).connections.list(),
    (err: unknown) => {
      assert.ok(err instanceof DoDomainError);
      assert.equal(err.message, "invalid_response_shape");
      return true;
    },
  );
});

test("connections.get sends GET /api/v1/connections/:id and returns the validated connection", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(seen, CONNECTION);

  const connection = await client(fetchImpl).connections.get("conn_1");

  assert.equal(seen[0]?.url, "https://app.dodomain.io/api/v1/connections/conn_1");
  assert.equal(seen[0]?.method, "GET");
  assert.deepEqual(connection, CONNECTION);
});

test("connections.get percent-encodes the id instead of letting it inject extra path segments", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(seen, CONNECTION);

  await client(fetchImpl).connections.get("conn 1/../apps");

  assert.equal(
    seen[0]?.url,
    "https://app.dodomain.io/api/v1/connections/conn%201%2F..%2Fapps",
    "a hostile id must stay one path segment",
  );
});

test("connections.get rejects a blank connection id before any network call", async () => {
  let called = false;
  const fetchImpl = (async () => {
    called = true;
    return new Response("{}", { status: 200 });
  }) as unknown as typeof fetch;

  await assert.rejects(
    () => client(fetchImpl).connections.get("   "),
    (err: unknown) => {
      assert.ok(err instanceof DoDomainError);
      assert.equal(err.message, "invalid_request");
      assert.equal(err.status, 0);
      return true;
    },
  );
  assert.equal(called, false, "a blank id must never collapse onto the collection route");
});

test("connections.get surfaces the API's 404 as a DoDomainError carrying the status", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(seen, { error: "not_found" }, 404);

  await assert.rejects(
    () => client(fetchImpl).connections.get("conn_missing"),
    (err: unknown) => {
      assert.ok(err instanceof DoDomainError);
      assert.equal(err.message, "not_found");
      assert.equal(err.status, 404);
      return true;
    },
  );
});

test("connections.delete sends DELETE /api/v1/connections/:id and returns the disconnect outcome", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(seen, {
    id: "conn_1",
    disconnectedAt: "2026-08-17T10:00:00.000Z",
    alreadyDisconnected: false,
  });

  const outcome = await client(fetchImpl).connections.delete("conn_1");

  assert.equal(seen[0]?.url, "https://app.dodomain.io/api/v1/connections/conn_1");
  assert.equal(seen[0]?.method, "DELETE");
  assert.equal(outcome.disconnectedAt, "2026-08-17T10:00:00.000Z");
  assert.equal(outcome.alreadyDisconnected, false);
});

test("connections.delete reports alreadyDisconnected on a repeat, with the ORIGINAL timestamp", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(seen, {
    id: "conn_1",
    disconnectedAt: "2026-08-17T10:00:00.000Z",
    alreadyDisconnected: true,
  });

  const outcome = await client(fetchImpl).connections.delete("conn_1");

  assert.equal(outcome.alreadyDisconnected, true);
  assert.equal(outcome.disconnectedAt, "2026-08-17T10:00:00.000Z");
});

test("connections.reverify POSTs to the reverify sub-path and accepts the 202", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(seen, { accepted: true }, 202);

  const outcome = await client(fetchImpl).connections.reverify("conn_1");

  assert.equal(seen[0]?.url, "https://app.dodomain.io/api/v1/connections/conn_1/reverify");
  assert.equal(seen[0]?.method, "POST");
  assert.equal(outcome.accepted, true);
});

test("connections.reverify surfaces the cooldown 429 as a DoDomainError with its details body", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(
    seen,
    { error: "rate_limited", details: { retryAfterSeconds: 420 } },
    429,
  );

  await assert.rejects(
    () => client(fetchImpl).connections.reverify("conn_1"),
    (err: unknown) => {
      assert.ok(err instanceof DoDomainError);
      assert.equal(err.status, 429);
      assert.deepEqual(err.body, { error: "rate_limited", details: { retryAfterSeconds: 420 } });
      return true;
    },
  );
});

test("connections.list honours an explicit baseUrl for self-hosted deployments", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(seen, { connections: [], nextCursor: null });

  const dd = new DoDomain({
    secretKey: VALID_KEY,
    baseUrl: "https://self-hosted.example.com/",
    fetchImpl,
  });
  await dd.connections.list();

  assert.equal(seen[0]?.url, "https://self-hosted.example.com/api/v1/connections");
});

// The exported webhook envelope types exist so a receiver stops hand-writing
// `{id, type, occurredAt, data}` from the docs. Types erase at runtime, so what
// this pins is the shape a real delivery has to satisfy: the annotation below
// is the assertion (a drifted type fails `pnpm typecheck`), and the runtime
// checks pin the alias relationship the transport actually maintains.
test("the exported webhook envelope types describe a real delivery body, alias included", () => {
  const wire: WebhookEventWire = {
    id: "whd_1",
    type: "connection.verified",
    occurredAt: "2026-08-17T09:00:00.000Z",
    data: { domain: "acme.com", connectionId: "conn_1", sessionId: "sess_1" },
    event: "connection.verified",
  };

  assert.equal(wire.event, wire.type, "the deprecated alias is byte-identical to type");

  // A wire body IS a canonical event — a receiver typed against the narrower
  // WebhookEvent keeps compiling and keeps working.
  const canonical: WebhookEvent = wire;
  assert.equal(canonical.id, "whd_1");
  assert.equal(canonical.data.domain, "acme.com");
});
