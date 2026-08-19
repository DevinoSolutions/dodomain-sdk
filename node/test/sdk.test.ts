import assert from "node:assert/strict";
import { test } from "node:test";

import { DoDomain, DoDomainError } from "../src/index.ts";

// Pure unit tests (always run) — no network, `fetchImpl` is injected. This
// file started as the pre-fix characterization (PLAN-F-008 §4/step 2):
// packages/node had NO test directory before that commit, so there was no
// pre-existing pin — those tests documented today's behavior first, per the
// green-suite rule. Step 5 (this commit) flips the SyntaxError pin to its
// fixed DoDomainError behavior and adds response/request validation coverage.

function client(fetchImpl: typeof fetch) {
  return new DoDomain({ secretKey: "dd_sk_test", fetchImpl });
}

function fakeFetch(status: number, body: string): typeof fetch {
  return (async () => new Response(body, { status })) as unknown as typeof fetch;
}

// A minimal body the SHARED input schema accepts, so these transport/response
// tests exercise the transport rather than re-testing validation. Domain and
// records are both required (a recipe id is consumed by nothing) — see
// packages/core/src/schemas.ts's zCreateSessionInput.
const VALID_INPUT = {
  domain: "app.customer.com",
  records: [{ type: "CNAME" as const, host: "app", value: "edge.sendly.io" }],
};

const VALID_RESPONSE = {
  id: "cuid1",
  token: "dd_sess_abc",
  expiresAt: new Date().toISOString(),
  connectUrl: "https://connect.dodomain.io/connect/dd_sess_abc",
  // F3: the composed fqdn the server always returns for each requested record.
  records: [{ type: "CNAME" as const, host: "app", fqdn: "app.app.customer.com" }],
};

test("FIXED(F-008): a non-JSON error body throws DoDomainError, never a raw SyntaxError", async () => {
  const dodomain = client(fakeFetch(502, "<html>502 Bad Gateway</html>"));
  await assert.rejects(
    () => dodomain.sessions.create(VALID_INPUT),
    (err: unknown) => {
      assert.ok(err instanceof DoDomainError, `expected DoDomainError, got ${(err as Error).name}`);
      assert.equal(err.message, "non_json_response");
      assert.equal(err.status, 502);
      assert.equal(err.body, "<html>502 Bad Gateway</html>");
      return true;
    },
  );
});

test("a JSON error body throws DoDomainError with status + body (unchanged by the fix)", async () => {
  const dodomain = client(fakeFetch(401, JSON.stringify({ error: "unauthorized" })));
  await assert.rejects(
    () => dodomain.sessions.create(VALID_INPUT),
    (err: unknown) => {
      assert.ok(err instanceof DoDomainError);
      assert.equal(err.message, "unauthorized");
      assert.equal(err.status, 401);
      assert.deepEqual(err.body, { error: "unauthorized" });
      return true;
    },
  );
});

test("a valid JSON success body returns the validated, parsed object (no regression)", async () => {
  const dodomain = client(fakeFetch(200, JSON.stringify(VALID_RESPONSE)));
  const session = await dodomain.sessions.create(VALID_INPUT);
  assert.deepEqual(session, VALID_RESPONSE);
});

// F3: the SDK is how most integrators meet this API, so the composed names and
// any advisory have to survive the client's own parse — not just the wire.
test("the SDK surfaces the composed fqdns and any warnings, typed, on the returned session", async () => {
  const warned = {
    ...VALID_RESPONSE,
    warnings: [
      {
        code: "duplicate_host_label" as const,
        message: 'host "app" repeats the leading label of domain "app.customer.com"',
        host: "app",
        fqdn: "app.app.customer.com",
      },
    ],
  };
  const dodomain = client(fakeFetch(200, JSON.stringify(warned)));
  const session = await dodomain.sessions.create(VALID_INPUT);
  assert.equal(session.records[0]?.fqdn, "app.app.customer.com");
  assert.equal(session.warnings?.[0]?.code, "duplicate_host_label");
});

test("FIXED(F-008): a response missing a required field throws DoDomainError('invalid_response_shape'), not a silently-wrong object", async () => {
  const dodomain = client(fakeFetch(200, JSON.stringify({ id: "cuid1" })));
  await assert.rejects(
    () => dodomain.sessions.create(VALID_INPUT),
    (err: unknown) => {
      assert.ok(err instanceof DoDomainError);
      assert.equal(err.message, "invalid_response_shape");
      assert.equal(err.status, 200);
      return true;
    },
  );
});

test("FIXED(F-008): an invalid request input is rejected client-side as DoDomainError before any network call", async () => {
  let called = false;
  const fetchImpl = (async () => {
    called = true;
    return new Response("{}", { status: 200 });
  }) as unknown as typeof fetch;
  const dodomain = client(fetchImpl);
  // No records — the same requirement the server enforces, from the same
  // schema. The cast is the point: the compiler now rejects this shape too,
  // and the test pins that a caller who bypasses TS still fails at runtime.
  await assert.rejects(
    () =>
      dodomain.sessions.create({ domain: "example.com" } as unknown as Parameters<
        typeof dodomain.sessions.create
      >[0]),
    (err: unknown) => {
      assert.ok(err instanceof DoDomainError);
      assert.equal(err.message, "invalid_request");
      assert.equal(err.status, 0, "status 0 signals no request was ever sent");
      return true;
    },
  );
  assert.equal(called, false, "an invalid input must never reach fetch");
});

test("constructor rejects a secret key without the dd_sk_ prefix", () => {
  assert.throws(() => new DoDomain({ secretKey: "not-a-key" }));
});
