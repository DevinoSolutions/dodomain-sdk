import assert from "node:assert/strict";
import { test } from "node:test";

import { DoDomain, DoDomainError } from "../src/index.ts";
import type { IntegratorSession, WebhookEndpoint } from "../src/index.ts";

// Full v1 parity (0.3.0): the namespaces that closed the gap between the SDK
// and the REST surface — sessions.get (the authed, id-addressed arm), apps,
// domains.check, the webhook-endpoint lifecycle and key rotation.
//
// Same injected-fetch unit style as connections.test.ts — no network. What
// these pin is what a partner dropping their hand-rolled fetch is trusting us
// for: the exact request on the wire (method, path, body, auth header), that a
// body which is NOT what the route documents fails LOUDLY, and that the
// show-once secrets arrive intact on exactly the two responses that carry them.

const VALID_KEY = "dd_sk_test_123";

const SESSION: IntegratorSession = {
  id: "sess_1",
  appId: "app_1",
  domain: "acme.com",
  records: [{ type: "CNAME", host: "app", fqdn: "app.acme.com" }],
  recipe: null,
  status: "pending",
  tier: 2,
  detectedProvider: "cloudflare",
  connectionId: null,
  createdAt: "2026-08-19T08:00:00.000Z",
  expiresAt: "2026-08-20T08:00:00.000Z",
  expired: false,
};

const ENDPOINT: WebhookEndpoint = {
  id: "whe_1",
  appId: "app_1",
  url: "https://hooks.acme.com/dodomain",
  createdAt: "2026-08-19T08:00:00.000Z",
};

interface SeenRequest {
  url: string;
  method: string;
  authorization: string | null;
  body: string | null;
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
      body: typeof init?.body === "string" ? init.body : null,
    });
    return new Response(JSON.stringify(body), { status });
  };
  return { fetchImpl };
}

function client(fetchImpl: typeof fetch): DoDomain {
  return new DoDomain({ secretKey: VALID_KEY, fetchImpl });
}

/** A fetch that fails the test if it is ever reached — for the client-side
 * rejections that must never cost a network round trip. */
function unreachableFetch(): { fetchImpl: typeof fetch; wasCalled: () => boolean } {
  let called = false;
  const fetchImpl = (async () => {
    called = true;
    return new Response("{}", { status: 200 });
  }) as unknown as typeof fetch;
  return { fetchImpl, wasCalled: () => called };
}

// ── sessions.get ────────────────────────────────────────────────────────────

test("sessions.get reads a session by id over GET /api/v1/sessions/:id with the bearer key", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(seen, SESSION);

  const session = await client(fetchImpl).sessions.get("sess_1");

  assert.equal(seen[0]?.url, "https://app.dodomain.io/api/v1/sessions/sess_1");
  assert.equal(seen[0]?.method, "GET");
  assert.equal(seen[0]?.authorization, `Bearer ${VALID_KEY}`);
  assert.deepEqual(session, SESSION);
});

test("sessions.get returns an expired session with expired:true instead of refusing it", async () => {
  const seen: SeenRequest[] = [];
  // The window the flag exists for: expiresAt has passed but the reaper has not
  // yet rewritten `status`, so `status` alone would still read "pending".
  const { fetchImpl } = recordingFetch(seen, { ...SESSION, expired: true });

  const session = await client(fetchImpl).sessions.get("sess_1");

  assert.equal(session.expired, true);
  assert.equal(
    session.status,
    "pending",
    "expiry is read off `expired`, never inferred from status",
  );
});

test("sessions.get refuses a dd_sess_ token before any network call, naming the wrong arm", async () => {
  const { fetchImpl, wasCalled } = unreachableFetch();

  await assert.rejects(
    () => client(fetchImpl).sessions.get("dd_sess_abc123"),
    (err: unknown) => {
      assert.ok(err instanceof DoDomainError);
      assert.equal(err.message, "invalid_request");
      assert.equal(err.status, 0, "status 0 signals no request was ever sent");
      return true;
    },
  );
  assert.equal(wasCalled(), false, "a token must never be sent to the id arm");
});

test("sessions.get rejects a blank session id before any network call", async () => {
  const { fetchImpl, wasCalled } = unreachableFetch();

  await assert.rejects(
    () => client(fetchImpl).sessions.get("  "),
    (err: unknown) => {
      assert.ok(err instanceof DoDomainError);
      assert.equal(err.status, 0);
      return true;
    },
  );
  assert.equal(wasCalled(), false, "a blank id must never collapse onto the create route");
});

test("sessions.get percent-encodes the id instead of letting it inject extra path segments", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(seen, SESSION);

  await client(fetchImpl).sessions.get("sess 1/../apps");

  assert.equal(seen[0]?.url, "https://app.dodomain.io/api/v1/sessions/sess%201%2F..%2Fapps");
});

test("sessions.get surfaces the API's 404 for an unknown or not-yours id", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(seen, { error: "not_found" }, 404);

  await assert.rejects(
    () => client(fetchImpl).sessions.get("sess_missing"),
    (err: unknown) => {
      assert.ok(err instanceof DoDomainError);
      assert.equal(err.message, "not_found");
      assert.equal(err.status, 404);
      return true;
    },
  );
});

test("sessions.get throws invalid_response_shape when the body omits the derived expired flag", async () => {
  const seen: SeenRequest[] = [];
  const { expired: _omitted, ...withoutExpired } = SESSION;
  const { fetchImpl } = recordingFetch(seen, withoutExpired);

  await assert.rejects(
    () => client(fetchImpl).sessions.get("sess_1"),
    (err: unknown) => {
      assert.ok(err instanceof DoDomainError);
      assert.equal(err.message, "invalid_response_shape");
      return true;
    },
  );
});

// ── apps.list ───────────────────────────────────────────────────────────────

test("apps.list sends GET /api/v1/apps and returns the apps the credential can see", async () => {
  const seen: SeenRequest[] = [];
  const app = {
    id: "app_1",
    name: "Acme",
    publicKey: "pk_live_123",
    sandbox: false,
    logoUrl: null,
    brandColor: null,
    createdAt: "2026-08-19T08:00:00.000Z",
  };
  const { fetchImpl } = recordingFetch(seen, { apps: [app] });

  const result = await client(fetchImpl).apps.list();

  assert.equal(seen[0]?.url, "https://app.dodomain.io/api/v1/apps");
  assert.equal(seen[0]?.method, "GET");
  assert.deepEqual(result.apps, [app]);
});

test("apps.list rejects a body carrying secret material shaped as a missing publicKey", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(seen, { apps: [{ id: "app_1", name: "Acme" }] });

  await assert.rejects(
    () => client(fetchImpl).apps.list(),
    (err: unknown) => {
      assert.ok(err instanceof DoDomainError);
      assert.equal(err.message, "invalid_response_shape");
      return true;
    },
  );
});

// ── domains.check ───────────────────────────────────────────────────────────

const CHECK_RESULT = {
  domain: "acme.com",
  zone: "acme.com",
  provider: "cloudflare",
  label: "Cloudflare",
  tier: 1 as const,
  method: "oauth" as const,
  confidence: "high" as const,
  nameServers: ["ns1.cloudflare.com", "ns2.cloudflare.com"],
  domainConnect: { discovered: false },
  guide: {
    provider: "cloudflare",
    label: "Cloudflare",
    hostFormat: "subdomain only",
    apexToken: "@" as const,
    steps: ["Open the DNS tab", "Add the record"],
  },
};

test("domains.check POSTs the domain to /api/v1/domains/check and returns the pre-flight verdict", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(seen, CHECK_RESULT);

  const verdict = await client(fetchImpl).domains.check({ domain: "acme.com" });

  assert.equal(seen[0]?.url, "https://app.dodomain.io/api/v1/domains/check");
  assert.equal(seen[0]?.method, "POST");
  assert.equal(seen[0]?.body, JSON.stringify({ domain: "acme.com" }));
  assert.equal(verdict.tier, 1);
  assert.equal(verdict.zone, "acme.com");
  assert.equal(verdict.guide.apexToken, "@");
});

test("domains.check sends the trimmed domain the server would have parsed anyway", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(seen, CHECK_RESULT);

  await client(fetchImpl).domains.check({ domain: "  acme.com  " });

  assert.equal(seen[0]?.body, JSON.stringify({ domain: "acme.com" }));
});

test("domains.check rejects a domain past the 253-octet DNS ceiling before any network call", async () => {
  const { fetchImpl, wasCalled } = unreachableFetch();

  await assert.rejects(
    () => client(fetchImpl).domains.check({ domain: `${"a".repeat(250)}.example.com` }),
    (err: unknown) => {
      assert.ok(err instanceof DoDomainError);
      assert.equal(err.message, "invalid_request");
      assert.equal(err.status, 0);
      return true;
    },
  );
  assert.equal(wasCalled(), false, "an unusable domain must never reach fetch");
});

// ── webhookEndpoints ────────────────────────────────────────────────────────

test("webhookEndpoints.list sends GET /api/v1/webhook-endpoints and returns endpoints without secrets", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(seen, { endpoints: [ENDPOINT] });

  const result = await client(fetchImpl).webhookEndpoints.list();

  assert.equal(seen[0]?.url, "https://app.dodomain.io/api/v1/webhook-endpoints");
  assert.equal(seen[0]?.method, "GET");
  assert.deepEqual(result.endpoints, [ENDPOINT]);
  assert.equal(
    "secret" in (result.endpoints[0] ?? {}),
    false,
    "the list surface must never carry the signing secret",
  );
});

test("webhookEndpoints.create POSTs the url and returns the show-once signing secret", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(seen, { ...ENDPOINT, secret: "whsec_abc123" }, 201);

  const created = await client(fetchImpl).webhookEndpoints.create({
    url: "https://hooks.acme.com/dodomain",
  });

  assert.equal(seen[0]?.url, "https://app.dodomain.io/api/v1/webhook-endpoints");
  assert.equal(seen[0]?.method, "POST");
  assert.equal(seen[0]?.body, JSON.stringify({ url: "https://hooks.acme.com/dodomain" }));
  assert.equal(created.secret, "whsec_abc123", "the 201 body is the only copy of the secret");
  assert.equal(created.id, "whe_1");
});

test("webhookEndpoints.create fails loudly when the 201 body arrives without the secret", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(seen, ENDPOINT, 201);

  await assert.rejects(
    () => client(fetchImpl).webhookEndpoints.create({ url: "https://hooks.acme.com/dodomain" }),
    (err: unknown) => {
      assert.ok(err instanceof DoDomainError);
      assert.equal(
        err.message,
        "invalid_response_shape",
        "a silently secret-less create would leave the caller unable to verify any delivery",
      );
      return true;
    },
  );
});

test("webhookEndpoints.create rejects an empty url before any network call", async () => {
  const { fetchImpl, wasCalled } = unreachableFetch();

  await assert.rejects(
    () => client(fetchImpl).webhookEndpoints.create({ url: "" }),
    (err: unknown) => {
      assert.ok(err instanceof DoDomainError);
      assert.equal(err.message, "invalid_request");
      assert.equal(err.status, 0);
      return true;
    },
  );
  assert.equal(wasCalled(), false);
});

test("webhookEndpoints.create surfaces the server's url-policy 400 with its reason intact", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(
    seen,
    { error: "invalid_request", message: "webhook urls must be https" },
    400,
  );

  await assert.rejects(
    () => client(fetchImpl).webhookEndpoints.create({ url: "http://hooks.acme.com" }),
    (err: unknown) => {
      assert.ok(err instanceof DoDomainError);
      assert.equal(err.status, 400);
      assert.deepEqual(err.body, {
        error: "invalid_request",
        message: "webhook urls must be https",
      });
      return true;
    },
  );
});

test("webhookEndpoints.create surfaces the plan endpoint cap as a 402", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(
    seen,
    { error: "quota_exceeded", details: { limit: 3 } },
    402,
  );

  await assert.rejects(
    () => client(fetchImpl).webhookEndpoints.create({ url: "https://hooks.acme.com/second" }),
    (err: unknown) => {
      assert.ok(err instanceof DoDomainError);
      assert.equal(err.message, "quota_exceeded");
      assert.equal(err.status, 402);
      return true;
    },
  );
});

test("webhookEndpoints.update PATCHes the new url and returns a summary with no secret", async () => {
  const seen: SeenRequest[] = [];
  const moved: WebhookEndpoint = { ...ENDPOINT, url: "https://hooks2.acme.com/dodomain" };
  const { fetchImpl } = recordingFetch(seen, moved);

  const updated = await client(fetchImpl).webhookEndpoints.update("whe_1", {
    url: "https://hooks2.acme.com/dodomain",
  });

  assert.equal(seen[0]?.url, "https://app.dodomain.io/api/v1/webhook-endpoints/whe_1");
  assert.equal(seen[0]?.method, "PATCH");
  assert.equal(seen[0]?.body, JSON.stringify({ url: "https://hooks2.acme.com/dodomain" }));
  assert.deepEqual(updated, moved);
  assert.equal(
    "secret" in updated,
    false,
    "repointing an endpoint must not force the receiver to re-key",
  );
});

test("webhookEndpoints.update rejects a blank endpoint id before any network call", async () => {
  const { fetchImpl, wasCalled } = unreachableFetch();

  await assert.rejects(
    () => client(fetchImpl).webhookEndpoints.update("", { url: "https://hooks.acme.com" }),
    (err: unknown) => {
      assert.ok(err instanceof DoDomainError);
      assert.equal(err.status, 0);
      return true;
    },
  );
  assert.equal(wasCalled(), false, "a blank id must never PATCH the collection route");
});

test("webhookEndpoints.update surfaces the 404 an unknown or another app's id answers with", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(seen, { error: "not_found" }, 404);

  await assert.rejects(
    () => client(fetchImpl).webhookEndpoints.update("whe_other", { url: "https://hooks.acme.com" }),
    (err: unknown) => {
      assert.ok(err instanceof DoDomainError);
      assert.equal(err.status, 404);
      return true;
    },
  );
});

test("webhookEndpoints.delete sends DELETE to the endpoint path and reports what it removed", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(seen, { id: "whe_1", deleted: true });

  const outcome = await client(fetchImpl).webhookEndpoints.delete("whe_1");

  assert.equal(seen[0]?.url, "https://app.dodomain.io/api/v1/webhook-endpoints/whe_1");
  assert.equal(seen[0]?.method, "DELETE");
  assert.equal(outcome.id, "whe_1");
  assert.equal(outcome.deleted, true);
});

test("webhookEndpoints.delete percent-encodes the id instead of letting it climb the path", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(seen, { id: "x", deleted: true });

  await client(fetchImpl).webhookEndpoints.delete("whe 1/../../keys/rotate");

  assert.equal(
    seen[0]?.url,
    "https://app.dodomain.io/api/v1/webhook-endpoints/whe%201%2F..%2F..%2Fkeys%2Frotate",
    "a hostile id must stay one path segment",
  );
});

test("webhookEndpoints.rotateSecret POSTs the verb sub-path and returns the new show-once secret", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(seen, { ...ENDPOINT, secret: "whsec_rotated" });

  const rotated = await client(fetchImpl).webhookEndpoints.rotateSecret("whe_1");

  assert.equal(
    seen[0]?.url,
    "https://app.dodomain.io/api/v1/webhook-endpoints/whe_1/rotate-secret",
  );
  assert.equal(seen[0]?.method, "POST");
  assert.equal(rotated.secret, "whsec_rotated");
  assert.equal(rotated.id, "whe_1", "rotation returns the same endpoint, re-keyed");
});

test("webhookEndpoints.rotateSecret rejects a blank endpoint id before any network call", async () => {
  const { fetchImpl, wasCalled } = unreachableFetch();

  await assert.rejects(
    () => client(fetchImpl).webhookEndpoints.rotateSecret("   "),
    (err: unknown) => {
      assert.ok(err instanceof DoDomainError);
      assert.equal(err.status, 0);
      return true;
    },
  );
  assert.equal(wasCalled(), false);
});

// ── keys.rotate ─────────────────────────────────────────────────────────────

test("keys.rotate POSTs /api/v1/keys/rotate with the CURRENT key and returns the new one", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(seen, {
    appId: "app_1",
    publicKey: "pk_live_123",
    secretKey: "dd_sk_new_456",
    rotatedAt: "2026-08-19T09:00:00.000Z",
  });

  const rotated = await client(fetchImpl).keys.rotate();

  assert.equal(seen[0]?.url, "https://app.dodomain.io/api/v1/keys/rotate");
  assert.equal(seen[0]?.method, "POST");
  assert.equal(
    seen[0]?.authorization,
    `Bearer ${VALID_KEY}`,
    "the key being replaced is what authorizes its own replacement",
  );
  assert.equal(rotated.secretKey, "dd_sk_new_456", "this response is the only copy of the new key");
  assert.equal(rotated.publicKey, "pk_live_123", "the publishable key is echoed unrotated");
});

test("keys.rotate fails loudly rather than returning a rotation result with no new key", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(seen, {
    appId: "app_1",
    publicKey: "pk_live_123",
    rotatedAt: "2026-08-19T09:00:00.000Z",
  });

  await assert.rejects(
    () => client(fetchImpl).keys.rotate(),
    (err: unknown) => {
      assert.ok(err instanceof DoDomainError);
      assert.equal(
        err.message,
        "invalid_response_shape",
        "a rotation whose new key never arrived has locked the caller out — it must throw",
      );
      return true;
    },
  );
});

test("keys.rotate surfaces the raw API's SECRET_KEY_REQUIRED refusal with its details code readable", async () => {
  // Unreachable THROUGH this SDK — the constructor only accepts a dd_sk_ key —
  // but a self-hosted baseUrl or a proxy can still answer it, and the code a
  // caller has to act on must survive in `body`, not be flattened to "HTTP 403".
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(
    seen,
    { error: "forbidden", details: { code: "SECRET_KEY_REQUIRED" } },
    403,
  );

  await assert.rejects(
    () => client(fetchImpl).keys.rotate(),
    (err: unknown) => {
      assert.ok(err instanceof DoDomainError);
      assert.equal(err.message, "forbidden");
      assert.equal(err.status, 403);
      assert.deepEqual(err.body, {
        error: "forbidden",
        details: { code: "SECRET_KEY_REQUIRED" },
      });
      return true;
    },
  );
});

test("every new namespace honours an explicit baseUrl for self-hosted deployments", async () => {
  const seen: SeenRequest[] = [];
  const { fetchImpl } = recordingFetch(seen, { endpoints: [] });

  const dd = new DoDomain({
    secretKey: VALID_KEY,
    baseUrl: "https://self-hosted.example.com/",
    fetchImpl,
  });
  await dd.webhookEndpoints.list();

  assert.equal(seen[0]?.url, "https://self-hosted.example.com/api/v1/webhook-endpoints");
});
