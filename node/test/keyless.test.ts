import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import { DoDomain, DoDomainError, DoDomainKeylessError, solveKeylessProof } from "../src/index.ts";
import { pickSha256 } from "../src/keyless.ts";

// Keyless mode (0.9.0, T-18036): the proof-of-work solver against known
// vectors, and the 428-then-200 flow against a SCRIPTED STAND-IN for the API.
// Every fake below is named for what it is and says so in a comment; nothing
// here reaches the network.

// Known vectors, computed independently of this SDK with Python's hashlib:
//   next(n for n in itertools.count()
//        if int.from_bytes(sha256(f"{c}:{n}".encode()).digest(), "big") >> (256 - d) == 0)
const VECTORS = [
  { challenge: "ARQAAAGa-test-vector", bits: 8, nonce: 309 },
  { challenge: "ARQAAAGa-test-vector", bits: 12, nonce: 1996 },
  { challenge: "dodomain-known-vector", bits: 16, nonce: 64049 },
] as const;

/** An independent check of a proof: the leading bits of the full digest. */
function proofHolds(headerValue: string, bits: number): boolean {
  const digest = createHash("sha256").update(headerValue).digest();
  let zeros = 0;
  for (const byte of digest) {
    if (byte === 0) {
      zeros += 8;
      continue;
    }
    zeros += Math.clz32(byte) - 24;
    break;
  }
  return zeros >= bits;
}

for (const vector of VECTORS) {
  test(`the solver finds the smallest nonce for "${vector.challenge}" at ${vector.bits} bits (${vector.nonce})`, async () => {
    const proof = await solveKeylessProof(vector.challenge, vector.bits);
    assert.equal(proof, `${vector.challenge}:${vector.nonce}`);
    assert.ok(proofHolds(proof, vector.bits));
  });
}

test("the solver answers nonce 0 at zero bits, and refuses an empty challenge or a difficulty outside 0 to 24", async () => {
  assert.equal(await solveKeylessProof("anything", 0), "anything:0");
  for (const bits of [25, -1, 1.5, Number.NaN]) {
    await assert.rejects(
      solveKeylessProof("c", bits),
      (error: unknown) =>
        error instanceof DoDomainKeylessError &&
        error.code === "KEYLESS_PROOF_UNSUPPORTED" &&
        error.status === 0,
    );
  }
  await assert.rejects(
    solveKeylessProof("", 8),
    (error: unknown) =>
      error instanceof DoDomainKeylessError && error.code === "KEYLESS_PROOF_UNSUPPORTED",
  );
});

test("the solver hashes with the one-shot crypto.hash when it exists and createHash otherwise, to the same digest", () => {
  const abcDigest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
  let oneShotCalls = 0;
  // FAKE crypto modules: the real createHash, with and without a one-shot
  // `hash`, so both branches run on any Node version.
  const fakeCryptoWithOneShotHash = {
    createHash,
    hash: (algorithm: string, data: string) => {
      oneShotCalls += 1;
      return createHash(algorithm).update(data).digest("hex");
    },
  };
  const fakeCryptoWithoutOneShotHash = { createHash };
  assert.equal(pickSha256(fakeCryptoWithOneShotHash)("abc"), abcDigest);
  assert.equal(oneShotCalls, 1);
  assert.equal(pickSha256(fakeCryptoWithoutOneShotHash)("abc"), abcDigest);
});

test("an aborted solve rejects KEYLESS_PROOF_ABORTED, and a slow one KEYLESS_PROOF_TIMEOUT", async () => {
  // "dodomain-slow-vector" has no 24-bit answer below nonce 200 000, so both
  // searches are still running when the abort or the deadline lands.
  const controller = new AbortController();
  const aborted = solveKeylessProof("dodomain-slow-vector", 24, { signal: controller.signal });
  setTimeout(() => controller.abort(), 5);
  await assert.rejects(
    aborted,
    (error: unknown) =>
      error instanceof DoDomainKeylessError && error.code === "KEYLESS_PROOF_ABORTED",
  );
  await assert.rejects(
    solveKeylessProof("dodomain-slow-vector", 24, { timeoutMs: 20 }),
    (error: unknown) =>
      error instanceof DoDomainKeylessError && error.code === "KEYLESS_PROOF_TIMEOUT",
  );
});

// ── the flow, against a scripted stand-in for the API ─────────────────────────

const INPUT = {
  domain: "acme.com",
  records: [{ type: "CNAME" as const, host: "app", value: "edge.example.com" }],
};
const KEY = "dd_ks_scripted_key";
const CHALLENGE = "ARQAAAGa-test-vector";
const BITS = 8;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

function proofRequired(challenge = CHALLENGE, reason = "proof_missing"): Response {
  return json(
    {
      type: "about:blank",
      status: 428,
      error: "proof_required",
      code: "KEYLESS_PROOF_REQUIRED",
      message: "Starting a keyless app without a key needs a small proof of work.",
      details: {
        reason,
        challenge,
        algorithm: "sha256",
        difficultyBits: BITS,
        expiresAt: "2026-11-17T09:05:00.000Z",
        header: "DoDomain-Keyless-Proof",
        signUpUrl: "https://app.dodomain.io/signin?mode=signup",
      },
    },
    428,
  );
}

function keylessSession(withKey: boolean, used = 0): Response {
  return json({
    id: "sess_1",
    token: "dd_sess_abc",
    expiresAt: "2026-11-17T09:00:00.000Z",
    connectUrl: "https://app.dodomain.io/connect/dd_sess_abc",
    records: [{ type: "CNAME", host: "app", fqdn: "app.acme.com" }],
    mode: "live",
    keyless: {
      ...(withKey ? { key: KEY } : {}),
      appId: "app_keyless_1",
      allowance: { limit: 10, used, open: 1, remaining: 9 - used },
      claimUrl: `https://app.dodomain.io/claim/keyless#${KEY}`,
      unlock: "Create a free account and claim this app for 50 verified connections a month.",
      docs: "https://dodomain.io/docs/getting-started#keyless-start",
    },
  });
}

interface SeenRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: unknown;
}

/**
 * MOCK fetch: a scripted stand-in for the keyless API. It answers a call with
 * no key 428 (or 200 once it carries a proof that really holds), and a call
 * with the scripted dd_ks_ key 200, recording every request it saw.
 */
function scriptedKeylessApi(overrides: { onProof?: (proof: string) => Response } = {}) {
  const seen: SeenRequest[] = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    if (typeof input !== "string") throw new Error("SDK must call fetch with a string URL");
    const headers = Object.fromEntries(
      Object.entries((init?.headers ?? {}) as Record<string, string>).map(([k, v]) => [
        k.toLowerCase(),
        v,
      ]),
    );
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    seen.push({ method: init?.method ?? "GET", url: input, headers, body });
    if (input.endsWith("/api/v1/keyless") && headers.authorization === `Bearer ${KEY}`) {
      return json({
        appId: "app_keyless_1",
        allowance: { limit: 10, used: 1, open: 0, remaining: 9 },
        claimUrl: `https://app.dodomain.io/claim/keyless#${KEY}`,
        unlock: "Create a free account and claim this app.",
        docs: "https://dodomain.io/docs/getting-started#keyless-start",
        createdAt: "2026-11-16T09:00:00.000Z",
        lastUsedAt: null,
      });
    }
    if (headers.authorization === `Bearer ${KEY}`) return keylessSession(false, 1);
    const proof = headers["dodomain-keyless-proof"];
    if (proof === undefined) return proofRequired();
    if (overrides.onProof) return overrides.onProof(proof);
    return proofHolds(proof, BITS) && proof.startsWith(`${CHALLENGE}:`)
      ? keylessSession(true)
      : proofRequired("ARQAAAGa-fresh-challenge");
  };
  return { fetchImpl, seen };
}

test("a keyless client answers the 428 with a solved proof, retries once, keeps the dd_ks_ key and needs no proof after", async () => {
  const api = scriptedKeylessApi();
  const dd = new DoDomain({ keyless: true, fetchImpl: api.fetchImpl });
  assert.equal(dd.keylessKey, null);

  const first = await dd.sessions.create(INPUT);
  assert.equal(first.connectUrl, "https://app.dodomain.io/connect/dd_sess_abc");
  assert.equal(first.keyless?.claimUrl, `https://app.dodomain.io/claim/keyless#${KEY}`);
  assert.deepEqual(first.keyless?.allowance, { limit: 10, used: 0, open: 1, remaining: 9 });
  assert.equal(dd.keylessKey, KEY);

  assert.equal(api.seen.length, 2);
  const [challenged, proved] = api.seen;
  assert.equal(challenged?.url, "https://app.dodomain.io/api/v1/keyless/sessions");
  assert.equal(challenged?.headers.authorization, undefined);
  assert.equal(proved?.headers["dodomain-keyless-proof"], `${CHALLENGE}:309`);
  assert.deepEqual(proved?.body, INPUT);

  const second = await dd.sessions.create(INPUT);
  assert.equal(second.keyless?.key, undefined);
  assert.equal(api.seen.length, 3);
  assert.equal(api.seen[2]?.headers.authorization, `Bearer ${KEY}`);
  assert.equal(api.seen[2]?.headers["dodomain-keyless-proof"], undefined);

  const status = await dd.keyless.status();
  assert.equal(status.allowance.remaining, 9);
  assert.equal(api.seen[3]?.method, "GET");
  assert.equal(api.seen[3]?.url, "https://app.dodomain.io/api/v1/keyless");
});

test("concurrent creates on a fresh keyless client start ONE keyless app and reuse its key", async () => {
  const api = scriptedKeylessApi();
  const dd = new DoDomain({ keyless: true, fetchImpl: api.fetchImpl });
  await Promise.all([
    dd.sessions.create(INPUT),
    dd.sessions.create(INPUT),
    dd.sessions.create(INPUT),
  ]);
  const anonymous = api.seen.filter((request) => request.headers.authorization === undefined);
  assert.equal(anonymous.length, 2, "one 428 and one proved retry, not three starts");
  assert.equal(api.seen.length, 4);
});

test("a 428 refusing the proof as invalid is thrown as KEYLESS_PROOF_REQUIRED, with no third attempt", async () => {
  const api = scriptedKeylessApi({
    onProof: () => proofRequired("ARQAAAGa-harder", "proof_invalid"),
  });
  const dd = new DoDomain({ keyless: true, fetchImpl: api.fetchImpl });
  await assert.rejects(dd.sessions.create(INPUT), (error: unknown) => {
    assert.ok(error instanceof DoDomainKeylessError);
    assert.ok(error instanceof DoDomainError, "still a DoDomainError for existing catch blocks");
    assert.equal(error.code, "KEYLESS_PROOF_REQUIRED");
    assert.equal(error.status, 428);
    assert.equal(error.details?.challenge, "ARQAAAGa-harder");
    return true;
  });
  assert.equal(api.seen.length, 2);
  assert.equal(dd.keylessKey, null);
});

test("a spent allowance surfaces as a typed KEYLESS_LIMIT_REACHED with the unlock details", async () => {
  // MOCK fetch: answers every call with the API's 402 allowance refusal.
  const fakeSpentAllowance: typeof fetch = async () =>
    json(
      {
        error: "quota_exceeded",
        code: "KEYLESS_LIMIT_REACHED",
        message: "This keyless app used its 10 verified connections.",
        details: {
          reason: "keyless_limit_reached",
          scope: "app",
          limit: 10,
          unlock: {
            action: "claim_and_create_api_key",
            claimUrl: "https://app.dodomain.io/claim/keyless",
          },
        },
      },
      402,
    );
  const dd = new DoDomain({ keyless: true, keylessKey: KEY, fetchImpl: fakeSpentAllowance });
  await assert.rejects(dd.sessions.create(INPUT), (error: unknown) => {
    assert.ok(error instanceof DoDomainKeylessError);
    assert.equal(error.code, "KEYLESS_LIMIT_REACHED");
    assert.equal(
      error.message,
      "quota_exceeded: This keyless app used its 10 verified connections.",
    );
    assert.equal(error.error, "quota_exceeded");
    assert.equal(error.status, 402);
    assert.equal(error.details?.limit, 10);
    return true;
  });
});

test("a keyless client refuses secret-key calls, an appId, and a status read before it has a key, all without a request", async () => {
  let calls = 0;
  // MOCK fetch: counts calls; any call at all fails this test.
  const fakeFetchThatMustNotBeCalled: typeof fetch = async () => {
    calls += 1;
    return json({});
  };
  const dd = new DoDomain({ keyless: true, fetchImpl: fakeFetchThatMustNotBeCalled });
  await assert.rejects(
    dd.apps.list(),
    (error: unknown) =>
      error instanceof DoDomainKeylessError && error.code === "KEYLESS_MODE" && error.status === 0,
  );
  await assert.rejects(
    dd.sessions.create({ ...INPUT, appId: "app_1" }),
    (error: unknown) =>
      error instanceof DoDomainError && error.message === "invalid_request" && error.status === 0,
  );
  await assert.rejects(
    dd.keyless.status(),
    (error: unknown) =>
      error instanceof DoDomainKeylessError && error.code === "KEYLESS_KEY_MISSING",
  );
  assert.equal(calls, 0);
});

test("keyless mode is an explicit opt-in: no secretKey still throws, and the two modes cannot be mixed", () => {
  assert.throws(
    () => new DoDomain({ secretKey: undefined as unknown as string }),
    /new DoDomain\(\{ keyless: true \}\)/,
  );
  assert.throws(
    () =>
      new DoDomain({ keyless: true, secretKey: "dd_sk_x" } as unknown as ConstructorParameters<
        typeof DoDomain
      >[0]),
  );
  assert.throws(() => new DoDomain({ keyless: true, keylessKey: "dd_sk_not_keyless" }));
  assert.equal(new DoDomain({ keyless: true, keylessKey: KEY }).keylessKey, KEY);
});

for (const reason of ["proof_too_easy", "proof_expired"] as const) {
  test(`a retry refused as ${reason} solves the fresh challenge once more and succeeds`, async () => {
    const FRESH = "ARQAAAGa-fresh-challenge";
    const api = scriptedKeylessApi({
      onProof: (proof) =>
        proof.startsWith(`${FRESH}:`) && proofHolds(proof, BITS)
          ? keylessSession(true)
          : proofRequired(FRESH, reason),
    });
    const dd = new DoDomain({ keyless: true, fetchImpl: api.fetchImpl });
    const session = await dd.sessions.create(INPUT);
    assert.equal(session.connectUrl, "https://app.dodomain.io/connect/dd_sess_abc");
    assert.equal(api.seen.length, 3, "the 428, the first proof, the fresh proof");
    assert.ok(api.seen[1]?.headers["dodomain-keyless-proof"]?.startsWith(`${CHALLENGE}:`));
    assert.ok(api.seen[2]?.headers["dodomain-keyless-proof"]?.startsWith(`${FRESH}:`));
    assert.equal(dd.keylessKey, KEY);
  });
}

test("a second stale-proof refusal propagates: a keyless start solves at most two proofs", async () => {
  let fresh = 0;
  const api = scriptedKeylessApi({
    onProof: () => proofRequired(`ARQAAAGa-fresh-${++fresh}`, "proof_too_easy"),
  });
  const dd = new DoDomain({ keyless: true, fetchImpl: api.fetchImpl });
  await assert.rejects(
    dd.sessions.create(INPUT),
    (error: unknown) =>
      error instanceof DoDomainKeylessError &&
      error.code === "KEYLESS_PROOF_REQUIRED" &&
      error.details?.challenge === "ARQAAAGa-fresh-2",
  );
  assert.equal(api.seen.length, 3);
});

test("an error never carries a whole dd_ks_ key: refusals, their details and a bad response shape are redacted", async () => {
  const SECRET = "dd_ks_live_secret_part_9f8e7d";
  // MOCK fetch: a 402 whose message, claimUrl and nested strings all echo the key.
  const fakeRefusalEchoingTheKey: typeof fetch = async () =>
    json(
      {
        error: `quota_exceeded for ${SECRET}`,
        code: "KEYLESS_LIMIT_REACHED",
        message: `Claim ${SECRET} to continue.`,
        details: {
          limit: 10,
          unlock: { claimUrl: `https://app.dodomain.io/claim/keyless#${SECRET}` },
          seen: [SECRET],
        },
      },
      402,
    );
  const dd = new DoDomain({
    keyless: true,
    keylessKey: SECRET,
    fetchImpl: fakeRefusalEchoingTheKey,
  });
  const refusal = await dd.sessions.create(INPUT).catch((error: unknown) => error);
  assert.ok(refusal instanceof DoDomainKeylessError);
  assert.equal(refusal.code, "KEYLESS_LIMIT_REACHED");
  assert.deepEqual(refusal.details?.unlock, {
    claimUrl: "https://app.dodomain.io/claim/keyless#dd_ks_…",
  });
  for (const rendered of [JSON.stringify(refusal), String(refusal), refusal.stack ?? ""]) {
    assert.ok(!rendered.includes(SECRET), `the key leaked: ${rendered}`);
  }
  assert.ok(
    JSON.stringify(refusal).includes("dd_ks_…"),
    "the prefix stays, so the field is recognisable",
  );

  // MOCK fetch: a 200 that carries the key but not the session shape the SDK checks.
  const fakeMalformedSuccess: typeof fetch = async () =>
    json({ keyless: { key: SECRET, claimUrl: `https://app.dodomain.io/claim/keyless#${SECRET}` } });
  const malformed = await new DoDomain({ keyless: true, fetchImpl: fakeMalformedSuccess }).sessions
    .create(INPUT)
    .catch((error: unknown) => error);
  assert.ok(malformed instanceof DoDomainError);
  assert.equal(malformed.message, "invalid_response_shape");
  for (const rendered of [JSON.stringify(malformed), String(malformed)]) {
    assert.ok(!rendered.includes(SECRET), `the key leaked: ${rendered}`);
  }
});

test("a create waiting on another create's keyless start honours its own abort signal", async () => {
  let releaseStart: (() => void) | undefined;
  const api = scriptedKeylessApi();
  // MOCK fetch: holds the very first (anonymous) call until the test releases it.
  const fakeSlowStart: typeof fetch = async (input, init) => {
    if (api.seen.length === 0) await new Promise<void>((resolve) => (releaseStart = resolve));
    return api.fetchImpl(input, init);
  };
  const dd = new DoDomain({ keyless: true, fetchImpl: fakeSlowStart });
  const starter = dd.sessions.create(INPUT);
  await new Promise((resolve) => setImmediate(resolve));

  const controller = new AbortController();
  const waiter = dd.sessions.create(INPUT, { signal: controller.signal });
  const reason = new Error("caller gave up");
  controller.abort(reason);
  await assert.rejects(waiter, (error: unknown) => error === reason);

  releaseStart?.();
  const started = await starter;
  assert.equal(started.keyless?.key, KEY, "the start the waiter left still finishes");
  assert.equal(api.seen.length, 2, "the aborted waiter sent nothing");
});

test("proofTimeoutMs must be a finite number of milliseconds above 0 and at most 5 minutes", () => {
  for (const bad of [0, -1, Number.NaN, Number.POSITIVE_INFINITY, 300_001]) {
    assert.throws(
      () => new DoDomain({ keyless: true, proofTimeoutMs: bad }),
      /proofTimeoutMs must be a number of milliseconds above 0 and at most 300000/,
      String(bad),
    );
  }
  assert.doesNotThrow(() => new DoDomain({ keyless: true, proofTimeoutMs: 300_000 }));
  assert.doesNotThrow(() => new DoDomain({ keyless: true, proofTimeoutMs: 1 }));
});

test("a keyless create sends its optional appName, and a secret-key client refuses one without a request", async () => {
  const api = scriptedKeylessApi();
  const dd = new DoDomain({ keyless: true, fetchImpl: api.fetchImpl });
  await dd.sessions.create({ ...INPUT, appName: "  Acme Sites  " });
  assert.deepEqual(
    api.seen[1]?.body,
    { ...INPUT, appName: "Acme Sites" },
    "trimmed, as the API stores it",
  );

  let calls = 0;
  // MOCK fetch: counts calls; any call at all fails this test.
  const fakeFetchThatMustNotBeCalled: typeof fetch = async () => {
    calls += 1;
    return json({});
  };
  const keyed = new DoDomain({ secretKey: "dd_sk_test", fetchImpl: fakeFetchThatMustNotBeCalled });
  await assert.rejects(
    keyed.sessions.create({ ...INPUT, appName: "Acme Sites" }),
    (error: unknown) =>
      error instanceof DoDomainError && error.message === "invalid_request" && error.status === 0,
  );
  assert.equal(calls, 0);
});
