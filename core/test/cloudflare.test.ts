// Offline unit tests for the Cloudflare OAuth connector — no network.
// `fetch` is mocked via the injectable fetchImpl on each function.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import {
  generatePkce,
  buildAuthorizeUrl,
  exchangeCode,
  CfOAuthError,
} from "../src/cloudflare/oauth.ts";
import {
  resolveZoneId,
  createRecord,
  deleteRecord,
  findRecordId,
  verifyRecordViaApi,
  CfDnsError,
} from "../src/cloudflare/dns.ts";
import { CF_TOKEN_URL, type CfConfig } from "../src/cloudflare/config.ts";

const CFG: CfConfig = {
  clientId: "client-abc",
  clientSecret: "secret-xyz",
  redirectUri: "http://localhost:8787/oauth/cf/callback",
};

// Build a fake fetch that records the call and returns a canned JSON response.
function fakeFetch(handler: (url: string, opts: any) => { status?: number; json: unknown }) {
  const calls: Array<{ url: string; opts: any }> = [];
  const impl = (async (url: string, opts: any) => {
    calls.push({ url, opts });
    const { status = 200, json } = handler(url, opts);
    return {
      ok: status >= 200 && status < 300,
      status,
      text: async () => JSON.stringify(json),
    } as any;
  }) as unknown as typeof fetch;
  return { impl, calls };
}

// ---- PKCE ----

test("generatePkce: challenge is base64url(sha256(verifier)) and url-safe", () => {
  const p = generatePkce();
  assert.equal(p.method, "S256");
  assert.match(p.verifier, /^[A-Za-z0-9_-]+$/, "verifier must be url-safe (no +/=)");
  assert.ok(p.verifier.length >= 43, "verifier should be high-entropy");
  const expected = createHash("sha256").update(p.verifier).digest().toString("base64url");
  assert.equal(p.challenge, expected);
  assert.match(p.challenge, /^[A-Za-z0-9_-]+$/);
});

test("generatePkce: fresh per call", () => {
  assert.notEqual(generatePkce().verifier, generatePkce().verifier);
});

// ---- authorize URL ----

test("buildAuthorizeUrl: all required params, correct endpoint, space-joined scopes", () => {
  const url = new URL(buildAuthorizeUrl({ config: CFG, state: "st-123", challenge: "ch-456" }));
  assert.equal(url.origin + url.pathname, "https://dash.cloudflare.com/oauth2/auth");
  const q = url.searchParams;
  assert.equal(q.get("response_type"), "code");
  assert.equal(q.get("client_id"), "client-abc");
  assert.equal(q.get("redirect_uri"), CFG.redirectUri);
  assert.equal(q.get("scope"), "zone.read dns.write");
  assert.equal(q.get("state"), "st-123");
  assert.equal(q.get("code_challenge"), "ch-456");
  assert.equal(q.get("code_challenge_method"), "S256");
});

// ---- token exchange ----

test("exchangeCode: posts client_secret_basic + verifier, parses token", async () => {
  const { impl, calls } = fakeFetch(() => ({
    json: {
      access_token: "tok-1",
      token_type: "bearer",
      expires_in: 3600,
      scope: "zone.read dns.write",
    },
  }));
  const tok = await exchangeCode({
    config: CFG,
    code: "auth-code",
    codeVerifier: "verifier-1",
    fetchImpl: impl,
  });
  assert.equal(tok.access_token, "tok-1");

  assert.equal(calls.length, 1);
  const { url, opts } = calls[0]!;
  assert.equal(url, CF_TOKEN_URL);
  assert.equal(opts.method, "POST");
  assert.equal(opts.headers["content-type"], "application/x-www-form-urlencoded");
  const expectedBasic = "Basic " + Buffer.from("client-abc:secret-xyz").toString("base64");
  assert.equal(opts.headers.authorization, expectedBasic);
  const body = new URLSearchParams(opts.body);
  assert.equal(body.get("grant_type"), "authorization_code");
  assert.equal(body.get("code"), "auth-code");
  assert.equal(body.get("redirect_uri"), CFG.redirectUri);
  assert.equal(body.get("code_verifier"), "verifier-1");
});

test("exchangeCode: throws on error response", async () => {
  const { impl } = fakeFetch(() => ({
    status: 400,
    json: { error: "invalid_grant", error_description: "bad code" },
  }));
  await assert.rejects(
    () => exchangeCode({ config: CFG, code: "x", codeVerifier: "y", fetchImpl: impl }),
    (e) => e instanceof CfOAuthError && /invalid_grant/.test(e.message),
  );
});

// ---- DNS (with OAuth bearer) ----

test("resolveZoneId: GET /zones?name= with bearer, returns first id", async () => {
  const { impl, calls } = fakeFetch(() => ({
    json: { success: true, result: [{ id: "zone-1", name: "devino.ca" }] },
  }));
  const id = await resolveZoneId("tok-1", "devino.ca", impl);
  assert.equal(id, "zone-1");
  const { url, opts } = calls[0]!;
  assert.ok(url.startsWith("https://api.cloudflare.com/client/v4/zones?"));
  assert.equal(new URL(url).searchParams.get("name"), "devino.ca");
  assert.equal(opts.headers.authorization, "Bearer tok-1");
});

test("resolveZoneId: throws when no zone", async () => {
  const { impl } = fakeFetch(() => ({ json: { success: true, result: [] } }));
  await assert.rejects(
    () => resolveZoneId("tok", "nope.example", impl),
    (e) => e instanceof CfDnsError,
  );
});

test("createRecord: POST dns_records with proxied:false + ttl, returns id", async () => {
  const { impl, calls } = fakeFetch(() => ({
    json: {
      success: true,
      result: { id: "rec-9", type: "CNAME", name: "dodomain-poc.devino.ca", content: "t.example" },
    },
  }));
  const rec = await createRecord(
    "tok-1",
    "zone-1",
    { type: "CNAME", name: "dodomain-poc.devino.ca", content: "t.example" },
    impl,
  );
  assert.equal(rec.id, "rec-9");
  const { url, opts } = calls[0]!;
  assert.equal(url, "https://api.cloudflare.com/client/v4/zones/zone-1/dns_records");
  assert.equal(opts.method, "POST");
  const sent = JSON.parse(opts.body);
  assert.equal(sent.type, "CNAME");
  assert.equal(sent.name, "dodomain-poc.devino.ca");
  assert.equal(sent.content, "t.example");
  assert.equal(sent.ttl, 120);
  assert.equal(sent.proxied, false);
});

// FIX(F-002 hop 3): DnsRecordInput.type widened to the full RECORD_TYPES set
// (was "CNAME" | "TXT" | "A") and createRecord now forwards `priority` —
// Cloudflare requires it on MX writes; the old code never sent it.
test("createRecord: MX writes forward priority in the request body", async () => {
  const { impl, calls } = fakeFetch(() => ({
    json: {
      success: true,
      result: { id: "rec-10", type: "MX", name: "customer.com", content: "mx1.example.com" },
    },
  }));
  await createRecord(
    "tok-1",
    "zone-1",
    { type: "MX", name: "customer.com", content: "mx1.example.com", priority: 10 },
    impl,
  );
  const sent = JSON.parse(calls[0]!.opts.body);
  assert.equal(sent.type, "MX");
  assert.equal(sent.priority, 10);
});

test("createRecord: an AAAA write omits priority (only MX carries it)", async () => {
  const { impl, calls } = fakeFetch(() => ({
    json: {
      success: true,
      result: { id: "rec-11", type: "AAAA", name: "customer.com", content: "2001:db8::1" },
    },
  }));
  await createRecord(
    "tok-1",
    "zone-1",
    { type: "AAAA", name: "customer.com", content: "2001:db8::1" },
    impl,
  );
  const sent = JSON.parse(calls[0]!.opts.body);
  assert.equal(sent.type, "AAAA");
  assert.equal("priority" in sent, false);
});

test("createRecord: throws on success:false envelope", async () => {
  const { impl } = fakeFetch(() => ({
    status: 200,
    json: {
      success: false,
      errors: [{ code: 81053, message: "record already exists" }],
      result: null,
    },
  }));
  await assert.rejects(
    () => createRecord("tok", "zone", { type: "CNAME", name: "x.devino.ca", content: "y" }, impl),
    (e) => e instanceof CfDnsError && /81053/.test(e.message),
  );
});

// ---- verifyRecordViaApi (D-001: read-back is a VALUE match, not raw ===) ----
// Each drives the CF read-back via the injected fetchImpl and asserts BOTH
// `.present` (does the record exist) and `.match` (does its value agree). These
// fail against the old `rec.content === expect` compare (case/dot-sensitive, no
// MX-priority) that D-001 replaced with record-capabilities.ts recordValueMatches.

test("verifyRecordViaApi: CNAME read-back is trailing-dot- and case-insensitive → match true", async () => {
  const { impl } = fakeFetch(() => ({
    json: { success: true, result: [{ content: "Target.Example.com.", proxied: false }] },
  }));
  const v = await verifyRecordViaApi(
    "tok",
    "zone-1",
    "CNAME",
    "www.customer.com",
    "target.example.com",
    undefined,
    impl,
  );
  assert.equal(v.present, true);
  assert.equal(v.match, true);
  assert.equal(v.value, "Target.Example.com."); // raw read-back preserved for telemetry
});

test("verifyRecordViaApi: a wrong CNAME target → present true / match false (presence is NOT a match)", async () => {
  const { impl } = fakeFetch(() => ({
    json: { success: true, result: [{ content: "someone-else.example.net" }] },
  }));
  const v = await verifyRecordViaApi(
    "tok",
    "zone-1",
    "CNAME",
    "www.customer.com",
    "target.example.com",
    undefined,
    impl,
  );
  assert.equal(v.present, true);
  assert.equal(v.match, false);
});

test("verifyRecordViaApi: TXT differing only in case → present true / match false (tokens are case-significant)", async () => {
  const { impl } = fakeFetch(() => ({
    json: { success: true, result: [{ content: "DODOMAIN-VERIFY=ABC123" }] },
  }));
  const v = await verifyRecordViaApi(
    "tok",
    "zone-1",
    "TXT",
    "_dodomain.customer.com",
    "dodomain-verify=abc123",
    undefined,
    impl,
  );
  assert.equal(v.present, true);
  assert.equal(v.match, false);
});

test("verifyRecordViaApi: MX with the WRONG priority → present true / match false", async () => {
  const { impl } = fakeFetch(() => ({
    json: { success: true, result: [{ content: "mx1.example.com", priority: 20 }] },
  }));
  const v = await verifyRecordViaApi(
    "tok",
    "zone-1",
    "MX",
    "customer.com",
    "mx1.example.com",
    10, // expected preference — read-back is 20
    impl,
  );
  assert.equal(v.present, true);
  assert.equal(v.match, false); // exchange agrees, but preference 20 ≠ 10
});

test("verifyRecordViaApi: MX with the correct exchange AND priority → match true", async () => {
  const { impl } = fakeFetch(() => ({
    json: { success: true, result: [{ content: "mx1.example.com", priority: 10 }] },
  }));
  const v = await verifyRecordViaApi(
    "tok",
    "zone-1",
    "MX",
    "customer.com",
    "mx1.example.com",
    10,
    impl,
  );
  assert.equal(v.match, true);
});

test("verifyRecordViaApi: multi-record read-back matches ANY record, not result[0] (apex TXT bag)", async () => {
  // A real apex: SPF + a site verification sort BEFORE our token in Cloudflare's
  // listing. The old `result[0]` read reported match:false for a token that IS
  // live — the read-back half of the TXT-coexistence fix.
  const { impl } = fakeFetch(() => ({
    json: {
      success: true,
      result: [
        { content: "v=spf1 include:_spf.example.com ~all" },
        { content: "google-site-verification=xyz" },
        { content: "dodomain-verify=abc123" },
      ],
    },
  }));
  const v = await verifyRecordViaApi(
    "tok",
    "zone-1",
    "TXT",
    "customer.com",
    "dodomain-verify=abc123",
    undefined,
    impl,
  );
  assert.equal(v.present, true);
  assert.equal(v.match, true, "our token is live even though it is not the first listed record");
  assert.equal(v.value, "dodomain-verify=abc123", "the MATCHED record's value is surfaced");
});

test("verifyRecordViaApi: multi-record read-back with NO matching value → match false, first value surfaced", async () => {
  const { impl } = fakeFetch(() => ({
    json: {
      success: true,
      result: [{ content: "v=spf1 ~all" }, { content: "google-site-verification=xyz" }],
    },
  }));
  const v = await verifyRecordViaApi(
    "tok",
    "zone-1",
    "TXT",
    "customer.com",
    "dodomain-verify=abc123",
    undefined,
    impl,
  );
  assert.equal(v.present, true);
  assert.equal(v.match, false);
  assert.equal(v.value, "v=spf1 ~all", "first record's value shown for the CONFLICT notice");
});

test("verifyRecordViaApi: an absent record → present false / match false / value null", async () => {
  const { impl } = fakeFetch(() => ({ json: { success: true, result: [] } }));
  const v = await verifyRecordViaApi(
    "tok",
    "zone-1",
    "A",
    "customer.com",
    "203.0.113.10",
    undefined,
    impl,
  );
  assert.equal(v.present, false);
  assert.equal(v.match, false);
  assert.equal(v.value, null);
});

test("findRecordId + deleteRecord: locate then DELETE by id", async () => {
  const find = fakeFetch(() => ({ json: { success: true, result: [{ id: "rec-1" }] } }));
  const id = await findRecordId("tok", "zone-1", "CNAME", "dodomain-poc.devino.ca", find.impl);
  assert.equal(id, "rec-1");

  const del = fakeFetch(() => ({ json: { success: true, result: { id: "rec-1" } } }));
  await deleteRecord("tok", "zone-1", "rec-1", del.impl);
  assert.equal(del.calls[0]!.opts.method, "DELETE");
  assert.equal(
    del.calls[0]!.url,
    "https://api.cloudflare.com/client/v4/zones/zone-1/dns_records/rec-1",
  );
});
