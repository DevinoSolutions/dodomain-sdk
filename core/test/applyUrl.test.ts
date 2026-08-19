import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildApplyUrl,
  payloadFromUrl,
  ApplyUrlError,
  DEFAULT_SIGNATURE_EMISSION_ORDER,
  signatureEmissionOrderForDnsProvider,
  type SignatureEmissionOrder,
} from "../src/applyUrl.ts";
import { generateKeyPair, signQueryString, verifyQueryString } from "../src/sign.ts";

const SYNC = "https://domainconnect.example/sync";
const ALLOW = ["localhost", "127.0.0.1"];

test("builds the canonical apply path", () => {
  const a = buildApplyUrl({
    urlSyncUX: SYNC,
    providerId: "example.com",
    serviceId: "custom-subdomain-cname",
    domain: "customer.com",
    host: "status",
    variables: { target: "cname.uptimely.io" },
    redirectUri: "http://localhost:8787/callback",
    allowedRedirectHosts: ALLOW,
  });
  assert.equal(
    a.base,
    `${SYNC}/v2/domainTemplates/providers/example.com/services/custom-subdomain-cname/apply`,
  );
  assert.match(
    a.url,
    /\?domain=customer\.com&host=status&target=cname\.uptimely\.io&redirect_uri=/,
  );
});

test("omits host when not provided", () => {
  const a = buildApplyUrl({
    urlSyncUX: SYNC,
    providerId: "p",
    serviceId: "domain-verification",
    domain: "customer.com",
    variables: { token: "abc" },
    redirectUri: "http://localhost/callback",
    allowedRedirectHosts: ALLOW,
  });
  assert.ok(!a.payload.includes("host="), "host should be absent");
  assert.match(a.payload, /domain=customer\.com&token=abc&redirect_uri=/);
});

test("url-encodes the redirect_uri", () => {
  const a = buildApplyUrl({
    urlSyncUX: SYNC,
    providerId: "p",
    serviceId: "s",
    domain: "d.com",
    variables: {},
    redirectUri: "http://localhost:8787/callback?sessionId=xyz",
    allowedRedirectHosts: ALLOW,
  });
  assert.ok(
    a.payload.includes("redirect_uri=http%3A%2F%2Flocalhost%3A8787%2Fcallback%3FsessionId%3Dxyz"),
  );
});

test("rejects redirect_uri not in allowlist (open-redirect protection)", () => {
  assert.throws(
    () =>
      buildApplyUrl({
        urlSyncUX: SYNC,
        providerId: "p",
        serviceId: "s",
        domain: "d.com",
        variables: {},
        redirectUri: "https://evil.example/steal",
        allowedRedirectHosts: ALLOW,
      }),
    ApplyUrlError,
  );
});

test("rejects non-https urlSyncUX", () => {
  assert.throws(() =>
    buildApplyUrl({
      urlSyncUX: "http://insecure.example/sync",
      providerId: "p",
      serviceId: "s",
      domain: "d.com",
      variables: {},
      redirectUri: "http://localhost/callback",
      allowedRedirectHosts: ALLOW,
    }),
  );
});

// ── The DNS Provider's model of our signature ────────────────────────────────
//
// Deliberately reimplemented here instead of calling payloadFromUrl: verifying
// our own payload with our own verifier is a closed loop that cannot catch a
// wrong signed string (it is exactly what let the `key`-inside-the-payload bug
// ship green — see the PR for fix/dc-apply-signature-spec). This mirrors the
// DNS-provider-side reference implementation byte for byte:
//   Domain-Connect/DomainConnectApplyZone, domainconnectzone/DomainConnectImpl.py
//     verify_sig(pubKey, sig, qs) — ":param qs: The query string without sig= or key="
//   called on qsutil.qsfilter(qs, ['sig','key'])
// i.e. the provider verifies the query string with BOTH `sig` and `key` removed
// by NAME (order-insensitive).
function providerVerifiedQueryString(url: string): string {
  return url
    .slice(url.indexOf("?") + 1)
    .split("&")
    .filter((pair) => {
      const name = pair.split("=")[0];
      return name !== "sig" && name !== "key";
    })
    .join("&");
}

function signedFixture(emissionOrder?: SignatureEmissionOrder) {
  const { publicKeyPem, privateKeyPem } = generateKeyPair();
  const applyUrl = buildApplyUrl({
    urlSyncUX: SYNC,
    providerId: "example.com",
    serviceId: "custom-subdomain-cname",
    domain: "customer.com",
    host: "status",
    variables: { target: "t.example" },
    redirectUri: "http://localhost/callback",
    state: "st8",
    allowedRedirectHosts: ALLOW,
    signing: {
      privateKeyPem,
      keyHost: "_dck1",
      ...(emissionOrder ? { emissionOrder } : {}),
    },
  });
  return { publicKeyPem, privateKeyPem, applyUrl };
}

test("a conformant DNS Provider verifies our signature (spec: signed string excludes sig AND key)", () => {
  const { publicKeyPem, applyUrl } = signedFixture();
  const asTheProviderSeesIt = providerVerifiedQueryString(applyUrl.url);
  assert.equal(
    verifyQueryString(publicKeyPem, asTheProviderSeesIt, applyUrl.sig!),
    true,
    "the signature must verify over the query string minus sig and key",
  );
});

test("payloadFromUrl reproduces exactly what a DNS Provider verifies", () => {
  const { applyUrl } = signedFixture();
  // The helper IS the provider model — anything else makes it a misleading
  // debugging aid for the next session.
  assert.equal(payloadFromUrl(applyUrl.url), providerVerifiedQueryString(applyUrl.url));
  assert.equal(payloadFromUrl(applyUrl.url), applyUrl.payload);
});

test("key is appended AFTER signing — absent from the signed payload, present in the URL after sig", () => {
  const { applyUrl } = signedFixture();
  assert.ok(!applyUrl.payload.includes("key="), "key must NOT be inside the signed payload");
  assert.ok(applyUrl.url.includes("&sig="), "has sig");
  assert.ok(
    applyUrl.url.indexOf("&key=_dck1") > applyUrl.url.indexOf("&sig="),
    "key must trail sig so a positional verifier's payload stops before it",
  );
});

// ── A POSITIONAL DNS Provider's model of our signature ───────────────────────
//
// Glauca HexDNS (AS207960) — one of exactly two providers serving our templates
// and the only one we can actually apply against today — does NOT filter by
// name. It splits the raw query string:
//   hexdns_django/connect/views.py :: verify_signature
//     signed_data = request.META['QUERY_STRING'].rsplit("&sig=", 1)[0]
// so "everything before &sig=" IS their signed payload, and any parameter
// emitted before sig lands inside it whether the spec says so or not. That is
// non-conformant (the spec's rule is name-based), but it is what runs in
// production, and it is why emitting `...&key=...&sig=...` returned
// 403 "Invalid request signature" on the 2026-08-06 live E2E.
function positionalVerifiedQueryString(url: string): string {
  const qs = url.slice(url.indexOf("?") + 1);
  const cut = qs.lastIndexOf("&sig="); // Python's rsplit("&sig=", 1)[0]
  return cut < 0 ? qs : qs.slice(0, cut);
}

test("a POSITIONAL DNS Provider (Glauca HexDNS) verifies our signature", () => {
  const { publicKeyPem, applyUrl } = signedFixture();
  const asGlaucaSeesIt = positionalVerifiedQueryString(applyUrl.url);
  assert.equal(
    asGlaucaSeesIt,
    applyUrl.payload,
    "everything before &sig= must be exactly the string we signed",
  );
  assert.equal(verifyQueryString(publicKeyPem, asGlaucaSeesIt, applyUrl.sig!), true);
});

test("REGRESSION: emitting key BEFORE sig is rejected by a positional verifier", () => {
  // The permanent trap for the 403 this commit fixes. Same signature, same
  // signed payload — only the emission order differs, which is precisely what
  // the live E2E proved by moving `key` after `sig` on an already-signed URL.
  const { publicKeyPem, applyUrl } = signedFixture();
  const keyBeforeSig =
    `${applyUrl.base}?${applyUrl.payload}` +
    `&key=${encodeURIComponent("_dck1")}` +
    `&sig=${encodeURIComponent(applyUrl.sig!)}`;

  assert.notEqual(
    positionalVerifiedQueryString(keyBeforeSig),
    applyUrl.payload,
    "key before sig contaminates a positional verifier's payload",
  );
  assert.equal(
    verifyQueryString(publicKeyPem, positionalVerifiedQueryString(keyBeforeSig), applyUrl.sig!),
    false,
    "a positional provider must reject the old ordering",
  );
});

test("REGRESSION: the old scheme (key inside the signed payload) is rejected by a DNS Provider", () => {
  // The permanent trap for the launch-blocking defect this branch fixed. If
  // someone re-adds `key` to the signed string, the signature stops covering
  // what a provider verifies and every signed apply is refused before consent.
  const { publicKeyPem, privateKeyPem, applyUrl } = signedFixture();
  const oldSchemePayload = `${applyUrl.payload}&key=${encodeURIComponent("_dck1")}`;
  const oldSchemeSig = signQueryString(privateKeyPem, oldSchemePayload);
  const oldSchemeUrl = `${applyUrl.base}?${oldSchemePayload}&sig=${encodeURIComponent(oldSchemeSig)}`;
  assert.equal(
    verifyQueryString(publicKeyPem, providerVerifiedQueryString(oldSchemeUrl), oldSchemeSig),
    false,
    "signing key= into the payload must fail provider-model verification",
  );
});

test("tampering with the payload breaks signature verification", () => {
  const { publicKeyPem, privateKeyPem } = generateKeyPair();
  const a = buildApplyUrl({
    urlSyncUX: SYNC,
    providerId: "p",
    serviceId: "s",
    domain: "customer.com",
    variables: { target: "good.example" },
    redirectUri: "http://localhost/callback",
    allowedRedirectHosts: ALLOW,
    signing: { privateKeyPem, keyHost: "_dck1" },
  });
  const tampered = a.payload.replace("good.example", "evil.example");
  assert.equal(verifyQueryString(publicKeyPem, tampered, a.sig!), false);
});

// ── Per-provider `sig`/`key` emission order ──────────────────────────────────
//
// The spec fixes WHAT is signed (query string minus sig and key, by name) but
// says nothing about WHERE they sit, so live providers disagree irreconcilably:
// Glauca HexDNS needs sig first (it verifies positionally), Cloudflare documents
// "Signature: Required. It also must be the last query parameter." The order is
// therefore an argument the caller picks from the DNS provider it discovered.

test("the default emission order is sig-then-key — the exact layout proven against Glauca HexDNS", () => {
  const { applyUrl } = signedFixture();
  assert.equal(DEFAULT_SIGNATURE_EMISSION_ORDER, "sig-then-key");
  // Byte-for-byte pin. The 2026-08-06 live E2E succeeded on precisely this
  // layout; anything that reshuffles it silently re-breaks a positional
  // verifier with a signature that still looks valid to us.
  assert.equal(
    applyUrl.payload,
    "domain=customer.com&host=status&target=t.example" +
      "&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&state=st8",
  );
  assert.equal(
    applyUrl.url,
    `${applyUrl.base}?${applyUrl.payload}` +
      `&sig=${encodeURIComponent(applyUrl.sig!)}` +
      `&key=_dck1`,
  );
});

test("an explicit sig-then-key order builds the identical URL to omitting the option", () => {
  // Proves the option is a true default rather than a second code path that can
  // drift away from the order the live proof rode.
  const { privateKeyPem } = generateKeyPair();
  const common = {
    urlSyncUX: SYNC,
    providerId: "example.com",
    serviceId: "domain-verification",
    domain: "customer.com",
    variables: { token: "abc" },
    redirectUri: "http://localhost/callback",
    allowedRedirectHosts: ALLOW,
  } as const;
  const implicit = buildApplyUrl({ ...common, signing: { privateKeyPem, keyHost: "_dck1" } });
  const explicit = buildApplyUrl({
    ...common,
    signing: { privateKeyPem, keyHost: "_dck1", emissionOrder: "sig-then-key" },
  });
  assert.equal(explicit.url, implicit.url);
});

test("the key-then-sig order puts sig LAST, as Cloudflare's Domain Connect reference requires", () => {
  const { applyUrl } = signedFixture("key-then-sig");
  assert.equal(
    applyUrl.url,
    `${applyUrl.base}?${applyUrl.payload}` +
      `&key=_dck1` +
      `&sig=${encodeURIComponent(applyUrl.sig!)}`,
  );
  const lastParam = applyUrl.url.slice(applyUrl.url.lastIndexOf("&") + 1);
  assert.match(lastParam, /^sig=/, "sig must be the final query parameter");
});

test("the signed payload is identical under both emission orders — only the trailer moves", () => {
  // The whole point: ordering is a transport detail, never a second signature
  // scheme. If a future edit makes the payload order-dependent, this fails.
  const { privateKeyPem } = generateKeyPair();
  const common = {
    urlSyncUX: SYNC,
    providerId: "example.com",
    serviceId: "domain-verification",
    domain: "customer.com",
    variables: { token: "abc" },
    redirectUri: "http://localhost/callback",
    state: "st8",
    allowedRedirectHosts: ALLOW,
  } as const;
  const sigFirst = buildApplyUrl({
    ...common,
    signing: { privateKeyPem, keyHost: "_dck1", emissionOrder: "sig-then-key" },
  });
  const sigLast = buildApplyUrl({
    ...common,
    signing: { privateKeyPem, keyHost: "_dck1", emissionOrder: "key-then-sig" },
  });
  assert.equal(sigLast.payload, sigFirst.payload);
  assert.equal(sigLast.sig, sigFirst.sig);
  assert.notEqual(sigLast.url, sigFirst.url);
});

test("a conformant DNS Provider verifies the signature under BOTH emission orders", () => {
  // Name-based filtering (the reference implementation, qsfilter(qs,['sig','key']))
  // is order-insensitive, so onboarding Cloudflare must not cost us anyone else.
  for (const order of ["sig-then-key", "key-then-sig"] as const) {
    const { publicKeyPem, applyUrl } = signedFixture(order);
    const asTheProviderSeesIt = providerVerifiedQueryString(applyUrl.url);
    assert.equal(asTheProviderSeesIt, applyUrl.payload, `payload recovered for ${order}`);
    assert.equal(
      verifyQueryString(publicKeyPem, asTheProviderSeesIt, applyUrl.sig!),
      true,
      `a conformant provider must accept ${order}`,
    );
    assert.equal(payloadFromUrl(applyUrl.url), applyUrl.payload, `payloadFromUrl for ${order}`);
  }
});

test("the Cloudflare order is rejected by a POSITIONAL verifier — proof the orders cannot be unified", () => {
  // Not a defect: it is the reason this is per-provider. Sending Cloudflare's
  // required layout to Glauca reproduces the 403 the 2026-08-06 E2E hit, so any
  // future "just pick one order" simplification fails here with the receipt.
  const { publicKeyPem, applyUrl } = signedFixture("key-then-sig");
  const asGlaucaSeesIt = positionalVerifiedQueryString(applyUrl.url);
  assert.notEqual(asGlaucaSeesIt, applyUrl.payload);
  assert.equal(verifyQueryString(publicKeyPem, asGlaucaSeesIt, applyUrl.sig!), false);
});

test("signatureEmissionOrderForDnsProvider selects sig-last for Cloudflare's discovered providerId", () => {
  // "cloudflare.com" is the providerId Cloudflare publishes in its own settings
  // JSON (docs/domain-connect-findings.md §9b).
  assert.equal(signatureEmissionOrderForDnsProvider("cloudflare.com"), "key-then-sig");
  assert.equal(signatureEmissionOrderForDnsProvider("  CloudFlare.com "), "key-then-sig");
});

test("signatureEmissionOrderForDnsProvider falls back to the proven default for every other provider", () => {
  for (const providerId of ["glauca.digital", "ionos.com", "domainchief.com", ""]) {
    assert.equal(
      signatureEmissionOrderForDnsProvider(providerId),
      DEFAULT_SIGNATURE_EMISSION_ORDER,
      `${providerId || "(empty)"} must keep the default order`,
    );
  }
});
