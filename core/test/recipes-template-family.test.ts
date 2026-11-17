// The purpose-scoped family (email-sending, website, site-verification, caa),
// seen through the matcher: which record sets reach each template, which
// group each record lands in, the host rules that keep them narrow (a MAIL
// FROM MX never at the root, a website rooted at a subdomain through `host=`),
// and that every record set a merged template already takes stays there.

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  DOMAIN_CONNECT_TEMPLATES,
  type DomainConnectTemplate,
} from "../src/domain-connect-templates.ts";
import { compileToRecipe } from "../src/recipes.ts";

const PROVIDER_ID = "dodomain.io";

// ── email-sending ───────────────────────────────────────────────────────────

test("an SES sending set compiles to email-sending in ONE apply, one group per record", () => {
  const recipe = compileToRecipe(
    [
      { type: "MX", name: "mail", value: "feedback-smtp.us-east-1.amazonses.com", priority: 10 },
      { type: "TXT", name: "mail", value: "v=spf1 include:amazonses.com ~all" },
      { type: "CNAME", name: "k1._domainkey", value: "k1.dkim.amazonses.com" },
      { type: "CNAME", name: "k2._domainkey", value: "k2.dkim.amazonses.com" },
      { type: "CNAME", name: "k3._domainkey", value: "k3.dkim.amazonses.com" },
      { type: "TXT", name: "_dmarc", value: "v=DMARC1; p=none" },
    ],
    PROVIDER_ID,
  );
  assert.equal(recipe.serviceId, "email-sending");
  assert.equal(recipe.host, undefined);
  assert.deepEqual(recipe.groupIds, [
    "dkim-cname-1",
    "dkim-cname-2",
    "dkim-cname-3",
    "dmarc",
    "mail-from-mx",
    "mail-from-spf",
  ]);
  assert.deepEqual(recipe.variables, {
    mailFromHost: "mail",
    mailFromMx: "feedback-smtp.us-east-1.amazonses.com",
    mailFromPriority: "10",
    mailFromSpfInclude: "amazonses.com",
    dkimSelector1: "k1",
    dkimTarget1: "k1.dkim.amazonses.com",
    dkimSelector2: "k2",
    dkimTarget2: "k2.dkim.amazonses.com",
    dkimSelector3: "k3",
    dkimTarget3: "k3.dkim.amazonses.com",
    dmarcTxt: "p=none",
  });
});

test("SPF at the root and SPF at the MAIL FROM name land in their own groups", () => {
  const recipe = compileToRecipe(
    [
      { type: "TXT", name: "bounce", value: "v=spf1 include:mailer.example ~all" },
      { type: "TXT", name: "@", value: "v=spf1 include:_spf.mailer.example ~all" },
      { type: "CNAME", name: "m1._domainkey", value: "m1.dkim.mailer.example" },
      { type: "CNAME", name: "m2._domainkey", value: "m2.dkim.mailer.example" },
    ],
    PROVIDER_ID,
  );
  assert.equal(recipe.serviceId, "email-sending");
  assert.equal(recipe.variables.spfInclude, "_spf.mailer.example");
  assert.equal(recipe.variables.mailFromHost, "bounce");
  assert.equal(recipe.variables.mailFromSpfInclude, "mailer.example");
});

test("a MAIL FROM MX is never written at the root: an inbound MX falls through to dns-records", () => {
  const recipe = compileToRecipe(
    [{ type: "MX", name: "@", value: "mx.mailer.example", priority: 10 }],
    PROVIDER_ID,
  );
  assert.equal(recipe.serviceId, "dns-records");
});

test("a MAIL FROM MX and SPF on DIFFERENT names cannot share the one MAIL FROM host", () => {
  const recipe = compileToRecipe(
    [
      { type: "MX", name: "mail", value: "feedback-smtp.us-east-1.amazonses.com", priority: 10 },
      { type: "TXT", name: "bounce", value: "v=spf1 include:amazonses.com ~all" },
    ],
    PROVIDER_ID,
  );
  assert.equal(recipe.serviceId, "dns-records");
});

test("a MAIL FROM name is never an underscore label", () => {
  const recipe = compileToRecipe(
    [{ type: "MX", name: "_bounce", value: "mx.mailer.example", priority: 10 }],
    PROVIDER_ID,
  );
  assert.equal(recipe.serviceId, "dns-records");
});

test("email-sending's dkim-txt takes a real-length key whose note has an unbalanced literal quote", () => {
  const mx = { type: "MX", name: "bounce", value: "mx.mailer.example", priority: 10 };
  const modulus = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA" + "x".repeat(348);
  for (const note of ['n=operations"', 'n=6" rack']) {
    const value = `v=DKIM1; k=rsa; ${note}; p=${modulus}`;
    const recipe = compileToRecipe(
      [{ type: "TXT", name: "s1._domainkey", value }, mx],
      PROVIDER_ID,
    );
    assert.equal(recipe.serviceId, "email-sending", note);
    assert.equal(recipe.variables.dkimTxt, value, note);
    assert.equal(recipe.variables.dkimTxtSelector, "s1", note);
  }
});

test("email-sending's dkim-txt takes a raw key with literal quotes, and refuses a malformed one", () => {
  const mx = { type: "MX", name: "bounce", value: "mx.mailer.example", priority: 10 };
  const key = 'v=DKIM1; k=rsa; n="operations"; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A';
  const ok = compileToRecipe([{ type: "TXT", name: "s1._domainkey", value: key }, mx], PROVIDER_ID);
  assert.equal(ok.serviceId, "email-sending");
  assert.equal(ok.variables.dkimTxt, key);
  for (const value of ['"v=DKIM1; p=MIIB', "v=DKIM1; oops; p=MIIB"]) {
    const recipe = compileToRecipe(
      [{ type: "TXT", name: "s1._domainkey", value }, mx],
      PROVIDER_ID,
    );
    assert.equal(recipe.serviceId, "dns-records", value);
    assert.equal(recipe.variables.dkimTxt, undefined, value);
  }
});

test("a non-key TXT at a DKIM selector never fills email-sending's replace-all dkim-txt group", () => {
  const key = "v=DKIM1; k=rsa; p=MIIB";
  const withKey = compileToRecipe(
    [{ type: "TXT", name: "s1._domainkey", value: key }],
    PROVIDER_ID,
  );
  assert.equal(withKey.serviceId, "email-authentication");
  const sending = compileToRecipe(
    [
      { type: "TXT", name: "s1._domainkey", value: "k=rsa; p=MIIB" },
      { type: "MX", name: "bounce", value: "mx.mailer.example", priority: 10 },
    ],
    PROVIDER_ID,
  );
  assert.equal(sending.serviceId, "email-sending");
  assert.equal(sending.variables.dkimTxt, "k=rsa; p=MIIB");
  for (const value of ["google-site-verification=abc", "v=APP1; p=not-a-key"]) {
    const recipe = compileToRecipe(
      [
        { type: "TXT", name: "s1._domainkey", value },
        { type: "MX", name: "bounce", value: "mx.mailer.example", priority: 10 },
      ],
      PROVIDER_ID,
    );
    assert.equal(recipe.serviceId, "dns-records", value);
    assert.ok(recipe.groupIds?.includes("txt1"), value);
    assert.equal(recipe.variables.dkimTxt, undefined, value);
  }
});

test("a wildcard or nested underscore name is never a MAIL FROM host, at any depth", () => {
  for (const name of ["*", "*.mail", "bounce._domainkey", "a._b.mail", "mail_from"]) {
    const recipe = compileToRecipe(
      [{ type: "MX", name, value: "mx.mailer.example", priority: 10 }],
      PROVIDER_ID,
    );
    assert.equal(recipe.serviceId, "dns-records", name);
  }
  // A real nested subdomain still is one.
  const nested = compileToRecipe(
    [
      { type: "MX", name: "bounce.eu", value: "mx.mailer.example", priority: 10 },
      { type: "TXT", name: "bounce.eu", value: "v=spf1 include:mailer.example ~all" },
    ],
    PROVIDER_ID,
  );
  assert.equal(nested.serviceId, "email-sending");
  assert.equal(nested.variables.mailFromHost, "bounce.eu");
});

test("two email-sending integrations at different MAIL FROM hosts are multiInstance applies", () => {
  for (const host of ["bounce-a", "bounce-b"]) {
    const recipe = compileToRecipe(
      [{ type: "MX", name: host, value: "mx.mailer.example", priority: 10 }],
      PROVIDER_ID,
    );
    assert.equal(recipe.serviceId, "email-sending");
    assert.equal(recipe.host, undefined);
  }
  const multi = (id: string) =>
    DOMAIN_CONNECT_TEMPLATES.find((t) => t.serviceId === id) as DomainConnectTemplate;
  assert.equal(multi("email-sending").multiInstance, true);
  assert.equal(multi("site-verification").multiInstance, true);
});

test("SPF + one DKIM CNAME + DMARC still compiles to the merged email-authentication", () => {
  const recipe = compileToRecipe(
    [
      { type: "TXT", name: "@", value: "v=spf1 include:_spf.mailer.example ~all" },
      { type: "CNAME", name: "s1._domainkey", value: "s1.dkim.mailer.example" },
      { type: "TXT", name: "_dmarc", value: "v=DMARC1; p=none" },
    ],
    PROVIDER_ID,
  );
  assert.equal(recipe.serviceId, "email-authentication");
});

// ── website ─────────────────────────────────────────────────────────────────

test("four apex A records and www compile to website", () => {
  const recipe = compileToRecipe(
    [
      { type: "A", name: "@", value: "185.199.108.153" },
      { type: "A", name: "@", value: "185.199.109.153" },
      { type: "A", name: "@", value: "185.199.110.153" },
      { type: "A", name: "@", value: "185.199.111.153" },
      { type: "CNAME", name: "www", value: "owner.github.io" },
    ],
    PROVIDER_ID,
  );
  assert.equal(recipe.serviceId, "website");
  assert.equal(recipe.host, undefined);
  assert.deepEqual(recipe.groupIds, ["a-a", "a-b", "a-c", "a-d", "www"]);
  assert.equal(recipe.variables.ipv4d, "185.199.111.153");
  assert.equal(recipe.variables.wwwTarget, "owner.github.io");
});

test("a site with its wildcard, ACME challenge CNAME and ownership TXT compiles to website", () => {
  const recipe = compileToRecipe(
    [
      { type: "A", name: "@", value: "203.0.113.10" },
      { type: "AAAA", name: "@", value: "2001:db8::10" },
      { type: "CNAME", name: "*", value: "edge.host.example" },
      { type: "CNAME", name: "_acme-challenge", value: "acme.host.example" },
      { type: "TXT", name: "_dodomain-challenge", value: "dodomain-verify=tok" },
    ],
    PROVIDER_ID,
  );
  assert.equal(recipe.serviceId, "website");
  assert.deepEqual(recipe.groupIds, ["a-a", "aaaa-a", "wildcard", "acme-challenge", "verify"]);
  assert.deepEqual(recipe.variables, {
    ipv4a: "203.0.113.10",
    ipv6a: "2001:db8::10",
    wildcardTarget: "edge.host.example",
    acmeTarget: "acme.host.example",
    token: "tok",
  });
});

test("a website on a subdomain applies under host=", () => {
  const recipe = compileToRecipe(
    [
      { type: "A", name: "shop", value: "203.0.113.10" },
      { type: "A", name: "shop", value: "203.0.113.11" },
      { type: "CNAME", name: "www.shop", value: "shop.host.example" },
    ],
    PROVIDER_ID,
  );
  assert.equal(recipe.serviceId, "website");
  assert.equal(recipe.host, "shop");
  assert.deepEqual(recipe.groupIds, ["a-a", "a-b", "www"]);
});

test("apex A + ownership TXT still compiles to the merged apex-a-with-verification", () => {
  const recipe = compileToRecipe(
    [
      { type: "A", name: "@", value: "203.0.113.10" },
      { type: "TXT", name: "_dodomain-challenge", value: "dodomain-verify=tok" },
    ],
    PROVIDER_ID,
  );
  assert.equal(recipe.serviceId, "apex-a-with-verification");
});

test("a lone wildcard or ACME CNAME stays custom-subdomain-cname at that host", () => {
  for (const name of ["*", "_acme-challenge"]) {
    const recipe = compileToRecipe([{ type: "CNAME", name, value: "t.example" }], PROVIDER_ID);
    assert.equal(recipe.serviceId, "custom-subdomain-cname");
    assert.equal(recipe.host, name);
  }
});

test("more A records than the website declares fall through to dns-records", () => {
  const records = Array.from({ length: 5 }, (_, i) => ({
    type: "A",
    name: "@",
    value: `203.0.113.${i + 1}`,
  }));
  assert.equal(compileToRecipe(records, PROVIDER_ID).serviceId, "dns-records");
});

// ── site-verification ───────────────────────────────────────────────────────

test("vendor ownership tokens at the root compile to site-verification, one group per vendor", () => {
  const recipe = compileToRecipe(
    [
      { type: "TXT", name: "@", value: "google-site-verification=abc123" },
      { type: "TXT", name: "@", value: "facebook-domain-verification=fb456" },
      { type: "TXT", name: "@", value: "MS=ms12345678" },
    ],
    PROVIDER_ID,
  );
  assert.equal(recipe.serviceId, "site-verification");
  assert.deepEqual(recipe.groupIds, ["google", "facebook", "microsoft"]);
  assert.deepEqual(recipe.variables, {
    googleToken: "abc123",
    facebookToken: "fb456",
    microsoftToken: "ms12345678",
  });
});

test("a token with no fixed vendor prefix, or a vendor prefix off the root, is not site-verification", () => {
  for (const record of [
    { type: "TXT", name: "@", value: "some-other-vendor=abc" },
    { type: "TXT", name: "shop", value: "google-site-verification=abc" },
  ]) {
    assert.equal(compileToRecipe([record], PROVIDER_ID).serviceId, "dns-records");
  }
});
