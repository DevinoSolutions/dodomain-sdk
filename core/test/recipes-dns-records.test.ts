// The `dns-records` universal template, seen through the matcher: which record
// sets fall through the shaped templates to it, which slot each record lands
// in, and the record sets it must refuse even though a slot of the right type
// is free (an apex CNAME, an SPF as a plain TXT, a DMARC in an add slot).

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  compileToRecipe,
  isDkimKeyRecord,
  isSingletonTxtRecord,
  RecipeError,
} from "../src/recipes.ts";

const PROVIDER_ID = "dodomain.io";

// An SES sending set alone is email-sending's (recipes-template-family.test.ts);
// the inbound MX at the root is what no shaped template writes.
test("a sending set plus an inbound MX at the root compiles to dns-records with one group per record", () => {
  const recipe = compileToRecipe(
    [
      { type: "MX", name: "@", value: "inbound-smtp.us-east-1.amazonaws.com", priority: 20 },
      { type: "MX", name: "mail", value: "feedback-smtp.us-east-1.amazonses.com", priority: 10 },
      { type: "TXT", name: "mail", value: "v=spf1 include:amazonses.com ~all" },
      { type: "CNAME", name: "k1._domainkey", value: "k1.dkim.amazonses.com", ttl: 1800 },
      { type: "TXT", name: "_dmarc", value: "v=DMARC1; p=none" },
    ],
    PROVIDER_ID,
  );
  assert.equal(recipe.serviceId, "dns-records");
  assert.equal(recipe.host, undefined);
  // Groups come back in template order (spf, txtr, txt, a, aaaa, cname, mx, ...).
  assert.deepEqual(recipe.groupIds, ["spf1", "txtr1", "cname1", "mx1", "mx2"]);
  assert.deepEqual(recipe.variables, {
    mx1host: "@",
    mx1value: "inbound-smtp.us-east-1.amazonaws.com",
    mxonepriority: "20",
    mx2host: "mail",
    mx2value: "feedback-smtp.us-east-1.amazonses.com",
    mxtwopriority: "10",
    spf1host: "mail",
    spf1rules: "include:amazonses.com",
    cname1host: "k1._domainkey",
    cname1value: "k1.dkim.amazonses.com",
    txtr1host: "_dmarc",
    txtr1value: "v=DMARC1; p=none",
  });
});

test("a record set a shaped template expresses still compiles to that template, not dns-records", () => {
  const recipe = compileToRecipe([{ type: "CNAME", name: "www", value: "t.example" }], PROVIDER_ID);
  assert.equal(recipe.serviceId, "custom-subdomain-cname");
});

test("five CNAMEs fill five CNAME slots in order", () => {
  const records = ["a", "b", "c", "d", "e"].map((name) => ({
    type: "CNAME",
    name,
    value: `${name}.target.example`,
  }));
  const recipe = compileToRecipe(records, PROVIDER_ID);
  assert.equal(recipe.serviceId, "dns-records");
  assert.deepEqual(recipe.groupIds, ["cname1", "cname2", "cname3", "cname4", "cname5"]);
  assert.equal(recipe.variables.cname5host, "e");
  assert.equal(recipe.variables.cname5value, "e.target.example");
});

// Four apex A + www alone is a `website`; the `docs` CNAME is what no shaped
// template carries beside them.
test("apex A records plus www and docs CNAMEs compile to dns-records with the apex host as @", () => {
  const recipe = compileToRecipe(
    [
      { type: "A", name: "@", value: "185.199.108.153" },
      { type: "A", name: "@", value: "185.199.109.153" },
      { type: "A", name: "@", value: "185.199.110.153" },
      { type: "A", name: "@", value: "185.199.111.153" },
      { type: "CNAME", name: "www", value: "owner.github.io" },
      { type: "CNAME", name: "docs", value: "docs.example.net" },
    ],
    PROVIDER_ID,
  );
  assert.equal(recipe.serviceId, "dns-records");
  assert.deepEqual(recipe.groupIds, ["a1", "a2", "a3", "a4", "cname1", "cname2"]);
  assert.equal(recipe.variables.a1host, "@");
  assert.equal(recipe.variables.a4value, "185.199.111.153");
  assert.equal(recipe.variables.cname1host, "www");
});

test("DMARC and DKIM TXT records take replace slots; other TXT records take add slots", () => {
  const recipe = compileToRecipe(
    [
      { type: "TXT", name: "_dmarc.mail", value: "v=DMARC1; p=quarantine" },
      { type: "TXT", name: "s1._domainkey.mail", value: "k=rsa; p=MIIB" },
      { type: "TXT", name: "@", value: "google-site-verification=abc" },
      { type: "A", name: "app", value: "203.0.113.7" },
    ],
    PROVIDER_ID,
  );
  assert.equal(recipe.serviceId, "dns-records");
  assert.deepEqual(recipe.groupIds, ["txtr1", "txtr2", "txt1", "a1"]);
  assert.equal(recipe.variables.txtr1host, "_dmarc.mail");
  assert.equal(recipe.variables.txtr2host, "s1._domainkey.mail");
  assert.equal(recipe.variables.txt1value, "google-site-verification=abc");
});

test("an SPF record is never written as a plain TXT: one SPF slot per record, merged", () => {
  const recipe = compileToRecipe(
    [
      {
        type: "TXT",
        name: "@",
        value: "v=spf1 include:_spf.a.example include:_spf.b.example -all",
      },
      { type: "TXT", name: "bounce", value: "v=spf1 ip4:198.51.100.0/24 ~all" },
      { type: "A", name: "app", value: "203.0.113.7" },
    ],
    PROVIDER_ID,
  );
  assert.deepEqual(recipe.groupIds, ["spf1", "spf2", "a1"]);
  assert.equal(recipe.variables.spf1rules, "include:_spf.a.example include:_spf.b.example");
  assert.equal(recipe.variables.spf2host, "bounce");
  assert.equal(recipe.variables.spf2rules, "ip4:198.51.100.0/24");
  assert.ok(Object.keys(recipe.variables).every((k) => !k.startsWith("txt")));
});

test("an SPF carrying redirect= cannot be merged and is refused rather than written as a TXT", () => {
  assert.throws(
    () =>
      compileToRecipe(
        [
          { type: "TXT", name: "@", value: "v=spf1 redirect=_spf.example" },
          { type: "A", name: "app", value: "203.0.113.7" },
        ],
        PROVIDER_ID,
      ),
    RecipeError,
  );
});

test("an MX record without a priority is refused (the template cannot guess one)", () => {
  assert.throws(
    () => compileToRecipe([{ type: "MX", name: "mail", value: "mx.example" }], PROVIDER_ID),
    RecipeError,
  );
});

test("an apex CNAME is refused with the documented apex message, never put in a CNAME slot", () => {
  assert.throws(
    () => compileToRecipe([{ type: "CNAME", name: "@", value: "t.example" }], PROVIDER_ID),
    /non-apex host/,
  );
  assert.throws(
    () =>
      compileToRecipe(
        [
          { type: "CNAME", name: "@", value: "t.example" },
          { type: "A", name: "app", value: "203.0.113.7" },
        ],
        PROVIDER_ID,
      ),
    RecipeError,
  );
});

test("a record set larger than the slots of its type is refused", () => {
  const records = Array.from({ length: 9 }, (_, i) => ({
    type: "A",
    name: `h${i}`,
    value: `203.0.113.${i + 1}`,
  }));
  assert.throws(() => compileToRecipe(records, PROVIDER_ID), RecipeError);
});

test("isSingletonTxtRecord recognises DMARC, DKIM, MTA-STS and TLS-RPT by their value, not by host alone", () => {
  assert.equal(isSingletonTxtRecord("_dmarc", "v=DMARC1; p=none"), true);
  assert.equal(isSingletonTxtRecord("_dmarc", "google-site-verification=abc"), false);
  assert.equal(isSingletonTxtRecord("_mta-sts", "google-site-verification=abc"), false);
  assert.equal(isSingletonTxtRecord("sel._domainkey.mail", "google-site-verification=abc"), false);
  assert.equal(isSingletonTxtRecord("sel._domainkey.mail", "p=MIIB"), true);
  assert.equal(isSingletonTxtRecord("_mta-sts", "v=STSv1; id=1"), true);
  assert.equal(isSingletonTxtRecord("_smtp._tls", "v=TLSRPTv1; rua=mailto:x@example.com"), true);
  assert.equal(isSingletonTxtRecord("custom", "v=DKIM1; k=rsa; p=MIIB"), true);
  assert.equal(isSingletonTxtRecord("@", "google-site-verification=abc"), false);
  assert.equal(isSingletonTxtRecord("_dodomain-challenge", "dodomain-verify=tok"), false);
});

test("an unrelated TXT at _dmarc takes an add slot and never replaces the DMARC policy", () => {
  const recipe = compileToRecipe(
    [
      { type: "TXT", name: "_dmarc", value: "google-site-verification=abc" },
      { type: "A", name: "app", value: "203.0.113.7" },
    ],
    PROVIDER_ID,
  );
  assert.equal(recipe.serviceId, "dns-records");
  assert.deepEqual(recipe.groupIds, ["txt1", "a1"]);
  assert.equal(recipe.variables.txt1host, "_dmarc");
  assert.ok(Object.keys(recipe.variables).every((k) => !k.startsWith("txtr")));
});

test("a real DMARC record at _dmarc still takes the replace slot beside an unrelated TXT there", () => {
  const recipe = compileToRecipe(
    [
      { type: "TXT", name: "_dmarc", value: "v=DMARC1; p=reject" },
      { type: "TXT", name: "_dmarc", value: "google-site-verification=abc" },
    ],
    PROVIDER_ID,
  );
  assert.deepEqual(recipe.groupIds, ["txtr1", "txt1"]);
  assert.equal(recipe.variables.txtr1value, "v=DMARC1; p=reject");
  assert.equal(recipe.variables.txt1value, "google-site-verification=abc");
});

test("an SPF with a modifier after its terminal all is refused, never compiled with the tail dropped", () => {
  for (const value of [
    "v=spf1 include:a.example ip4:203.0.113.1 -all exp=why.example",
    "v=spf1 include:a.example -all redirect=other.example",
    "v=spf1 include:a.example ~all ip4:203.0.113.9",
  ]) {
    assert.throws(
      () =>
        compileToRecipe(
          [
            { type: "TXT", name: "mail", value },
            { type: "A", name: "app", value: "203.0.113.7" },
          ],
          PROVIDER_ID,
        ),
      /Domain Connect cannot apply mail/,
      value,
    );
  }
});

test("an SPF with exp= before all, or a sole include followed by a tail, is refused by name", () => {
  assert.throws(
    () =>
      compileToRecipe(
        [{ type: "TXT", name: "@", value: "v=spf1 include:a.example exp=why.example -all" }],
        PROVIDER_ID,
      ),
    /exp=why.example/,
  );
  assert.throws(
    () =>
      compileToRecipe(
        [{ type: "TXT", name: "@", value: "v=spf1 include:a.example -all exp=why.example" }],
        PROVIDER_ID,
      ),
    /exp=why.example/,
  );
});

test("DMARC with the whitespace the tag grammar permits still takes the replace slot", () => {
  for (const [name, value] of [
    ["_dmarc", "v = DMARC1; p=reject"],
    ["_dmarc.sub", "v= DMARC1; p=reject"],
    ["_dmarc", "  V =dmarc1 ;p=none"],
  ] as const) {
    assert.equal(isSingletonTxtRecord(name, value), true, `${name} ${value}`);
    const recipe = compileToRecipe([{ type: "TXT", name, value }], PROVIDER_ID);
    assert.deepEqual(recipe.groupIds, ["txtr1"], `${name} ${value}`);
  }
  assert.equal(isSingletonTxtRecord("_mta-sts", "v = STSv1; id=1"), true);
  assert.equal(isSingletonTxtRecord("_smtp._tls", "v = TLSRPTv1; rua=mailto:x@example.com"), true);
  assert.equal(isSingletonTxtRecord("s._domainkey", "v = DKIM1; k=rsa; p=MIIB"), true);
});

test("an explicit version that is not a singleton one is never a singleton, whatever else it carries", () => {
  assert.equal(isSingletonTxtRecord("s._domainkey", "v=APP1; p=not-a-key"), false);
  assert.equal(isSingletonTxtRecord("s._domainkey", "v = APP1; p=not-a-key"), false);
  assert.equal(isSingletonTxtRecord("_dmarc", "v=APP1; p=reject"), false);
  // No version tag at all: a DKIM key by its p= tag under _domainkey.
  assert.equal(isSingletonTxtRecord("s._domainkey", "k=rsa; p=MIIB"), true);
  assert.equal(isSingletonTxtRecord("s._domainkey", "google-site-verification=abc"), false);
  const recipe = compileToRecipe(
    [{ type: "TXT", name: "s._domainkey", value: "v=APP1; p=not-a-key" }],
    PROVIDER_ID,
  );
  assert.deepEqual(recipe.groupIds, ["txt1"]);
});

test("a quoted or split TXT is judged on its joined data, and a malformed segment beside p= is never a key", () => {
  // Quoted presentation form of a non-singleton version: still not one.
  assert.equal(isSingletonTxtRecord("s._domainkey", '"v=APP1; p=not-a-key"'), false);
  // Split strings join with nothing between them, as DNS does.
  assert.equal(isSingletonTxtRecord("_dmarc", '"v=DMARC1; p=re" "ject"'), true);
  assert.equal(isSingletonTxtRecord("s._domainkey", '"v=DKIM1; k=rsa; " "p=MIIB"'), true);
  assert.equal(isSingletonTxtRecord("s._domainkey", '"k=rsa; p=MI" "IB"'), true);
  assert.equal(isSingletonTxtRecord("s._domainkey", '"v=DKIM1; p=MIIB"'), true);
  // A segment that is not tag=value next to p= disqualifies the whole record.
  assert.equal(isSingletonTxtRecord("s._domainkey", "oops; p=MIIB"), false);
  assert.equal(isSingletonTxtRecord("s._domainkey", "google-site-verification=abc; p=MIIB"), false);
  assert.equal(isSingletonTxtRecord("_dmarc", "v=DMARC1; p=reject; not a tag"), false);
  // Broken quoting is never a singleton.
  assert.equal(isSingletonTxtRecord("s._domainkey", '"v=DKIM1; p=MIIB'), false);
  assert.equal(isSingletonTxtRecord("s._domainkey", 'k=rsa; "p=MIIB"'), false);
  for (const value of ['"v=APP1; p=not-a-key"', "oops; p=MIIB", '"k=rsa; p=MI" junk']) {
    const recipe = compileToRecipe([{ type: "TXT", name: "s._domainkey", value }], PROVIDER_ID);
    assert.deepEqual(recipe.groupIds, ["txt1"], value);
  }
});

test("a raw DKIM key with literal quotes inside a tag value is still a key", () => {
  const key = 'v=DKIM1; k=rsa; n="operations"; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A';
  assert.equal(isSingletonTxtRecord("s._domainkey", key), true);
  assert.equal(isSingletonTxtRecord("s._domainkey", 'k=rsa; n="a b"; p=MIIB'), true);
  // The quoted presentation form of the same key joins to the same data.
  assert.equal(isSingletonTxtRecord("s._domainkey", '"v=DKIM1; k=rsa; n=\\"ops\\"; p=MIIB"'), true);
  // A raw value is never quote-parsed: unbalanced literal quotes are just characters.
  assert.equal(isSingletonTxtRecord("s._domainkey", 'v=DKIM1; n=operations"; p=MIIB'), true);
  assert.equal(isSingletonTxtRecord("s._domainkey", 'v=DKIM1; n=6" rack; p=MIIB'), true);
  // Only a value that STARTS with a quote can have broken quoting.
  assert.equal(isSingletonTxtRecord("s._domainkey", '"v=DKIM1; p=MIIB'), false);
});

test("a raw RSA-2048-length key whose note holds an unbalanced literal quote still takes the replace slot", () => {
  const modulus = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA" + "x".repeat(348);
  for (const note of ['n=operations"', 'n=6" rack', 'n="operations"']) {
    const value = `v=DKIM1; k=rsa; ${note}; p=${modulus}`;
    assert.equal(isSingletonTxtRecord("s._domainkey", value), true, note);
    assert.equal(isDkimKeyRecord("s._domainkey", value), true, note);
    const recipe = compileToRecipe([{ type: "TXT", name: "s._domainkey", value }], PROVIDER_ID);
    assert.equal(recipe.serviceId, "email-authentication", note);
    assert.equal(recipe.variables.dkimTxt, value.slice("v=DKIM1; ".length), note);
  }
});

test("a malformed DKIM or DMARC value never reaches a replace-all slot, even under its canonical prefix", () => {
  const bad: [string, string][] = [
    ["s._domainkey", '"v=DKIM1; p=MIIB'],
    ["s._domainkey", "v=DKIM1; oops; p=MIIB"],
    ["_dmarc", "v=DMARC1; p=reject; not a tag"],
    ["_dmarc", '"v=DMARC1; p=reject'],
  ];
  for (const [name, value] of bad) {
    // Alone (the email-authentication shapes) and beside an MX (email-sending).
    for (const extra of [
      [],
      [{ type: "MX", name: "bounce", value: "mx.mailer.example", priority: 10 }],
    ]) {
      const recipe = compileToRecipe([{ type: "TXT", name, value }, ...extra], PROVIDER_ID);
      assert.equal(recipe.serviceId, "dns-records", `${name} ${value}`);
      assert.deepEqual(
        recipe.groupIds?.filter((g) => g.startsWith("txtr")),
        [],
        `${name} ${value}`,
      );
    }
  }
  // The well-formed records still compile to their template.
  assert.equal(
    compileToRecipe([{ type: "TXT", name: "s._domainkey", value: "v=DKIM1; p=MIIB" }], PROVIDER_ID)
      .serviceId,
    "email-authentication",
  );
});
