// Callback handling + the "redirect is not proof of success" rule, plus the
// records[] -> constrained-recipe compilation that the Domain Connect path requires.
//
// D-005 discharge (tier-2 build, 2026-07-11): compileToRecipe takes providerId
// as an ARGUMENT — core reads no process.env. These tests pass an explicit id
// and assert it lands on the compiled recipe untouched.

import { test } from "node:test";
import assert from "node:assert/strict";
import { compileToRecipe, RecipeError, VERIFY_PREFIX } from "../src/recipes.ts";

const PROVIDER_ID = "dodomain.io";

test("compiles a single CNAME into the custom-subdomain-cname recipe", () => {
  const r = compileToRecipe(
    [{ type: "CNAME", name: "status", value: "cname.uptimely.io" }],
    PROVIDER_ID,
  );
  assert.equal(r.serviceId, "custom-subdomain-cname");
  assert.equal(r.host, "status");
  assert.deepEqual(r.variables, { target: "cname.uptimely.io" });
});

test("compiles a prefixed TXT into the domain-verification recipe", () => {
  const r = compileToRecipe(
    [{ type: "TXT", name: "_dodomain-challenge", value: `${VERIFY_PREFIX}tok123` }],
    PROVIDER_ID,
  );
  assert.equal(r.serviceId, "domain-verification");
  assert.equal(r.host, undefined);
  assert.deepEqual(r.variables, { token: "tok123" });
});

test("providerId is the caller's argument, never an env read (D-005)", () => {
  const r = compileToRecipe(
    [{ type: "CNAME", name: "www", value: "target.example" }],
    "custom-provider.example",
  );
  assert.equal(r.providerId, "custom-provider.example");
});

test("refuses a CNAME at the apex (protocol constraint)", () => {
  assert.throws(
    () => compileToRecipe([{ type: "CNAME", name: "@", value: "x.example" }], PROVIDER_ID),
    RecipeError,
  );
});

test("refuses an unprefixed (arbitrary) TXT value", () => {
  assert.throws(
    () => compileToRecipe([{ type: "TXT", name: "_x", value: "anything goes" }], PROVIDER_ID),
    RecipeError,
  );
});

test("refuses a record set no template expresses (no arbitrary records[] over Domain Connect)", () => {
  // SPF with no include + an MX: MX is in no template (v1 exclusion) and a
  // bare `~all` carries no mechanism to merge.
  assert.throws(
    () =>
      compileToRecipe(
        [
          { type: "TXT", name: "@", value: "v=spf1 ~all" },
          { type: "MX", name: "@", value: "mx.example" },
        ],
        PROVIDER_ID,
      ),
    RecipeError,
  );
  // Two records that each match a template on their own but no template together.
  assert.throws(
    () =>
      compileToRecipe(
        [
          { type: "CNAME", name: "www", value: "t.example" },
          { type: "CNAME", name: "blog", value: "t.example" },
        ],
        PROVIDER_ID,
      ),
    RecipeError,
  );
});

test("refuses unsupported record types", () => {
  assert.throws(
    () => compileToRecipe([{ type: "MX", name: "@", value: "mx.example" }], PROVIDER_ID),
    RecipeError,
  );
});

test("refuses an empty record set", () => {
  assert.throws(() => compileToRecipe([], PROVIDER_ID), RecipeError);
});

// ── multi-record templates (Stage 9: the registry matcher) ──────────────────

test("CNAME + the ownership TXT UNDER it -> custom-subdomain-cname-with-verification, host derived from the CNAME", () => {
  const r = compileToRecipe(
    [
      { type: "TXT", name: "_dodomain-challenge.status", value: `${VERIFY_PREFIX}tok` },
      { type: "CNAME", name: "status", value: "cname.uptimely.io" },
    ],
    PROVIDER_ID,
  );
  assert.equal(r.serviceId, "custom-subdomain-cname-with-verification");
  assert.equal(r.host, "status");
  assert.deepEqual(r.variables, { target: "cname.uptimely.io", token: "tok" });
  assert.equal(r.groupIds, undefined, "every shape filled ⇒ no groupId (apply all groups)");
});

test("CNAME + an ownership TXT at the ZONE apex is NOT the with-verification template (the TXT must hang off the host)", () => {
  assert.throws(
    () =>
      compileToRecipe(
        [
          { type: "CNAME", name: "status", value: "cname.uptimely.io" },
          { type: "TXT", name: "_dodomain-challenge", value: `${VERIFY_PREFIX}tok` },
        ],
        PROVIDER_ID,
      ),
    RecipeError,
  );
});

test("apex A + TXT -> apex-a-with-verification with only the filled groups; adding AAAA fills them all", () => {
  const r = compileToRecipe(
    [
      { type: "A", name: "@", value: "203.0.113.10" },
      { type: "TXT", name: "_dodomain-challenge", value: `${VERIFY_PREFIX}tok` },
    ],
    PROVIDER_ID,
  );
  assert.equal(r.serviceId, "apex-a-with-verification");
  assert.equal(r.host, undefined);
  assert.deepEqual(r.variables, { ipv4: "203.0.113.10", token: "tok" });
  assert.deepEqual(r.groupIds, ["apex-a", "verify"]);

  const full = compileToRecipe(
    [
      { type: "AAAA", name: "@", value: "2001:db8::10" },
      { type: "A", name: "@", value: "203.0.113.10" },
      { type: "TXT", name: "_dodomain-challenge", value: `${VERIFY_PREFIX}tok` },
    ],
    PROVIDER_ID,
  );
  assert.deepEqual(full.variables, { ipv6: "2001:db8::10", ipv4: "203.0.113.10", token: "tok" });
  assert.equal(full.groupIds, undefined);
});

test("apex A without the ownership TXT is refused (the TXT is the non-optional shape)", () => {
  assert.throws(
    () => compileToRecipe([{ type: "A", name: "@", value: "203.0.113.10" }], PROVIDER_ID),
    RecipeError,
  );
});

test("SPF include + DKIM CNAME + DMARC -> email-authentication, selector extracted from the DKIM host", () => {
  const r = compileToRecipe(
    [
      {
        type: "TXT",
        name: "_dmarc",
        value: "v=DMARC1; p=quarantine; rua=mailto:dmarc@mailer.example",
      },
      { type: "CNAME", name: "resend._domainkey", value: "resend.dkim.mailer.example" },
      { type: "TXT", name: "@", value: "v=spf1 include:_spf.mailer.example ~all" },
    ],
    PROVIDER_ID,
  );
  assert.equal(r.serviceId, "email-authentication");
  assert.equal(r.host, undefined);
  assert.deepEqual(r.variables, {
    dmarcTxt: "p=quarantine; rua=mailto:dmarc@mailer.example",
    dkimSelector: "resend",
    dkimTarget: "resend.dkim.mailer.example",
    spfInclude: "_spf.mailer.example",
  });
  assert.deepEqual(
    r.groupIds,
    ["spf", "dkim-cname", "dmarc"],
    "dkim-txt is the one unfilled group",
  );
});

test("a DKIM key published as TXT fills the dkim-txt group instead; the fixed prefix is byte-exact", () => {
  const r = compileToRecipe(
    [{ type: "TXT", name: "s1._domainkey", value: "v=DKIM1; k=rsa; p=MIGfMA0G" }],
    PROVIDER_ID,
  );
  assert.equal(r.serviceId, "email-authentication");
  assert.deepEqual(r.variables, { dkimSelector: "s1", dkimTxt: "k=rsa; p=MIGfMA0G" });
  assert.deepEqual(r.groupIds, ["dkim-txt"]);
  // "v=DKIM1;k=rsa" (no space) could be applied but would never verify byte-exactly — refused.
  assert.throws(
    () =>
      compileToRecipe(
        [{ type: "TXT", name: "s1._domainkey", value: "v=DKIM1;k=rsa;p=MIGf" }],
        PROVIDER_ID,
      ),
    RecipeError,
  );
});

test("a CNAME at <selector>._domainkey is DKIM, not a custom subdomain (registry order is load-bearing)", () => {
  const r = compileToRecipe(
    [{ type: "CNAME", name: "s1._domainkey", value: "s1.dkim.mailer.example" }],
    PROVIDER_ID,
  );
  assert.equal(r.serviceId, "email-authentication");
});

test("two DKIM records with DIFFERENT selectors cannot share one template application", () => {
  assert.throws(
    () =>
      compileToRecipe(
        [
          { type: "CNAME", name: "s1._domainkey", value: "s1.dkim.mailer.example" },
          { type: "CNAME", name: "s2._domainkey", value: "s2.dkim.mailer.example" },
        ],
        PROVIDER_ID,
      ),
    RecipeError,
  );
});

test("an SPF record with more than one mechanism is entered by hand, never merged blind", () => {
  assert.throws(
    () =>
      compileToRecipe(
        [{ type: "TXT", name: "@", value: "v=spf1 include:a.example ip4:203.0.113.10 ~all" }],
        PROVIDER_ID,
      ),
    RecipeError,
  );
});

test("MX is never applied over Domain Connect, even beside a full email-authentication set", () => {
  assert.throws(
    () =>
      compileToRecipe(
        [
          { type: "TXT", name: "@", value: "v=spf1 include:_spf.mailer.example ~all" },
          { type: "MX", name: "@", value: "mx.mailer.example" },
        ],
        PROVIDER_ID,
      ),
    RecipeError,
  );
});
