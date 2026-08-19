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

test("refuses multi-record sets (no arbitrary records[] over Domain Connect)", () => {
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
});

test("refuses unsupported record types", () => {
  assert.throws(
    () => compileToRecipe([{ type: "MX", name: "@", value: "mx.example" }], PROVIDER_ID),
    RecipeError,
  );
});
