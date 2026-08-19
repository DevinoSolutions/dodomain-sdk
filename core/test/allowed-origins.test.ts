// App.allowedOrigins write-boundary validation (schemas.ts) — the rule that
// decides what an "origin" is before one reaches the column, and the
// normalization that decides what gets stored.
//
// These matter beyond tidiness: the list is meant to be compared against a
// browser-supplied `Origin` header the day enforcement ships, and a comparison
// only works if both sides serialize the same way. Storing "https://A.com:443/"
// next to "https://a.com" would produce a list that looks like two rules and
// matches like one.
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  ALLOWED_ORIGINS_MAX,
  normalizeAllowedOrigin,
  zAppAllowedOriginsInput,
} from "../src/schemas.ts";

void describe("normalizeAllowedOrigin", () => {
  void it("accepts a plain https origin unchanged", () => {
    assert.equal(normalizeAllowedOrigin("https://app.example.com"), "https://app.example.com");
  });

  void it("keeps a non-default port, because the port is part of the origin", () => {
    assert.equal(
      normalizeAllowedOrigin("https://app.example.com:8443"),
      "https://app.example.com:8443",
    );
  });

  void it("drops the DEFAULT port, so :443 and bare can never sit in one list as two entries", () => {
    assert.equal(normalizeAllowedOrigin("https://app.example.com:443"), "https://app.example.com");
    assert.equal(normalizeAllowedOrigin("http://localhost:80"), "http://localhost");
  });

  void it("lowercases the host, since origin comparison is case-insensitive on the authority", () => {
    assert.equal(normalizeAllowedOrigin("https://APP.Example.COM"), "https://app.example.com");
  });

  void it("treats a lone trailing slash as the empty path and still accepts it", () => {
    assert.equal(normalizeAllowedOrigin("https://app.example.com/"), "https://app.example.com");
  });

  void it("refuses a URL with a path — truncating it would store something the integrator never typed", () => {
    assert.equal(normalizeAllowedOrigin("https://app.example.com/embed"), null);
  });

  void it("refuses query and fragment for the same reason a path is refused", () => {
    assert.equal(normalizeAllowedOrigin("https://app.example.com/?a=1"), null);
    assert.equal(normalizeAllowedOrigin("https://app.example.com/#x"), null);
  });

  void it("refuses embedded credentials", () => {
    assert.equal(normalizeAllowedOrigin("https://user:pw@app.example.com"), null);
  });

  void it("refuses plain http on a PUBLIC host — the whole point of listing an origin is that it is the real one", () => {
    assert.equal(normalizeAllowedOrigin("http://app.example.com"), null);
  });

  void it("allows http on loopback, because an integrator wires this up against their dev server before they own a certificate", () => {
    assert.equal(normalizeAllowedOrigin("http://localhost:3000"), "http://localhost:3000");
    assert.equal(normalizeAllowedOrigin("http://127.0.0.1:3000"), "http://127.0.0.1:3000");
  });

  void it("refuses a wildcard, because no matcher exists to give it meaning yet", () => {
    assert.equal(normalizeAllowedOrigin("https://*.example.com"), null);
  });

  void it("refuses a bare hostname with no scheme — that is a host, not an origin", () => {
    assert.equal(normalizeAllowedOrigin("app.example.com"), null);
  });

  void it("refuses a non-web scheme", () => {
    assert.equal(normalizeAllowedOrigin("ftp://app.example.com"), null);
    assert.equal(normalizeAllowedOrigin("javascript:alert(1)"), null);
  });

  void it("refuses empty and whitespace-only input", () => {
    assert.equal(normalizeAllowedOrigin(""), null);
    assert.equal(normalizeAllowedOrigin("   "), null);
  });

  void it("trims surrounding whitespace rather than refusing a pasted value", () => {
    assert.equal(normalizeAllowedOrigin("  https://app.example.com  "), "https://app.example.com");
  });
});

void describe("zAppAllowedOriginsInput", () => {
  void it("normalizes every entry on the way in", () => {
    const parsed = zAppAllowedOriginsInput.parse(["https://APP.example.com:443/"]);
    assert.deepEqual(parsed, ["https://app.example.com"]);
  });

  void it("de-duplicates AFTER normalizing, so two spellings of one origin collapse to one rule", () => {
    const parsed = zAppAllowedOriginsInput.parse([
      "https://app.example.com",
      "https://APP.example.com:443",
    ]);
    assert.deepEqual(parsed, ["https://app.example.com"]);
  });

  void it("preserves order, so the list reads back the way it was built", () => {
    const parsed = zAppAllowedOriginsInput.parse([
      "https://b.example.com",
      "https://a.example.com",
    ]);
    assert.deepEqual(parsed, ["https://b.example.com", "https://a.example.com"]);
  });

  void it("accepts an empty list — that is the state every app starts in", () => {
    assert.deepEqual(zAppAllowedOriginsInput.parse([]), []);
  });

  void it("rejects the whole list when ONE entry is not an origin, and names the offender in the message", () => {
    const result = zAppAllowedOriginsInput.safeParse([
      "https://ok.example.com",
      "https://bad.example.com/path",
    ]);
    assert.equal(result.success, false);
    assert.match(result.error.issues[0]?.message ?? "", /bad\.example\.com\/path/);
  });

  void it(`refuses more than ${ALLOWED_ORIGINS_MAX} origins so the column stays a list`, () => {
    const tooMany = Array.from(
      { length: ALLOWED_ORIGINS_MAX + 1 },
      (_, i) => `https://app${i}.example.com`,
    );
    assert.equal(zAppAllowedOriginsInput.safeParse(tooMany).success, false);
    assert.equal(zAppAllowedOriginsInput.safeParse(tooMany.slice(0, -1)).success, true);
  });
});
