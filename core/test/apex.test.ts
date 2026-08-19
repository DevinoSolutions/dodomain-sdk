// Unit tests for the single PSL-backed apex util (F-011). Pure function, no
// DNS/network — tldts's bundled Public Suffix List data drives these.

import { test } from "node:test";
import assert from "node:assert/strict";

import { apexOf } from "../src/apex.ts";

test("apexOf: multi-label public suffix (.co.uk) — the F-011 mis-zone case", () => {
  assert.equal(apexOf("status.customer.co.uk"), "customer.co.uk");
});

test("apexOf: multi-label public suffix (.com.au)", () => {
  assert.equal(apexOf("shop.example.com.au"), "example.com.au");
});

test("apexOf: ordinary 2-label apex under a deep subdomain", () => {
  assert.equal(apexOf("a.b.example.com"), "example.com");
});

test("apexOf: an already-bare apex is unchanged", () => {
  assert.equal(apexOf("example.com"), "example.com");
});

test("apexOf: a bare public suffix has no registrable label under it — falls back to the input", () => {
  assert.equal(apexOf("co.uk"), "co.uk");
});

test("apexOf: an unrecognised single-label host — falls back to the input", () => {
  assert.equal(apexOf("localhost"), "localhost");
});

test("apexOf: case-insensitive and trailing-dot-insensitive", () => {
  assert.equal(apexOf("EXAMPLE.COM."), "example.com");
});
