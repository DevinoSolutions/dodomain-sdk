// T-18036 review, issue 5: the first keyless call may name its test app (the
// name the end user reads on the hosted connect page). Trimmed, 1 to 60
// characters, optional; zCreateKeylessSessionInput is the boundary schema.
import assert from "node:assert/strict";
import { test } from "node:test";

import { zCreateKeylessSessionInput } from "../src/schemas.ts";

const BODY = {
  domain: "shop.example.com",
  records: [{ type: "TXT", host: "_dodomain", value: "verify-1" }],
};

test("a keyless body with no appName parses and carries none", () => {
  const parsed = zCreateKeylessSessionInput.parse(BODY);
  assert.equal("appName" in parsed, false);
});

test("a keyless appName is trimmed and kept up to 60 characters", () => {
  assert.equal(
    zCreateKeylessSessionInput.parse({ ...BODY, appName: "  Acme Sites  " }).appName,
    "Acme Sites",
  );
  const sixty = "a".repeat(60);
  assert.equal(zCreateKeylessSessionInput.parse({ ...BODY, appName: sixty }).appName, sixty);
  // Surrounding spaces do not count against the limit.
  assert.equal(
    zCreateKeylessSessionInput.parse({ ...BODY, appName: `  ${sixty}  ` }).appName,
    sixty,
  );
});

test("a blank, too long or non-string keyless appName is refused on the appName field", () => {
  for (const appName of ["", "   ", "a".repeat(61), 42]) {
    const result = zCreateKeylessSessionInput.safeParse({ ...BODY, appName });
    assert.equal(result.success, false, JSON.stringify(appName));
    assert.deepEqual(
      result.error?.issues.map((issue) => issue.path[0]),
      ["appName"],
    );
  }
});
