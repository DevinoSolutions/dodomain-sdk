// The committed provider-watch snapshot (docs/domain-connect/provider-watch.json,
// written by scripts/ci/dc-provider-watch.mjs) parses with the reader's schema.
// The writer is a zero-dependency .mjs that cannot import zod, so THIS is the
// contract between the two: a field renamed on either side fails here, in the
// core suite, not in the landing build at 05:10 UTC.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { DOMAIN_CONNECT_TEMPLATES } from "../src/domain-connect-templates.ts";
import { zProviderWatchSnapshot } from "../src/provider-watch.ts";

const SNAPSHOT_PATH = join(
  import.meta.dirname,
  "..",
  "..",
  "..",
  "docs",
  "domain-connect",
  "provider-watch.json",
);

test("the committed provider-watch snapshot parses with zProviderWatchSnapshot", () => {
  const raw: unknown = JSON.parse(readFileSync(SNAPSHOT_PATH, "utf8"));
  const parsed = zProviderWatchSnapshot.safeParse(raw);
  assert.ok(
    parsed.success,
    `docs/domain-connect/provider-watch.json no longer matches packages/core/src/provider-watch.ts: ${parsed.success ? "" : JSON.stringify(parsed.error.issues, null, 2)}`,
  );
  if (!parsed.success) return;

  // EVERY registry template is a column of /state-of-domain-connect (the page
  // derives its columns from snapshot.ourTemplates.serviceIds), so the writer's
  // OUR_SERVICE_IDS must stay in lockstep with DOMAIN_CONNECT_TEMPLATES — that
  // is what this asserts, rather than a literal that has to be hand-edited.
  // Templates awaiting an upstream merge simply read `not_served` until a
  // provider indexes them; a serviceId missing from the snapshot would render a
  // hole, not a verdict.
  const snapshot = parsed.data;
  assert.deepEqual(
    [...snapshot.ourTemplates.serviceIds].sort(),
    DOMAIN_CONNECT_TEMPLATES.map((template) => template.serviceId).sort(),
  );
  for (const provider of snapshot.providers) {
    for (const serviceId of snapshot.ourTemplates.serviceIds) {
      assert.ok(provider.templates[serviceId], `${provider.name} has no entry for ${serviceId}`);
    }
  }
  assert.ok(snapshot.providers.length >= 6, "every watched provider has a row");
});

test("a served template always carries a firstSeen date, and drift is only ever judged on a served one", () => {
  const snapshot = zProviderWatchSnapshot.parse(JSON.parse(readFileSync(SNAPSHOT_PATH, "utf8")));
  for (const provider of snapshot.providers) {
    for (const [serviceId, template] of Object.entries(provider.templates)) {
      const where = `${provider.name} / ${serviceId}`;
      if (template.state === "served") {
        assert.notEqual(template.firstSeen, null, `${where}: served without a firstSeen`);
        assert.equal(template.status, 200, `${where}: served but status is not 200`);
      } else {
        assert.equal(template.versionDrift, null, `${where}: drift judged on an unserved template`);
        assert.equal(template.servedVersion, null, `${where}: a version on an unserved template`);
      }
    }
  }
});
