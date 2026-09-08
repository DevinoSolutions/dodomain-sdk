import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { globalConfig } from "zod/v4/core";

import { z } from "../src/zod-runtime.ts";

const SRC = join(dirname(fileURLToPath(import.meta.url)), "..", "src");

test("importing zod through zod-runtime leaves Node untouched — jitless is browser-only", () => {
  // This suite runs in Node, where there is no CSP and JIT-compiled validators
  // are simply faster. The accommodation is guarded on `window`, so the
  // integrator SDK (packages/node, which ships this module into THEIR process)
  // and apps/web's server tree keep zod at full speed. If this ever flips, the
  // guard has been dropped and every server-side parse got slower for a
  // browser-only reason.
  assert.equal(
    globalConfig.jitless,
    undefined,
    "jitless must stay unset outside the browser (typeof window === 'undefined' here)",
  );
  assert.equal(z.string().parse("still a working zod handle"), "still a working zod handle");
});

test("every core module that builds a schema goes through the one zod door", () => {
  // The companion to scripts/check-boundary-schema-bans.sh check #3, kept here
  // too so the rule survives a run of the unit suites alone: a core file that
  // imports zod directly produces schemas that never saw the jitless config,
  // and zod's Function("") probe — the CSP violation this whole arrangement
  // exists to stop (Sentry DODOMAIN-WEB-K, 2026-09-07) — quietly returns on
  // whichever page bundles it.
  const offenders = readdirSync(SRC, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".ts"))
    .map((entry) => ({ dir: entry.parentPath, name: entry.name }))
    .filter(({ name }) => name !== "zod-runtime.ts")
    .filter(({ dir, name }) =>
      /^\s*import .*from "zod"/m.test(readFileSync(join(dir, name), "utf8")),
    )
    .map(({ name }) => name);
  assert.deepEqual(
    offenders,
    [],
    'these files import zod directly; use `import { z } from "./zod-runtime.ts"`',
  );
});
