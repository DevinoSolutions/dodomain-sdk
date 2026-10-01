import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { globalConfig } from "zod/v4/core";

import { z } from "../src/zod-runtime.ts";

const PACKAGE_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SRC = join(PACKAGE_ROOT, "src");

test("packages/core declares zod-runtime as a side effect, so the bundler keeps the browser's jitless switch", () => {
  // zod-runtime's only consumed export is a re-export of zod's own `z`; the
  // `config({ jitless: true })` call is a module-scope side effect. Under
  // `"sideEffects": false` the bundler is entitled to drop that module's body
  // and wire every import straight to "zod" — and Turbopack did exactly that:
  // on 2026-09-22 the config call was in none of the 16 chunks prod's connect
  // page loads, while zod's `Function("")` probe sat in one, and the CSP kept
  // reporting it from real integrator embeds for two weeks after the "fix"
  // (Sentry DODOMAIN-WEB-K, 11 events / 5 users). Listing the file keeps it.
  const manifest = JSON.parse(readFileSync(join(PACKAGE_ROOT, "package.json"), "utf8")) as {
    sideEffects?: unknown;
  };
  assert.ok(
    Array.isArray(manifest.sideEffects) && manifest.sideEffects.includes("./src/zod-runtime.ts"),
    `packages/core/package.json "sideEffects" must be an array listing "./src/zod-runtime.ts" (got ${JSON.stringify(manifest.sideEffects)}). ` +
      "Anything else lets the bundler drop zod-runtime's config() call, and zod's eval probe returns to the connect page (DODOMAIN-WEB-K, 2026-09-22).",
  );
});

test("every Next app switches zod's eval probe off first thing in the browser, from its instrumentation-client", () => {
  // Core's own schemas going through zod-runtime only helps if core reaches the
  // page before anything else builds a schema, and on most pages it does not:
  // zod decides `allowsEval` the first time ANY `z.object()` is constructed, by
  // any copy of zod, and its config is one object on globalThis. Measured
  // 2026-10-01: `__zod_globalConfig` was `{}` after load on /signin, /docs, the
  // landing and /connect, and DODOMAIN-WEB-K was still firing from real browsers
  // on /dashboard, /billing, /settings and /support. Next requires each app's
  // instrumentation-client before hydration, so a side-effect import of
  // zod-runtime as that file's FIRST import runs before every page and layout
  // module. The exact specifier matters: it must be the subpath core lists in
  // `sideEffects`, or the bundler may drop the config() call again.
  const repoRoot = join(PACKAGE_ROOT, "..", "..");
  const clients = [
    "apps/web/src/instrumentation-client.ts",
    "apps/landing/src/instrumentation-client.ts",
    "apps/docs/instrumentation-client.ts",
  ];
  for (const relative of clients) {
    const source = readFileSync(join(repoRoot, relative), "utf8");
    const firstImport = /^import\s[^;]*;/m.exec(source)?.[0];
    assert.equal(
      firstImport,
      'import "@dodomain/core/zod-runtime";',
      `${relative} must open with \`import "@dodomain/core/zod-runtime";\` before any other import (got ${JSON.stringify(firstImport)}). ` +
        "Anything that imports first can build a zod schema before jitless is set, and the CSP logs zod's eval probe again (DODOMAIN-WEB-K).",
    );
  }
  const manifest = JSON.parse(readFileSync(join(PACKAGE_ROOT, "package.json"), "utf8")) as {
    exports?: Record<string, string>;
  };
  assert.equal(
    manifest.exports?.["./zod-runtime"],
    "./src/zod-runtime.ts",
    'packages/core must export "./zod-runtime" as the side-effect-listed file',
  );
});

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
