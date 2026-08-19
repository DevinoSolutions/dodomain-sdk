import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { createRequire } from "node:module";

// Build-smoke (PLAN-F-010 §5): the package builds, artifacts exist, named
// exports + .d.ts types resolve. Also the F-010 BUILD-VERIFY itself: the
// widget bundle must be zod-free (packages/core/src/messages.ts imports zod
// for zDoDomainMessage; this widget imports only the plain-const/type-only
// half of that module — see messages.ts's and src/index.ts's module docs).
// This is the "real bundle output" check those comments point at.
//
// pnpm/turbo always invoke a workspace's "test" script with cwd set to the
// package root, so process.cwd() is packages/connect here.
const pkgDir = process.cwd();
const distDir = path.join(pkgDir, "dist");

test("tsup build emits dist/index.{js,cjs,d.ts}", { timeout: 120_000 }, () => {
  // execFileSync + an argument array (no shell string interpolation) — shell
  // is only requested on win32, where pnpm resolves to a .cmd shim that
  // execFile can't invoke directly; every argument here is a static literal,
  // never attacker/user-controlled, so this carries no injection surface.
  execFileSync("pnpm", ["exec", "tsup"], {
    cwd: pkgDir,
    stdio: "inherit",
    shell: process.platform === "win32",
  });
  assert.ok(existsSync(path.join(distDir, "index.js")), "dist/index.js missing");
  assert.ok(existsSync(path.join(distDir, "index.cjs")), "dist/index.cjs missing");
  assert.ok(existsSync(path.join(distDir, "index.d.ts")), "dist/index.d.ts missing");
});

test("the built ESM bundle exports showDoDomain", async () => {
  const mod: Record<string, unknown> = await import(
    pathToFileURL(path.join(distDir, "index.js")).href
  );
  assert.equal(typeof mod.showDoDomain, "function");
});

test("the built CJS bundle exports showDoDomain", () => {
  // require(), not dynamic import(): this is a platform:"browser" build (see
  // tsup.config.ts), so esbuild reasonably omits the "Annotate the CommonJS
  // export names for ESM import in node" shim it adds for platform:"node"
  // builds (packages/node's dist/index.cjs has it; this one doesn't) — that
  // shim only matters for Node's cjs-module-lexer/ESM-interop, a consumption
  // path a browser widget's CJS build isn't meant for. A real CJS consumer
  // (e.g. a bundler resolving `require("@dodomain/connect")`) uses plain
  // require() and sees the export correctly either way — verified below.
  const require = createRequire(import.meta.url);
  const mod: Record<string, unknown> = require(path.join(distDir, "index.cjs"));
  assert.equal(typeof mod.showDoDomain, "function");
});

test("index.d.ts declares showDoDomain / ShowDoDomainOptions / DoDomainWidgetError", () => {
  const dts = readFileSync(path.join(distDir, "index.d.ts"), "utf8");
  for (const name of [
    "showDoDomain",
    "ShowDoDomainOptions",
    "DoDomainWidgetError",
    // 2026-08-17 additions — the typed mount failure + stateful close.
    "MOUNT_BLOCKED",
    "DoDomainSessionState",
    "DoDomainCloseDetail",
  ]) {
    assert.ok(dts.includes(name), `index.d.ts missing "${name}"`);
  }
});

test("the built ESM bundle exports the MOUNT_BLOCKED code partners switch on", async () => {
  const mod: Record<string, unknown> = await import(
    pathToFileURL(path.join(distDir, "index.js")).href
  );
  assert.equal(mod.MOUNT_BLOCKED, "MOUNT_BLOCKED");
});

test("F-010 BUILD-VERIFY: the widget bundle is zod-free (R5 tree-shaking claim, checked against real output)", () => {
  const js = readFileSync(path.join(distDir, "index.js"), "utf8");
  const cjs = readFileSync(path.join(distDir, "index.cjs"), "utf8");
  for (const [label, bundle] of [
    ["index.js", js],
    ["index.cjs", cjs],
  ] as const) {
    assert.ok(
      !/from\s+["']zod["']/.test(bundle),
      `${label}: a "from \\"zod\\"" import leaked into the bundle`,
    );
    assert.ok(
      !/require\(\s*["']zod["']\s*\)/.test(bundle),
      `${label}: a require("zod") call leaked into the bundle`,
    );
    // zod v4's runtime is unmistakable in a bundle by these identifiers even
    // if the import specifier itself got renamed/inlined by the bundler.
    assert.ok(
      !bundle.includes("ZodError"),
      `${label}: zod's ZodError class leaked into the bundle`,
    );
    assert.ok(
      !bundle.includes("discriminatedUnion"),
      `${label}: zod's discriminatedUnion (zDoDomainMessage) leaked into the bundle`,
    );
  }
});
