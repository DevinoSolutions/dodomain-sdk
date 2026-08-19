import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { createRequire } from "node:module";
import { ensureConnectDist } from "./helpers/ensure-connect-dist.ts";

// Build-smoke (same shape as packages/connect's): the package builds, the
// dual artifacts exist, named exports + .d.ts types resolve — plus the
// DEPENDENCY-SHAPE VERIFY for this package's one structural decision (see
// tsup.config.ts): react and @dodomain/connect stay EXTERNAL, never inlined,
// checked against the real build output rather than trusted from config.
//
// pnpm/turbo always invoke a workspace's "test" script with cwd set to the
// package root, so process.cwd() is packages/react here.
const pkgDir = process.cwd();
const distDir = path.join(pkgDir, "dist");

test("tsup build emits dist/index.{js,cjs,d.ts}", { timeout: 120_000 }, () => {
  // The dts step resolves @dodomain/connect's published types from its dist.
  ensureConnectDist();
  // execFileSync + an argument array (no shell string interpolation) — shell
  // is only requested on win32, where pnpm resolves to a .cmd shim that
  // execFile can't invoke directly; every argument here is a static literal.
  execFileSync("pnpm", ["exec", "tsup"], {
    cwd: pkgDir,
    stdio: "inherit",
    shell: process.platform === "win32",
  });
  assert.ok(existsSync(path.join(distDir, "index.js")), "dist/index.js missing");
  assert.ok(existsSync(path.join(distDir, "index.cjs")), "dist/index.cjs missing");
  assert.ok(existsSync(path.join(distDir, "index.d.ts")), "dist/index.d.ts missing");
});

test("the built ESM bundle exports useDoDomainConnect, DoDomainConnectButton and the MOUNT_BLOCKED re-export", async () => {
  const mod: Record<string, unknown> = await import(
    pathToFileURL(path.join(distDir, "index.js")).href
  );
  assert.equal(typeof mod.useDoDomainConnect, "function");
  assert.equal(typeof mod.DoDomainConnectButton, "function");
  assert.equal(mod.MOUNT_BLOCKED, "MOUNT_BLOCKED");
});

test("the built CJS bundle exports useDoDomainConnect and DoDomainConnectButton", () => {
  const require = createRequire(import.meta.url);
  const mod: Record<string, unknown> = require(path.join(distDir, "index.cjs"));
  assert.equal(typeof mod.useDoDomainConnect, "function");
  assert.equal(typeof mod.DoDomainConnectButton, "function");
});

test("index.d.ts declares the hook, the button, and the re-exported widget vocabulary", () => {
  const dts = readFileSync(path.join(distDir, "index.d.ts"), "utf8");
  for (const name of [
    "useDoDomainConnect",
    "UseDoDomainConnectOptions",
    "UseDoDomainConnectResult",
    "DoDomainConnectButton",
    "DoDomainConnectButtonProps",
    // Re-exported from @dodomain/connect so React integrators can type
    // handlers without a second direct dependency.
    "MOUNT_BLOCKED",
    "ShowDoDomainOptions",
    "DoDomainWidgetError",
    "DoDomainCloseDetail",
    "DoDomainSessionState",
  ]) {
    assert.ok(dts.includes(name), `index.d.ts missing "${name}"`);
  }
});

test("DEPENDENCY-SHAPE VERIFY: react and @dodomain/connect are imported, never inlined (and the bundle stays zod-free)", () => {
  const js = readFileSync(path.join(distDir, "index.js"), "utf8");
  const cjs = readFileSync(path.join(distDir, "index.cjs"), "utf8");
  // The externals actually held: both bundles still REFERENCE the packages…
  assert.ok(/from\s*["']react["']/.test(js), 'index.js: no external `from "react"` import');
  assert.ok(
    /from\s*["']@dodomain\/connect["']/.test(js),
    'index.js: no external `from "@dodomain/connect"` import',
  );
  assert.ok(/require\(\s*["']react["']\s*\)/.test(cjs), 'index.cjs: no external require("react")');
  assert.ok(
    /require\(\s*["']@dodomain\/connect["']\s*\)/.test(cjs),
    'index.cjs: no external require("@dodomain/connect")',
  );
  for (const [label, bundle] of [
    ["index.js", js],
    ["index.cjs", cjs],
  ] as const) {
    // …and neither implementation leaked in: "backdrop" is the widget
    // implementation's DOM marker (this package's own source never says it),
    // and react.transitional.element is React 19's runtime element symbol.
    assert.ok(
      !bundle.includes("backdrop"),
      `${label}: @dodomain/connect's implementation leaked in`,
    );
    assert.ok(
      !bundle.includes("react.transitional.element"),
      `${label}: react's runtime leaked into the bundle`,
    );
    assert.ok(!bundle.includes("ZodError"), `${label}: zod leaked into the bundle`);
    assert.ok(
      bundle.length < 20_000,
      `${label}: ${bundle.length} bytes — far larger than this package's few hundred lines of glue, something got inlined`,
    );
  }
});
