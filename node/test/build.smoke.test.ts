import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { pathToFileURL } from "node:url";

// Build-smoke (PLAN-F-010 §5): the package builds, artifacts exist, named
// exports + .d.ts types resolve. The build itself is the unit under test —
// run it here rather than assume CI's separate `pnpm build` step already
// populated dist/ (that step runs AFTER unit tests in ci.yml).
//
// pnpm/turbo always invoke a workspace's "test" script with cwd set to the
// package root, so process.cwd() is packages/node here (same assumption the
// package's own "test": "... test/*.test.ts" script glob already relies on).
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

test("the built ESM bundle exports DoDomain, DoDomainError, verifyWebhook", async () => {
  const mod: Record<string, unknown> = await import(
    pathToFileURL(path.join(distDir, "index.js")).href
  );
  assert.equal(typeof mod.DoDomain, "function");
  assert.equal(typeof mod.DoDomainError, "function");
  assert.equal(typeof mod.verifyWebhook, "function");
});

test("the built CJS bundle exports the same three names", async () => {
  const mod: Record<string, unknown> = await import(
    pathToFileURL(path.join(distDir, "index.cjs")).href
  );
  assert.equal(typeof mod.DoDomain, "function");
  assert.equal(typeof mod.DoDomainError, "function");
  assert.equal(typeof mod.verifyWebhook, "function");
});

test("index.d.ts declares the same public names", () => {
  const dts = readFileSync(path.join(distDir, "index.d.ts"), "utf8");
  for (const name of [
    "DoDomain",
    "DoDomainError",
    "verifyWebhook",
    "DoDomainOptions",
    // The connections namespace + webhook envelope types (2026-08-17): a
    // partner types their receiver against these, so they have to survive dts
    // bundling, not just typecheck in-repo.
    "Connection",
    "ListConnectionsInput",
    "ListConnectionsResult",
    "DisconnectConnectionResult",
    "ReverifyConnectionResult",
    "WebhookEvent",
    "WebhookEventWire",
    // Full v1 parity (0.3.0). Same reason: an integrator types their rotation
    // job / endpoint provisioning against these, so they have to survive dts
    // bundling, not just typecheck in-repo.
    "IntegratorSession",
    "App",
    "ListAppsResult",
    "CheckDomainInput",
    "CheckDomainResult",
    "ProviderGuide",
    "WebhookEndpoint",
    "WebhookEndpointInput",
    "WebhookEndpointWithSecret",
    "DeleteWebhookEndpointResult",
    "RotateSecretKeyResult",
  ]) {
    assert.ok(dts.includes(name), `index.d.ts missing "${name}"`);
  }
});

test("the built package has no unresolved bare @dodomain/core import left over (core is inlined, not a runtime dep)", () => {
  const js = readFileSync(path.join(distDir, "index.js"), "utf8");
  assert.ok(
    !js.includes('"@dodomain/core'),
    "an un-inlined @dodomain/core import leaked into dist/index.js",
  );
});

// PUBLISH guard (2026-07-31, the F-010 "revisit at publish time" item): the
// emitted d.ts must be fully self-contained — rollup-dts keeps bare
// `from "@dodomain/core/..."` / `from "zod"` imports whenever a PUBLIC type
// leaks from core instead of src/public-types.ts, and an external
// `npm install @dodomain/node` consumer cannot resolve those (tsup.config.ts
// has the history). This is the check the tsup config's RESOLVED note points
// at.
test("index.d.ts and index.d.cts are self-contained — no external type imports survive dts bundling", () => {
  for (const file of ["index.d.ts", "index.d.cts"]) {
    const dts = readFileSync(path.join(distDir, file), "utf8");
    const externalImports = dts.match(
      /from\s+['"][^.'"][^'"]*['"]|import\(['"][^.'"][^'"]*['"]\)/g,
    );
    assert.deepEqual(
      externalImports ?? [],
      [],
      `${file} leaked external type imports an npm consumer cannot resolve`,
    );
  }
});
