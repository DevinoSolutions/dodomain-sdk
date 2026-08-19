import { existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";

// This suite drives the REAL @dodomain/connect widget under jsdom (no mock
// that could drift from the actual postMessage/DOM contract), and the
// package's exports resolve to packages/connect/dist — which does not exist
// on a fresh clone, and in CI these tests run BEFORE the global Build step.
// Build it on demand instead of depending on step ordering.
//
// Callers must run this BEFORE importing ../src/index.ts, which is why the
// hook suite imports the source dynamically: a static import would resolve
// @dodomain/connect at module-link time, before any top-level code runs.
//
// execFileSync + an argument array (no shell string interpolation) — shell is
// only requested on win32, where pnpm resolves to a .cmd shim that execFile
// can't invoke directly; every argument is a static literal (same pattern as
// packages/connect/test/build.smoke.test.ts).
export function ensureConnectDist(): void {
  // pnpm/turbo always invoke a workspace's "test" script with cwd set to the
  // package root, so process.cwd() is packages/react here.
  const connectDir = path.resolve(process.cwd(), "..", "connect");
  if (existsSync(path.join(connectDir, "dist", "index.js"))) return;
  execFileSync("pnpm", ["exec", "tsup"], {
    cwd: connectDir,
    stdio: "inherit",
    shell: process.platform === "win32",
  });
}
