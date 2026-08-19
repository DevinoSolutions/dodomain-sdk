import { defineConfig } from "tsup";

// Dependency-shape decision (mirrors the connect/core split, inverted):
// @dodomain/connect is PUBLISHED, so this package DEPENDS on it instead of
// inlining it — tsup's default externals (dependencies + peerDependencies)
// keep both react and @dodomain/connect out of the bundle. That keeps the
// artifact honest and tiny (~1KB of glue), guarantees an integrator's app
// bundles exactly ONE copy of the widget even when they also use
// @dodomain/connect directly, and lets a connect fix reach react users via a
// range bump without a @dodomain/react release. (connect inlines
// @dodomain/core only because core is private:true/unpublished — see
// packages/connect/tsup.config.ts; nothing here is private, so nothing is
// inlined.) test/build.smoke.test.ts asserts the externals hold against the
// real build output.
export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  sourcemap: true,
  platform: "browser",
  target: "es2020",
});
