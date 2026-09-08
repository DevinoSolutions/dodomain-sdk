import { defineConfig } from "tsup";

// F-010: @dodomain/core is private:true/unpublished, so a shipped SDK cannot
// declare it as a runtime `dependency` (npm couldn't resolve it for an
// external installer). noExternal inlines core + zod into dist so the
// published package is self-contained. node:crypto (core/webhook.ts) stays
// external — it's a Node builtin, not bundled.
export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  // RESOLVED at publish (2026-07-31): rollup-dts used to keep bare
  // `from "@dodomain/core/..."` / `from "zod"` imports in dist/index.d.ts
  // (noExternal only governs the esbuild JS bundle; `dts: { resolve: true }`
  // corrupted zod's inferred types, and scoped resolve can't flatten core's
  // raw-TS exports — PLAN-F-010 §8 has the full experiment log in git
  // history). The fix is structural, not config: the entry now types its
  // whole public surface against src/public-types.ts (zero imports), so the
  // emitted d.ts is self-contained by construction — guarded by the
  // "d.ts has no external imports" check in test/build.smoke.test.ts, with
  // src/schema-parity.check.ts pinning those public types to the core zod
  // schemas at typecheck time (F-008: one schema, no silent drift).
  // TypeScript 7 shim (2026-08-26) — same reason as packages/connect: tsup's
  // dts step hardcodes `baseUrl: compilerOptions.baseUrl || "."`, this
  // package's `typescript` is pinned to @typescript/typescript6 (typescript@7
  // ships no JS Compiler API), and TS 6 turns the baseUrl deprecation into the
  // hard error TS5101. Silences ONLY tsup's injected baseUrl — no tsconfig here
  // sets one. Delete with the typescript6 pin once tsup supports TypeScript 7.
  dts: { compilerOptions: { ignoreDeprecations: "6.0" } },
  clean: true,
  sourcemap: true,
  platform: "node",
  target: "node20",
  noExternal: [/^@dodomain\/core/, "zod"],
});
