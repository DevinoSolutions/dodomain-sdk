import { defineConfig } from "tsup";

// F-010: @dodomain/core is private:true/unpublished, so it's inlined (not a
// runtime dependency) — noExternal pulls in the zero-import origin.ts
// constant + the zero-import message-types.ts consts this widget actually
// imports. platform:"browser" (not "node") since this ships into an
// INTEGRATOR's page bundle.
//
// zod-free by STRUCTURE, not by tree-shaking: an earlier attempt had this
// widget import from @dodomain/core/messages (which imports zod, for
// zDoDomainMessage) and relied on tree-shaking to drop the unused zod graph
// — verified empirically that neither esbuild's default tree-shaking NOR
// Rollup's (tsup's `treeshake: true` escalation) actually eliminated it
// (~535KB, ZodError/discriminatedUnion present in dist). Fix: the widget now
// imports from @dodomain/core/message-types, a module with ZERO imports —
// zod is not merely unused, it's absent from the import graph entirely, so
// no tree-shaking sophistication is required. See
// test/build.smoke.test.ts's "bundle is zod-free" check for the ongoing
// regression guard (current build: ~3KB).
export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  // TypeScript 7 shim (2026-08-26): tsup's dts step hardcodes
  // `baseUrl: compilerOptions.baseUrl || "."` (tsup/dist/rollup.js), and this
  // package's `typescript` is pinned to @typescript/typescript6 — the only JS
  // Compiler API left, since typescript@7 ships the Go binary alone. TS 6 turns
  // the baseUrl deprecation into the hard error TS5101, so tsup cannot emit a
  // .d.ts at all without this opt-out. It silences ONLY the injected baseUrl:
  // no tsconfig in this repo sets one (grep: zero hits), so nothing of ours is
  // being excused. Delete it together with the typescript6 pin in package.json
  // the moment tsup supports TypeScript 7. See packages/connect/package.json.
  dts: { compilerOptions: { ignoreDeprecations: "6.0" } },
  clean: true,
  sourcemap: true,
  platform: "browser",
  target: "es2020",
  noExternal: [/^@dodomain\/core/],
});
