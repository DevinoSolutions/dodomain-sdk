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
  dts: true,
  clean: true,
  sourcemap: true,
  platform: "browser",
  target: "es2020",
  noExternal: [/^@dodomain\/core/],
});
