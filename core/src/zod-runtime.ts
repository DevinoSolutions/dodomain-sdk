// The ONE zod handle for packages/core — every core module that builds a schema
// imports `z` from HERE, not from "zod" directly, so the browser CSP
// accommodation below cannot be bypassed by a new file forgetting it.
//
// Why it exists: zod 4 JIT-compiles validators, and it decides whether it may
// by PROBING — `Function("")` inside a try/catch (zod/v4/core/util.js
// `allowsEval`). Under a Content-Security-Policy without 'unsafe-eval' the
// throw is caught and zod silently falls back to its interpreted path, so
// nothing breaks — but the browser still fires a `securitypolicyviolation` for
// the attempt. zod's own source says so verbatim:
//
//     // Skip the probe under `jitless`: strict CSPs report the caught
//     // `new Function` as a `securitypolicyviolation` even though the throw is
//     // swallowed.
//
// Measured, not theorised: the report-only soak logged that violation from our
// own bundle — `blocked-uri: eval`, `script-src`, source file
// /_next/static/chunks/<hash>.js, document /connect/<token> — 6 reports on
// 2026-09-07 (Sentry DODOMAIN-WEB-K). The hosted connect flow imports
// ./messages.ts for the postMessage contract, which is how zod reaches an
// integrator-embedded page. Left alone, flipping the CSP to enforce would put a
// console error on every load of the money path forever, and drown the reports
// that actually matter.
//
// The fix is zod's supported switch, NOT 'unsafe-eval' in the policy — widening
// script-src to allow eval to silence a report about eval would defeat the
// whole point of the policy.
//
// Guarded on `window` so it is a strict no-op everywhere zod is fast and there
// is no CSP: apps/web's server tree, the worker, and packages/node inside an
// INTEGRATOR's Node process (this module ships to them; it must not change
// their validation performance). Set at module scope, which is ordered
// correctly by ESM construction — `allowsEval` is lazy, so any schema that
// could consult it can only be built after this module has evaluated.
//
// That ordering only holds if the bundler RUNS this module, and ESM semantics
// do not guarantee that on their own. Its one consumed export is a pure
// re-export of zod's `z`, and the `config()` call is a side effect, so a
// `"sideEffects": false` package lets the bundler drop the body and wire every
// import straight to "zod". packages/core declared exactly that, and it
// happened: measured 2026-09-22, the config call was in none of the chunks
// prod's connect page loads while zod's probe sat in one, so the #210 "fix"
// never reached a browser — 11 reports / 5 users by then (DODOMAIN-WEB-K), from
// real integrator embeds. packages/core/package.json therefore lists this file
// in `sideEffects`, and zod-runtime.test.ts fails the build if it stops.
//
// Reaching the browser through core's own schemas was still not enough, because
// core is not the only thing that builds zod schemas there. zod decides
// `allowsEval` ONCE, the first time ANY `z.object()` is constructed by ANY copy
// of zod on the page (its config lives on `globalThis.__zod_globalConfig`, shared
// across copies), and the dashboard, /signin and the docs ship zod in a shared
// chunk that other modules reach before core's schemas ever load. Measured
// 2026-10-01: `__zod_globalConfig` read `{}` after load on /signin, /docs, the
// landing and even /connect, and DODOMAIN-WEB-K kept firing from real browsers
// on /dashboard, /dashboard/billing, /settings and /support (32 events from
// Chrome 150-154, Edge and Android WebView since 2026-09-22), source file the
// zod chunk. So every Next app now imports THIS module first thing in its
// `instrumentation-client.ts` — `import "@dodomain/core/zod-runtime"` — which
// Next requires before hydration, i.e. before any page or layout module can
// build a schema. zod-runtime.test.ts pins that import in all three apps.
import { config, z } from "zod";

if (typeof window !== "undefined") {
  config({ jitless: true });
}

export { z };
