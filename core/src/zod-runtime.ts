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
// correctly by construction — `allowsEval` is lazy, so any schema that could
// consult it can only be built after this module has evaluated.
import { config, z } from "zod";

if (typeof window !== "undefined") {
  config({ jitless: true });
}

export { z };
