// The widget <-> hosted-flow postMessage contract (F-008; split F-010) — the
// canonical zod-validated home for the `"dodomain:*"` message types,
// replacing the string literals the widget (packages/connect) and the
// hosted flow (apps/web's connect-flow.tsx) each independently hand-typed
// before F-008. Client-safe (no `node:` imports).
//
// R5 / bundle-size history: this file imports zod (for zDoDomainMessage) —
// the hosted-flow side (apps/web) is expected to use the full module. The
// embeddable widget (packages/connect) is bundle-size-sensitive (it ships
// into an INTEGRATOR's page, not DoDomain's own); F-008 had it import only
// `MESSAGE_TYPES`/`type DoDomainMessage` from THIS module, betting that a
// bundler's tree-shaking would eliminate the unused zDoDomainMessage/z graph.
//
// FIX(F-010): that bet did NOT pay off — verified empirically against a real
// tsup build (packages/connect/test/build.smoke.test.ts): BOTH esbuild's
// default tree-shaking AND Rollup's (tsup's documented escalation,
// `treeshake: true`) left the entire zod runtime in the widget bundle
// (~535KB, ZodError/discriminatedUnion present in dist/index.js). So
// MESSAGE_TYPES/EMBED_PARAM/EMBED_VALUE/ORIGIN_PARAM/DoDomainMessage moved to
// the zero-import ./message-types.ts (PLAN-F-008 §10.2's flagged fallback);
// this file re-exports them unchanged (so existing
// `from "@dodomain/core/messages"` imports keep working) and ADDS the zod
// validator. packages/connect now imports directly from
// "@dodomain/core/message-types", never from this file, so zod can never
// reach that bundle regardless of tree-shaking.
import { z } from "zod";

import {
  EMBED_PARAM,
  EMBED_VALUE,
  MESSAGE_TYPES,
  ORIGIN_PARAM,
  THEME_PARAM,
  type DoDomainMessage,
} from "./message-types.ts";

export { EMBED_PARAM, EMBED_VALUE, MESSAGE_TYPES, ORIGIN_PARAM, THEME_PARAM, type DoDomainMessage };

// `z.ZodType<DoDomainMessage>` pins this schema's inferred type to the
// independently hand-written DoDomainMessage (message-types.ts) — if the two
// ever drift, this annotation fails to typecheck, so "in sync" is
// compiler-enforced rather than just documented.
export const zDoDomainMessage: z.ZodType<DoDomainMessage> = z.discriminatedUnion("type", [
  z.object({ type: z.literal(MESSAGE_TYPES.VERIFIED), domain: z.string().optional() }),
  z.object({ type: z.literal(MESSAGE_TYPES.CLOSE) }),
  z.object({ type: z.literal(MESSAGE_TYPES.READY) }),
  z.object({ type: z.literal(MESSAGE_TYPES.ERROR), code: z.string() }),
  z.object({ type: z.literal(MESSAGE_TYPES.HEIGHT), height: z.number() }),
]);
