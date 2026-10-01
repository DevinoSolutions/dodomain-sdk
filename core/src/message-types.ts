// The zod-FREE half of the widget <-> hosted-flow postMessage contract
// (F-010 split — see messages.ts's header for the full history). Zero
// imports, so nothing here can ever pull zod into a consuming bundle,
// regardless of tree-shaking. @dodomain/connect (bundle-size-sensitive — it
// ships into an INTEGRATOR's page, not DoDomain's own) imports ONLY from
// this file, never from messages.ts.
//
// messages.ts re-exports everything below unchanged, so existing
// `from "@dodomain/core/messages"` imports (apps/web's connect-flow.tsx)
// keep working without any change — messages.ts is still the one place that
// ALSO exports the zod validator (zDoDomainMessage) for zod-tolerant
// consumers.

/**
 * postMessage type discriminants for the widget <-> hosted-flow contract.
 *
 * READY/ERROR are the load-detection handshake — a cross-origin iframe's
 * HTTP 404/500 fires neither `onerror` nor exposes readable content, so a
 * handshake postMessage from the flow is the only reliable "did this
 * actually load?" signal. The hosted flow (connect-flow.tsx) posts READY on
 * mount; the widget (packages/connect) starts a `loadTimeoutMs` timer on
 * show and clears it on the first READY/VERIFIED, else calls
 * `onError({type:"load-timeout"})`. ERROR carries a `code` (the same
 * verify()-failure vocabulary connect-flow.tsx already renders in its own
 * in-page banner) so the widget can call `onError({type:"session-error",code})`
 * — additive: an older widget build safely ignores both unknown types.
 */
export const MESSAGE_TYPES = {
  VERIFIED: "dodomain:verified",
  CLOSE: "dodomain:close",
  READY: "dodomain:ready",
  ERROR: "dodomain:error",
  // Content-height report (2026-08-04 embed polish): the hosted flow posts
  // its natural content height on mount and on every resize so the widget's
  // iframe can hug the content instead of sitting at a fixed height with
  // dead space below the footer. Additive — an older widget build safely
  // ignores the unknown type, and an older flow simply never posts it (the
  // widget keeps its initial height).
  HEIGHT: "dodomain:height",
  // Provider-popup handoff (2026-09-10). NOT part of the integrator-facing
  // contract: this one travels SAME-ORIGIN ONLY, from a hosted connect page
  // running inside the provider popup back to the hosted connect page that
  // opened it (the iframe). Cloudflare and every Domain Connect provider
  // refuse to be framed, so the one-click CTAs open a popup; until now the
  // iframe learned the outcome only from popup-closed/focus/visibilitychange
  // heuristics and sat on "one-click connect available" beside a popup that
  // already said the domain was live (owner screenshot 2026-09-03). The popup
  // now says so directly. Carries the session `token` so an unrelated connect
  // page in another same-origin window can never be mistaken for this one's
  // popup. The widget (packages/connect) has no use for it and falls through
  // its type switch, exactly as an older widget build does for any type it
  // does not know.
  POPUP_VERIFIED: "dodomain:popup-verified",
} as const;

// BroadcastChannel name for the popup handoff above, per session token. The
// popup posts on BOTH channels — `window.opener` and this one — because the
// opener leg is the fragile half: the popup navigates through a provider
// origin we do not control, and a document served with
// `Cross-Origin-Opener-Policy: same-origin` severs the opener permanently, so
// the window that comes back to us has `window.opener === null` through no
// fault of ours. It is also null by construction on the popup-blocked
// fallback path, where the CTA's `rel="noopener"` new tab takes over. A
// same-origin BroadcastChannel is unaffected by both. This is one message on
// two delivery paths, not a try-A-then-B ladder: the receiver's handler is
// idempotent and whichever copy arrives first does the work.
export const POPUP_HANDOFF_CHANNEL_PREFIX = "dodomain:connect-handoff:";

/** The per-session BroadcastChannel name both ends of the handoff open. */
export function popupHandoffChannelName(token: string): string {
  return `${POPUP_HANDOFF_CHANNEL_PREFIX}${token}`;
}

// ── The iframe URL contract ──────────────────────────────────────────────
// packages/connect builds `${base}/connect/${token}?${EMBED_PARAM}=${EMBED_VALUE}
// &${ORIGIN_PARAM}=<its own origin>`; the hosted connect page
// (apps/web/src/app/connect/[token]/connect-flow.tsx) reads both params — ONE
// set of query-param names instead of "embed"/"origin" string literals
// hand-typed on both sides. `ORIGIN_PARAM` carries the embedding integrator's
// origin so the hosted flow can scope postMessage's targetOrigin to it
// instead of "*" (PLAN-F-008 §2/§10.1 — see connect-flow.tsx for the
// documented "*" fallback when the param is absent).
export const EMBED_PARAM = "embed";
export const EMBED_VALUE = "1";
export const ORIGIN_PARAM = "origin";
// Host-app theme handoff (2026-08-04 embed polish): the widget passes the
// integrator page's theme so the embedded sheet matches it — a theme toggle
// inside someone else's modal is chrome noise, so the hosted flow hides its
// own toggle in embed mode and adopts this value instead. Only "light" and
// "dark" are honored; anything else falls back to the flow's own resolution.
export const THEME_PARAM = "theme";

// Hand-written (not `z.infer<typeof zDoDomainMessage>`, unlike before the
// split — that schema now lives in messages.ts, which imports zod, and this
// file must not). messages.ts's zDoDomainMessage is annotated
// `z.ZodType<DoDomainMessage>` against THIS type, so if the two shapes ever
// drift, messages.ts fails to typecheck — compiler-enforced sync, not just a
// documentation promise.
export type DoDomainMessage =
  | { type: typeof MESSAGE_TYPES.VERIFIED; domain?: string }
  | { type: typeof MESSAGE_TYPES.CLOSE }
  | { type: typeof MESSAGE_TYPES.READY }
  | { type: typeof MESSAGE_TYPES.ERROR; code: string }
  | { type: typeof MESSAGE_TYPES.HEIGHT; height: number }
  | { type: typeof MESSAGE_TYPES.POPUP_VERIFIED; token: string; domain: string };
