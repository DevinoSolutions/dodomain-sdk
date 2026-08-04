// @dodomain/connect — the embeddable browser widget.
// Opens the hosted connect page in a modal iframe and relays lifecycle events.
// Integrator branding (App.name/logoUrl/brandColor, 2026-07-21) reaches the
// end user THROUGH the hosted flow this iframe renders — the widget draws no
// flow chrome of its own, so it needs no branding API and no postMessage
// contract change (message-types stays as-is).
//
//   import { showDoDomain } from "@dodomain/connect";
//   const session = await fetch("/my-api/create-session").then(r => r.json());
//   showDoDomain({ token: session.token, onVerified: () => refetch() });
//
// FIX(F-008, split F-010): imports the message-type constants + a type-only
// contract from @dodomain/core/message-types — a ZERO-IMPORT module — never
// zod at runtime (R5: this widget ships into an INTEGRATOR's page bundle, so
// it stays dependency-free). F-008 originally imported the plain-const half
// of @dodomain/core/messages (which ALSO imports zod, for zDoDomainMessage),
// betting a bundler's tree-shaking would drop the unused zod graph. F-010
// verified that bet against a real tsup build and it did NOT hold (esbuild's
// default AND Rollup's tree-shaking both left zod's full runtime in dist,
// confirmed via test/build.smoke.test.ts) — so the plain consts now live in
// their own zod-free module (messages.ts's header has the full history) and
// this package imports ONLY from there, guaranteeing zod can never reach
// this bundle regardless of any bundler's tree-shaking sophistication.
import { DODOMAIN_DEFAULT_ORIGIN } from "@dodomain/core/origin";
import {
  EMBED_PARAM,
  EMBED_VALUE,
  MESSAGE_TYPES,
  ORIGIN_PARAM,
  THEME_PARAM,
  type DoDomainMessage,
} from "@dodomain/core/message-types";

export interface ShowDoDomainOptions {
  /** Session token from POST /api/v1/sessions (dd_sess_…). */
  token: string;
  /** DoDomain origin. Defaults to https://app.dodomain.io. */
  baseUrl?: string;
  onVerified?: (detail: { domain?: string }) => void;
  onClose?: () => void;
  /**
   * FIX(F-010): fires when the hosted flow fails to load or reports a
   * session error — a cross-origin iframe's HTTP 404/500 exposes neither
   * `onerror` nor readable content by default, so before this fix a broken
   * embed just sat there silently. See DoDomainWidgetError's own doc for the
   * three cases.
   */
  onError?: (detail: DoDomainWidgetError) => void;
  /**
   * FIX(F-010): milliseconds to wait for the hosted flow's `dodomain:ready`
   * handshake before treating the embed as failed-to-load. Default 15000.
   */
  loadTimeoutMs?: number;
  /**
   * Host-page theme (2026-08-04 embed polish). Pass the theme YOUR page is
   * currently rendering so the embedded sheet matches it — the hosted flow
   * adopts it and hides its own theme toggle. Omitted ⇒ the flow resolves
   * its own theme (prefers-color-scheme / its visitor preference).
   */
  theme?: "light" | "dark";
}

/**
 * FIX(F-010): the three ways `onError` can fire.
 * - `load-timeout` — no `dodomain:ready`/`dodomain:verified` arrived within
 *   `loadTimeoutMs` (covers a 404/DNS failure/hung load — anything that
 *   never gets far enough to run the hosted flow's own JS).
 * - `load-error` — the iframe's own `error` event fired (best-effort;
 *   browsers rarely fire this for a cross-origin navigation, but it's free
 *   to listen for).
 * - `session-error` — the hosted flow mounted and posted `dodomain:error`
 *   with a `code` (e.g. an expired/not-found token, or a verify() failure —
 *   see connect-flow.tsx).
 */
export type DoDomainWidgetError =
  { type: "load-timeout" } | { type: "load-error" } | { type: "session-error"; code: string };

export interface DoDomainHandle {
  close: () => void;
}

const DEFAULT_BASE = DODOMAIN_DEFAULT_ORIGIN;
const DEFAULT_LOAD_TIMEOUT_MS = 15_000;

export function showDoDomain(opts: ShowDoDomainOptions): DoDomainHandle {
  if (typeof document === "undefined") {
    throw new Error("showDoDomain must run in a browser");
  }
  const base = (opts.baseUrl ?? DEFAULT_BASE).replace(/\/$/, "");
  const origin = new URL(base).origin;

  const backdrop = document.createElement("div");
  backdrop.setAttribute("data-dodomain", "backdrop");
  // Graphite & Pine (docs/DESIGN.md): graphite-ink scrim (#17201C at 55%) — no
  // backdrop-blur (the system bans glassmorphism chrome) and no blue-grays.
  Object.assign(backdrop.style, {
    position: "fixed",
    inset: "0",
    background: "rgba(23,32,28,0.55)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    zIndex: "2147483647",
  } as CSSStyleDeclaration);

  const frame = document.createElement("iframe");
  // FIX(F-008/§10.1 origin scoping): appends this page's own origin so the
  // hosted flow can scope postMessage's targetOrigin to it instead of "*" —
  // see connect-flow.tsx for the producer side of this handshake. The theme
  // param (2026-08-04 embed polish) hands the HOST page's theme to the flow
  // so the sheet matches the page around it.
  frame.src =
    `${base}/connect/${encodeURIComponent(opts.token)}` +
    `?${EMBED_PARAM}=${EMBED_VALUE}&${ORIGIN_PARAM}=${encodeURIComponent(window.location.origin)}` +
    (opts.theme ? `&${THEME_PARAM}=${opts.theme}` : "");
  frame.setAttribute("title", "Connect your domain");
  // Graphite & Pine card: surface-1 + 1px hairline, card radius 14px,
  // level-3 (modal) graphite shadow. The background pre-paints the hosted
  // flow's canvas IN THE HANDED-OVER THEME, so a slow load never flashes the
  // wrong brightness. Height starts compact and then HUGS THE CONTENT: the
  // flow reports its natural height via `dodomain:height` (onMessage below)
  // and the frame follows — a fixed-height box left a dead slab of empty
  // canvas under short content (2026-08-04 embed polish).
  const dark = opts.theme === "dark";
  Object.assign(frame.style, {
    // content-box is load-bearing: host pages routinely reset every element
    // to border-box (Tailwind Preflight et al), which would make the 1px
    // borders eat into the height applyReportedHeight sets — the inner
    // viewport lands 2px short of the reported content and the sheet grows a
    // permanent scrollbar (found live on Uptimely, 2026-08-04).
    boxSizing: "content-box",
    width: "min(560px, 94vw)",
    height: "min(480px, 92vh)",
    border: dark ? "1px solid #2a352f" : "1px solid #e5e9e7",
    borderRadius: "14px",
    boxShadow: "0 1px 2px rgba(23,32,28,0.05), 0 12px 32px rgba(23,32,28,0.14)",
    background: dark ? "#17201c" : "#ffffff",
    transition: "height 180ms ease",
  } as CSSStyleDeclaration);

  function applyReportedHeight(height: number) {
    if (!Number.isFinite(height) || height <= 0) return;
    const max = Math.floor(window.innerHeight * 0.92);
    const clamped = Math.max(280, Math.min(Math.ceil(height), max));
    frame.style.height = `${clamped}px`;
  }

  // FIX(F-010): the only reliable "did the flow actually come up?" signal —
  // a cross-origin iframe's 404/500 fires neither `onerror` nor exposes
  // readable content. Cleared by the first `dodomain:ready`/`dodomain:verified`
  // (onMessage below); otherwise fires onError({type:"load-timeout"}).
  let loadTimer: ReturnType<typeof setTimeout> | undefined = setTimeout(() => {
    loadTimer = undefined;
    opts.onError?.({ type: "load-timeout" });
  }, opts.loadTimeoutMs ?? DEFAULT_LOAD_TIMEOUT_MS);

  function clearLoadTimer() {
    if (loadTimer !== undefined) {
      clearTimeout(loadTimer);
      loadTimer = undefined;
    }
  }

  // FIX(F-010): best-effort network-level signal (rarely fires for a
  // cross-origin navigation, but free to listen for) — the load-timeout
  // above is the primary detector.
  function onFrameError() {
    clearLoadTimer();
    opts.onError?.({ type: "load-error" });
  }
  frame.addEventListener("error", onFrameError);

  let closed = false;
  function teardown() {
    if (closed) return;
    closed = true;
    clearLoadTimer();
    window.removeEventListener("message", onMessage);
    frame.removeEventListener("error", onFrameError);
    backdrop.remove();
  }
  function close() {
    teardown();
    opts.onClose?.();
  }

  function onMessage(e: MessageEvent) {
    if (e.origin !== origin) return;
    // Cheap runtime guard (no zod, per R5 — see the module-level fix note
    // above): a `MessageEvent.data` narrowing, not a full schema parse.
    const data = e.data as DoDomainMessage | undefined;
    if (!data || typeof data.type !== "string") return;
    if (data.type === MESSAGE_TYPES.VERIFIED) {
      clearLoadTimer();
      opts.onVerified?.({ domain: data.domain });
    } else if (data.type === MESSAGE_TYPES.READY) {
      clearLoadTimer();
    } else if (data.type === MESSAGE_TYPES.ERROR) {
      clearLoadTimer();
      opts.onError?.({ type: "session-error", code: data.code });
    } else if (data.type === MESSAGE_TYPES.HEIGHT) {
      applyReportedHeight(data.height);
    } else if (data.type === MESSAGE_TYPES.CLOSE) {
      close();
    }
  }

  backdrop.addEventListener("click", (e) => {
    if (e.target === backdrop) close();
  });
  window.addEventListener("message", onMessage);

  backdrop.appendChild(frame);
  document.body.appendChild(backdrop);

  return { close };
}
