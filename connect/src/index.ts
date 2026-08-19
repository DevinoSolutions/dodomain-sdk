// @dodomain/connect — the embeddable browser widget.
// Opens the hosted connect page in a modal iframe and relays lifecycle events.
// Integrator branding (App.name/logoUrl/brandColor, 2026-07-21) reaches the
// end user THROUGH the hosted flow this iframe renders — the widget draws no
// flow chrome of its own, so it needs no branding API and no postMessage
// contract change (message-types stays as-is).
//
//   import { showDoDomain } from "@dodomain/connect";
//   const session = await fetch("/my-api/create-session").then(r => r.json());
//   showDoDomain({
//     token: session.token,
//     onVerified: () => refetch(),
//     onClose: ({ state }) => { if (state !== "verified") keepPromptVisible(); },
//     // The embed can't mount (host CSP / network / content blocker) — send
//     // the user to the same flow full-page instead of failing silently.
//     onError: (e) => { if (e.code === "MOUNT_BLOCKED") location.assign(e.hostedUrl); },
//   });
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
  /**
   * Fires when the modal is dismissed (backdrop click, the flow's own close
   * affordance, or `handle.close()`).
   *
   * The detail argument (2026-08-17, BioFlow feedback) carries the session's
   * last-known state so closing means something: partners reported that a
   * zero-arg close "proves nothing either way", forcing them to re-poll their
   * own backend after every dismissal. Existing zero-arg handlers keep
   * compiling and behaving identically — a `() => void` is assignable to this
   * type, and the argument is simply ignored.
   */
  onClose?: (detail: DoDomainCloseDetail) => void;
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
 * The one machine-readable code meaning "the sheet never came up — nothing
 * the user does inside this modal can succeed" (2026-08-17, BioFlow
 * feedback: a host-page CSP whose `frame-src` omitted the DoDomain origin
 * failed indistinguishably from every other error, so the integrator had to
 * hang a hosted-URL fallback off a generic `onError`).
 *
 * Deliberately NOT named CSP_BLOCKED: the widget cannot tell a CSP block
 * from a DNS failure, an offline network, or a content blocker eating the
 * frame — all four look identical from the parent page (a cross-origin
 * iframe exposes neither readable content nor a reliable error event). The
 * honest name covers all of them, and the handling is the same for all of
 * them: send the user to `hostedUrl` (see the README's "Origins & CSP").
 */
export const MOUNT_BLOCKED = "MOUNT_BLOCKED";

/**
 * FIX(F-010): the three ways `onError` can fire.
 * - `load-timeout` — no `dodomain:ready`/`dodomain:verified` arrived within
 *   `loadTimeoutMs` (covers a 404/DNS failure/hung load — anything that
 *   never gets far enough to run the hosted flow's own JS).
 * - `load-error` — the iframe's own `error` event fired, OR the HOST page's
 *   own CSP reported blocking this frame (`securitypolicyviolation` on
 *   `frame-src`/`child-src`/`default-src` — 2026-08-17). Both are
 *   best-effort fast paths for the same fact the `load-timeout` above
 *   eventually proves anyway; the CSP one just gets there in milliseconds
 *   instead of `loadTimeoutMs`.
 * - `session-error` — the hosted flow mounted and posted `dodomain:error`
 *   with a `code` (e.g. an expired/not-found token, or a verify() failure —
 *   see connect-flow.tsx).
 *
 * Every variant carries `hostedUrl` (the full-page `/connect/<token>` URL,
 * no embed params) and a `code`. `code === MOUNT_BLOCKED` is the single
 * check a partner needs for "the embed is impossible here, fall back":
 * navigate to `hostedUrl`. `type` stays the pre-existing 3-value vocabulary
 * so no consumer's switch changes meaning.
 */
export type DoDomainWidgetError =
  | { type: "load-timeout"; code: typeof MOUNT_BLOCKED; hostedUrl: string }
  | { type: "load-error"; code: typeof MOUNT_BLOCKED; hostedUrl: string }
  | { type: "session-error"; code: string; hostedUrl: string };

/**
 * The session's last-known state, derived entirely from the postMessage
 * traffic already flowing from the hosted flow (2026-08-17) — no new message
 * type was needed, and the widget never talks to the API itself.
 * - `unknown` — nothing was ever heard from the flow (it never mounted:
 *   CSP/network/blocked, i.e. the `MOUNT_BLOCKED` case).
 * - `pending` — the flow mounted (`dodomain:ready`) but reached no outcome
 *   before the user closed it.
 * - `verified` — `dodomain:verified` arrived; the domain is connected.
 *   Sticky: a later `dodomain:error` cannot downgrade it.
 * - `failed` — the flow reported `dodomain:error` (e.g. a verify() failure)
 *   and never went on to verify.
 */
export type DoDomainSessionState = "verified" | "pending" | "failed" | "unknown";

/**
 * What `onClose` receives (2026-08-17). Additive: handlers written as
 * `() => …` before this existed keep compiling and behaving identically.
 */
export interface DoDomainCloseDetail {
  state: DoDomainSessionState;
  /** The verified domain, when `state === "verified"` reported one. */
  domain?: string;
}

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
  // The full-page flow for this same session — what a partner navigates to
  // when the embed can't mount (2026-08-17). Deliberately WITHOUT the embed/
  // origin/theme params the iframe carries: those put the flow in embedded
  // mode (no page chrome, postMessage close), which is wrong for a top-level
  // navigation.
  const hostedUrl = `${base}/connect/${encodeURIComponent(opts.token)}`;

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
    hostedUrl +
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

  // The session's last-known state, derived from the postMessage traffic
  // this widget already receives (2026-08-17) — see DoDomainSessionState.
  // Starts "unknown": a modal that never heard from the flow proves nothing.
  let state: DoDomainSessionState = "unknown";
  let verifiedDomain: string | undefined;
  let closed = false;

  // FIX(F-010): the only reliable "did the flow actually come up?" signal —
  // a cross-origin iframe's 404/500 fires neither `onerror` nor exposes
  // readable content. Cleared by the first `dodomain:ready`/`dodomain:verified`
  // (onMessage below); otherwise fires onError({type:"load-timeout"}).
  let loadTimer: ReturnType<typeof setTimeout> | undefined = setTimeout(() => {
    loadTimer = undefined;
    reportMountFailure("load-timeout");
  }, opts.loadTimeoutMs ?? DEFAULT_LOAD_TIMEOUT_MS);

  function clearLoadTimer() {
    if (loadTimer !== undefined) {
      clearTimeout(loadTimer);
      loadTimer = undefined;
    }
  }

  // "The frame never mounted" is ONE fact with several possible detectors
  // (2026-08-17), so it reports at most once no matter how many of them
  // fire: the CSP violation event and the iframe error event can both land
  // for the same block, and either would otherwise be followed by the
  // load-timeout as well.
  let mountFailureReported = false;
  function reportMountFailure(type: "load-timeout" | "load-error") {
    if (mountFailureReported || closed) return;
    mountFailureReported = true;
    clearLoadTimer();
    opts.onError?.({ type, code: MOUNT_BLOCKED, hostedUrl });
  }

  // FIX(F-010): best-effort network-level signal (rarely fires for a
  // cross-origin navigation, but free to listen for) — the load-timeout
  // above is the primary detector.
  function onFrameError() {
    reportMountFailure("load-error");
  }
  frame.addEventListener("error", onFrameError);

  // 2026-08-17 (BioFlow): the host page's OWN CSP is the one mount failure
  // the browser will actually tell us about — when it refuses to load this
  // frame it fires `securitypolicyviolation` on the embedding document. That
  // turns a 15-second silent wait into an immediate, correctly-coded
  // MOUNT_BLOCKED. It is a fast path, never the only one: browsers without
  // the event (or a block that isn't CSP at all — DNS, offline, a content
  // blocker) still land on the load-timeout above.
  //
  // The event is typed loosely on purpose: `SecurityPolicyViolationEvent`
  // isn't guaranteed to exist at runtime, and the two fields read here are
  // the only ones this needs.
  function onCspViolation(e: Event) {
    const violation = e as { blockedURI?: unknown; violatedDirective?: unknown };
    const directive =
      typeof violation.violatedDirective === "string" ? violation.violatedDirective : "";
    const blockedUri = typeof violation.blockedURI === "string" ? violation.blockedURI : "";
    // CSP falls back frame-src → child-src → default-src, and the report
    // names whichever directive was actually enforced, so all three mean
    // "this page's policy refused our frame". (Browsers report either the
    // bare directive name or `<name> <source-list>`, hence startsWith.)
    const framesBlocked =
      directive.startsWith("frame-src") ||
      directive.startsWith("child-src") ||
      directive.startsWith("default-src");
    // blockedURI is the frame URL, or just its origin when the browser
    // strips it cross-origin — both start with our origin.
    if (!framesBlocked || !blockedUri.startsWith(origin)) return;
    reportMountFailure("load-error");
  }
  document.addEventListener("securitypolicyviolation", onCspViolation);

  function teardown() {
    if (closed) return;
    closed = true;
    clearLoadTimer();
    window.removeEventListener("message", onMessage);
    frame.removeEventListener("error", onFrameError);
    document.removeEventListener("securitypolicyviolation", onCspViolation);
    backdrop.remove();
  }
  function close() {
    teardown();
    // `domain` is omitted rather than passed as undefined so the detail
    // object reads the way a consumer would write it.
    opts.onClose?.(verifiedDomain === undefined ? { state } : { state, domain: verifiedDomain });
  }

  function onMessage(e: MessageEvent) {
    if (e.origin !== origin) return;
    // Cheap runtime guard (no zod, per R5 — see the module-level fix note
    // above): a `MessageEvent.data` narrowing, not a full schema parse.
    const data = e.data as DoDomainMessage | undefined;
    if (!data || typeof data.type !== "string") return;
    if (data.type === MESSAGE_TYPES.VERIFIED) {
      clearLoadTimer();
      // Terminal and sticky: a later dodomain:error (e.g. a re-check the
      // user triggered after the fact) cannot un-verify a connected domain.
      state = "verified";
      verifiedDomain = data.domain;
      opts.onVerified?.({ domain: data.domain });
    } else if (data.type === MESSAGE_TYPES.READY) {
      clearLoadTimer();
      // The flow is up but has reached no outcome — anything stronger than
      // "pending" would be a claim we haven't heard.
      if (state === "unknown") state = "pending";
    } else if (data.type === MESSAGE_TYPES.ERROR) {
      clearLoadTimer();
      // connect-flow.tsx posts this for a verify() failure, which the user
      // can still retry inside the same session — so it is NOT terminal, and
      // a subsequent dodomain:verified promotes the state above.
      if (state !== "verified") state = "failed";
      opts.onError?.({ type: "session-error", code: data.code, hostedUrl });
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
