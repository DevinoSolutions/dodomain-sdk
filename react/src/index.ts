// @dodomain/react — React bindings for the @dodomain/connect widget.
//
// The widget's own API is imperative (showDoDomain() opens a modal iframe and
// returns a close handle), so the natural React shape is a HOOK that owns the
// handle's lifecycle — not a component that pretends the modal is declarative:
//
//   const { open, close, isOpen } = useDoDomainConnect({
//     token: session.token,           // from POST /api/v1/sessions, server-side
//     onVerified: () => refetch(),
//     onError: (e) => { if (e.code === MOUNT_BLOCKED) location.assign(e.hostedUrl); },
//   });
//   <button onClick={open}>Connect your domain</button>
//
// What the hook adds over calling showDoDomain() directly in a click handler:
// - LATEST-PROPS CALLBACKS: the widget is handed stable wrapper callbacks that
//   read the current render's handlers through a ref at fire time, so a
//   re-render while the modal is open never strands a stale closure (the
//   classic "onVerified captured the first render's state" bug).
// - ONE MODAL AT A TIME: open() while already open is a no-op — a double-click
//   cannot stack two backdrops.
// - UNMOUNT CLEANUP: an open modal is torn down when the owning component
//   unmounts, instead of orphaning a full-screen iframe over the page.
// - isOpen STATE: the modal's mounted-ness as plain React state.
//
// This package stays zod-free the same way the widget does — it imports only
// @dodomain/connect's public surface (which is itself zod-free by structure,
// see packages/connect/src/index.ts) and adds no runtime dependency beyond it.
import { createElement, useCallback, useEffect, useRef, useState } from "react";
import type { ReactElement, ReactNode } from "react";
import { showDoDomain } from "@dodomain/connect";
import type { DoDomainHandle, ShowDoDomainOptions } from "@dodomain/connect";

// Re-exported so a React integrator can type handlers and switch on the mount
// failure code without also depending on @dodomain/connect directly.
export { MOUNT_BLOCKED } from "@dodomain/connect";
export type {
  DoDomainCloseDetail,
  DoDomainHandle,
  DoDomainSessionState,
  DoDomainWidgetError,
  ShowDoDomainOptions,
} from "@dodomain/connect";

/**
 * Options for {@link useDoDomainConnect} — exactly the widget's own
 * ShowDoDomainOptions (token, baseUrl, theme, loadTimeoutMs, onVerified,
 * onClose, onError). Callbacks may be inline arrow functions: the hook reads
 * the latest render's handlers at fire time, so they need no useCallback.
 */
export type UseDoDomainConnectOptions = ShowDoDomainOptions;

export interface UseDoDomainConnectResult {
  /**
   * Opens the connect modal with the current render's options. No-op while
   * the modal is already open (one modal at a time). Must run in a browser —
   * call it from an event handler, never during server rendering.
   */
  open: () => void;
  /**
   * Dismisses the modal programmatically — fires onClose with the session's
   * last-known state, exactly like the widget's own handle.close(). No-op
   * when nothing is open.
   */
  close: () => void;
  /** Whether the modal is currently mounted. */
  isOpen: boolean;
}

export function useDoDomainConnect(options: UseDoDomainConnectOptions): UseDoDomainConnectResult {
  const [isOpen, setIsOpen] = useState(false);

  // Latest-props ref (the pre-useEffectEvent pattern — this package supports
  // react >=18, where useEffectEvent doesn't exist): re-assigned after every
  // render commit, read by open() and by the widget-callback wrappers at fire
  // time. Never read during render, so the mutation is legal.
  const optionsRef = useRef(options);
  useEffect(() => {
    optionsRef.current = options;
  });

  const handleRef = useRef<DoDomainHandle | null>(null);

  const open = useCallback(() => {
    if (handleRef.current !== null) return; // one modal at a time
    const current = optionsRef.current;
    handleRef.current = showDoDomain({
      token: current.token,
      baseUrl: current.baseUrl,
      loadTimeoutMs: current.loadTimeoutMs,
      theme: current.theme,
      onVerified: (detail) => optionsRef.current.onVerified?.(detail),
      onError: (detail) => optionsRef.current.onError?.(detail),
      onClose: (detail) => {
        // The widget fires this for EVERY dismissal path (backdrop click,
        // in-flow close, handle.close()), so clearing the handle here is the
        // one place that keeps hook state true for all of them.
        handleRef.current = null;
        setIsOpen(false);
        optionsRef.current.onClose?.(detail);
      },
    });
    setIsOpen(true);
  }, []);

  const close = useCallback(() => {
    handleRef.current?.close();
  }, []);

  // Unmount cleanup: never orphan a full-screen modal past its owner. Runs
  // the widget's own close path, so onClose still reports the last-known
  // state. StrictMode's dev-only mount→cleanup→mount cycle is safe here: the
  // modal only ever opens from an event handler, so nothing is open during
  // the synthetic first cleanup and this is a no-op then.
  useEffect(() => {
    return () => {
      handleRef.current?.close();
    };
  }, []);

  return { open, close, isOpen };
}

export interface DoDomainConnectButtonProps extends UseDoDomainConnectOptions {
  /** Button label. Defaults to "Connect your domain". */
  children?: ReactNode;
  className?: string;
  disabled?: boolean;
}

/**
 * Drop-in trigger for the connect modal — a plain unstyled `<button>` wired
 * to {@link useDoDomainConnect}. It disables itself while the modal is open.
 * For anything beyond "a button that opens the flow", use the hook directly.
 */
export function DoDomainConnectButton(props: DoDomainConnectButtonProps): ReactElement {
  const { children, className, disabled, ...options } = props;
  const { open, isOpen } = useDoDomainConnect(options);
  return createElement(
    "button",
    {
      type: "button",
      className,
      disabled: disabled === true || isOpen,
      onClick: open,
      "data-dodomain": "connect-button",
      "aria-haspopup": "dialog",
    },
    children ?? "Connect your domain",
  );
}
