import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { JSDOM } from "jsdom";
import { ensureConnectDist } from "./helpers/ensure-connect-dist.ts";
import type {
  DoDomainCloseDetail,
  UseDoDomainConnectOptions,
  UseDoDomainConnectResult,
} from "../src/index.ts";

// The hook suite runs the REAL @dodomain/connect widget (built dist, per the
// package's exports) under jsdom, rendered by the REAL react-dom — no mocked
// widget or renderer that could drift from either contract. That's why the
// value imports below are dynamic: @dodomain/connect must exist on disk
// before ../src/index.ts can link (see ensure-connect-dist.ts).
ensureConnectDist();

// One JSDOM for the whole file, installed BEFORE react-dom is imported —
// react-dom feature-detects its environment (window/document) at import
// time, so the globals must already be in place. Per-test isolation comes
// from a fresh container + unmount in afterEach; the widget removes its own
// window listeners on teardown, which every test path exercises.
const WIDGET_PAGE_ORIGIN = "https://embedder.acme.invalid";
const HOSTED_ORIGIN = "https://app.dodomain.io"; // the widget's own default
const dom = new JSDOM("<!doctype html><html><body></body></html>", {
  url: `${WIDGET_PAGE_ORIGIN}/`,
});
{
  const g = globalThis as unknown as Record<string, unknown>;
  g.window = dom.window;
  g.document = dom.window.document;
  g.MessageEvent = dom.window.MessageEvent;
  g.Event = dom.window.Event;
  g.MouseEvent = dom.window.MouseEvent;
  // React's act() refuses to run outside a declared act environment.
  g.IS_REACT_ACT_ENVIRONMENT = true;
}

const { act, createElement, StrictMode } = await import("react");
const { createRoot } = await import("react-dom/client");
const { useDoDomainConnect, DoDomainConnectButton } = await import("../src/index.ts");

// Everything the widget and the hook do here is synchronous (DOM writes,
// message-event dispatch, state updates), so every act() call below takes a
// sync callback and act flushes it — renders AND effects — before returning.
// React 19's types give that overload a void return, hence no awaits.

type Root = ReturnType<typeof createRoot>;

let container: HTMLElement;
let root: Root;

beforeEach(() => {
  container = dom.window.document.createElement("div");
  dom.window.document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => {
    root.unmount();
  });
  // A failed assertion mid-test can leave a widget mounted; sweep it so the
  // NEXT test's "one backdrop" checks stay meaningful. (querySelectorAll
  // returns a static NodeList, so removing while iterating is safe.)
  for (const el of dom.window.document.querySelectorAll('[data-dodomain="backdrop"]')) {
    el.remove();
  }
  container.remove();
});

function backdrops() {
  return dom.window.document.querySelectorAll('[data-dodomain="backdrop"]');
}
function iframeEl() {
  return dom.window.document.querySelector("iframe");
}
function postToWidget(data: unknown, origin = HOSTED_ORIGIN) {
  act(() => {
    dom.window.dispatchEvent(new dom.window.MessageEvent("message", { origin, data }));
  });
}

// Render-prop probe: `expose` is called during render with the hook's latest
// result, so tests read `open`/`close`/`isOpen` exactly as a component would.
function HookProbe(props: {
  options: UseDoDomainConnectOptions;
  expose: (result: UseDoDomainConnectResult) => void;
}) {
  props.expose(useDoDomainConnect(props.options));
  return null;
}

function renderHook(options: UseDoDomainConnectOptions, target: Root = root) {
  let latest: UseDoDomainConnectResult | undefined;
  const expose = (result: UseDoDomainConnectResult) => {
    latest = result;
  };
  const rerender = (nextOptions: UseDoDomainConnectOptions) => {
    act(() => {
      target.render(createElement(HookProbe, { options: nextOptions, expose }));
    });
  };
  rerender(options);
  return {
    rerender,
    result: () => {
      assert.ok(latest, "HookProbe never rendered");
      return latest;
    },
  };
}

test("open() mounts the widget iframe with the session token and flips isOpen (pins the hook↔widget contract)", () => {
  const hook = renderHook({ token: "dd_sess_hook1", loadTimeoutMs: 5_000 });
  assert.equal(hook.result().isOpen, false);
  act(() => {
    hook.result().open();
  });
  assert.equal(backdrops().length, 1);
  assert.ok(iframeEl()?.src.startsWith(`${HOSTED_ORIGIN}/connect/dd_sess_hook1?`));
  assert.equal(hook.result().isOpen, true);
});

test("open() while already open is a no-op — a double-click cannot stack a second modal", () => {
  const hook = renderHook({ token: "dd_sess_dbl", loadTimeoutMs: 5_000 });
  act(() => {
    hook.result().open();
    hook.result().open();
  });
  act(() => {
    hook.result().open();
  });
  assert.equal(backdrops().length, 1);
  act(() => {
    hook.result().close();
  });
});

test("widget callbacks read the LATEST render's handlers — a re-render after open() cannot strand a stale closure", () => {
  const calls: string[] = [];
  const hook = renderHook({
    token: "dd_sess_latest",
    loadTimeoutMs: 5_000,
    onVerified: () => calls.push("first-render handler"),
  });
  act(() => {
    hook.result().open();
  });
  // Re-render WHILE the modal is open — the widget was handed its callbacks
  // at open() time, so without the latest-props ref this would still call
  // the first render's handler.
  hook.rerender({
    token: "dd_sess_latest",
    loadTimeoutMs: 5_000,
    onVerified: (detail) => calls.push(`second-render handler:${detail.domain ?? ""}`),
  });
  postToWidget({ type: "dodomain:verified", domain: "shop.acme.invalid" });
  assert.deepEqual(calls, ["second-render handler:shop.acme.invalid"]);
  act(() => {
    hook.result().close();
  });
});

test("backdrop dismissal reports onClose with the last-known state, resets isOpen, and open() works again", () => {
  const closes: DoDomainCloseDetail[] = [];
  const hook = renderHook({
    token: "dd_sess_dismiss",
    loadTimeoutMs: 5_000,
    onClose: (detail) => closes.push(detail),
  });
  act(() => {
    hook.result().open();
  });
  postToWidget({ type: "dodomain:ready" });
  const backdrop = backdrops()[0];
  assert.ok(backdrop, "widget backdrop not mounted");
  act(() => {
    backdrop.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));
  });
  assert.deepEqual(closes, [{ state: "pending" }]);
  assert.equal(hook.result().isOpen, false);
  assert.equal(backdrops().length, 0);
  // The handle was cleared, so the same hook instance can open a fresh modal.
  act(() => {
    hook.result().open();
  });
  assert.equal(backdrops().length, 1);
  assert.equal(hook.result().isOpen, true);
  act(() => {
    hook.result().close();
  });
});

test("close() dismisses programmatically through the widget's own close path (onClose fires, isOpen resets)", () => {
  const closes: DoDomainCloseDetail[] = [];
  const hook = renderHook({
    token: "dd_sess_close",
    loadTimeoutMs: 5_000,
    onClose: (detail) => closes.push(detail),
  });
  act(() => {
    hook.result().open();
  });
  act(() => {
    hook.result().close();
  });
  assert.equal(closes.length, 1);
  assert.equal(closes[0]?.state, "unknown"); // nothing was ever heard from the flow
  assert.equal(hook.result().isOpen, false);
  assert.equal(backdrops().length, 0);
});

test("unmounting while open tears the modal down (no orphaned iframe) and still reports onClose with the verified state", () => {
  const verified: Array<string | undefined> = [];
  const closes: DoDomainCloseDetail[] = [];
  const hook = renderHook({
    token: "dd_sess_unmount",
    loadTimeoutMs: 5_000,
    onVerified: (detail) => verified.push(detail.domain),
    onClose: (detail) => closes.push(detail),
  });
  act(() => {
    hook.result().open();
  });
  postToWidget({ type: "dodomain:verified", domain: "shop.acme.invalid" });
  assert.deepEqual(verified, ["shop.acme.invalid"]);
  act(() => {
    root.unmount();
  });
  assert.equal(backdrops().length, 0, "unmount left an orphaned widget backdrop");
  assert.deepEqual(closes, [{ state: "verified", domain: "shop.acme.invalid" }]);
});

test("StrictMode double-mount opens exactly one modal and its synthetic cleanup fires no phantom onClose", () => {
  const closes: DoDomainCloseDetail[] = [];
  let latest: UseDoDomainConnectResult | undefined;
  act(() => {
    root.render(
      createElement(
        StrictMode,
        null,
        createElement(HookProbe, {
          options: {
            token: "dd_sess_strict",
            loadTimeoutMs: 5_000,
            onClose: (d) => closes.push(d),
          },
          expose: (result) => {
            latest = result;
          },
        }),
      ),
    );
  });
  assert.deepEqual(closes, []); // the dev-only mount→cleanup→mount cycle closed nothing
  assert.ok(latest);
  act(() => {
    latest?.open();
  });
  assert.equal(backdrops().length, 1);
  act(() => {
    root.unmount();
  });
  assert.equal(backdrops().length, 0);
  assert.deepEqual(closes, [{ state: "unknown" }]); // exactly one close, from the real unmount
});

test("DoDomainConnectButton renders a type=button that opens the widget on click and disables itself while open", () => {
  act(() => {
    root.render(
      createElement(DoDomainConnectButton, { token: "dd_sess_btn", loadTimeoutMs: 5_000 }),
    );
  });
  const button = container.querySelector('button[data-dodomain="connect-button"]');
  assert.ok(button, "trigger button not rendered");
  assert.equal(button.getAttribute("type"), "button");
  assert.equal(button.textContent, "Connect your domain");
  assert.equal(button.hasAttribute("disabled"), false);
  act(() => {
    button.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));
  });
  assert.equal(backdrops().length, 1);
  assert.ok(iframeEl()?.src.startsWith(`${HOSTED_ORIGIN}/connect/dd_sess_btn?`));
  assert.equal(button.hasAttribute("disabled"), true);
  const backdrop = backdrops()[0];
  assert.ok(backdrop);
  act(() => {
    backdrop.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));
  });
  assert.equal(backdrops().length, 0);
  assert.equal(button.hasAttribute("disabled"), false);
});
