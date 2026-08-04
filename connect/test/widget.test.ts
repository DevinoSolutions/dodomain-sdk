import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { JSDOM } from "jsdom";

import { showDoDomain } from "../src/index.ts";

// Characterization (DOM contract, origin-checked message handling) + F-010
// new-behavior tests (onError/loadTimeoutMs) for the widget — see
// PLAN-F-010 §4/§5. packages/connect had no test/ dir before this fix; this
// file is what makes src/index.ts's onMessage handler + show flow pinned.

const WIDGET_PAGE_ORIGIN = "https://embedder.example.com";
const HOSTED_ORIGIN = "https://app.dodomain.io"; // showDoDomain's own default

let dom: JSDOM;

beforeEach(() => {
  dom = new JSDOM("<!doctype html><html><body></body></html>", {
    url: `${WIDGET_PAGE_ORIGIN}/`,
  });
  const g = globalThis as unknown as Record<string, unknown>;
  g.window = dom.window;
  g.document = dom.window.document;
  g.MessageEvent = dom.window.MessageEvent;
  g.Event = dom.window.Event;
});

afterEach(() => {
  const g = globalThis as unknown as Record<string, unknown>;
  delete g.window;
  delete g.document;
  delete g.MessageEvent;
  delete g.Event;
  dom.window.close();
});

function backdropEl() {
  return dom.window.document.querySelector('[data-dodomain="backdrop"]');
}
function iframeEl() {
  return dom.window.document.querySelector("iframe");
}
function postToWidget(data: unknown, origin = HOSTED_ORIGIN) {
  dom.window.dispatchEvent(new dom.window.MessageEvent("message", { origin, data }));
}

test("showDoDomain appends a backdrop + iframe with the token and embed param encoded in src (pins the DOM contract)", () => {
  const handle = showDoDomain({ token: "dd_sess_abc", loadTimeoutMs: 5_000 });
  const backdrop = backdropEl();
  const iframe = iframeEl();
  assert.ok(backdrop, "backdrop not appended");
  assert.ok(iframe, "iframe not appended");
  assert.ok(iframe?.src.startsWith(`${HOSTED_ORIGIN}/connect/dd_sess_abc?`));
  assert.ok(iframe?.src.includes("embed=1"));
  assert.ok(iframe?.src.includes(`origin=${encodeURIComponent(WIDGET_PAGE_ORIGIN)}`));
  handle.close();
});

test("theme option rides the iframe URL and darkens the pre-paint (2026-08-04 embed polish)", () => {
  const handle = showDoDomain({ token: "t1", loadTimeoutMs: 5_000, theme: "dark" });
  const iframe = iframeEl();
  assert.ok(iframe?.src.includes("theme=dark"));
  assert.equal(iframe?.style.background, "rgb(23, 32, 28)");
  handle.close();
});

test("no theme option ⇒ no theme param and the light pre-paint (back-compat)", () => {
  const handle = showDoDomain({ token: "t1", loadTimeoutMs: 5_000 });
  const iframe = iframeEl();
  assert.ok(!iframe?.src.includes("theme="));
  assert.equal(iframe?.style.background, "rgb(255, 255, 255)");
  handle.close();
});

test("dodomain:height resizes the iframe to the reported content height", () => {
  const handle = showDoDomain({ token: "t1", loadTimeoutMs: 5_000 });
  postToWidget({ type: "dodomain:height", height: 431 });
  assert.equal(iframeEl()?.style.height, "431px");
  handle.close();
});

test("dodomain:height clamps: never below 280px, never above 92% of the window", () => {
  const handle = showDoDomain({ token: "t1", loadTimeoutMs: 5_000 });
  postToWidget({ type: "dodomain:height", height: 10 });
  assert.equal(iframeEl()?.style.height, "280px");
  postToWidget({ type: "dodomain:height", height: 50_000 });
  assert.equal(iframeEl()?.style.height, `${Math.floor(dom.window.innerHeight * 0.92)}px`);
  handle.close();
});

test("a dodomain:height from a mismatched origin is ignored", () => {
  const handle = showDoDomain({ token: "t1", loadTimeoutMs: 5_000 });
  const before = iframeEl()?.style.height;
  postToWidget({ type: "dodomain:height", height: 431 }, "https://evil.example.com");
  assert.equal(iframeEl()?.style.height, before);
  handle.close();
});

test("a message from a mismatched origin is ignored", () => {
  let verifiedCalled = false;
  const handle = showDoDomain({
    token: "t1",
    loadTimeoutMs: 5_000,
    onVerified: () => {
      verifiedCalled = true;
    },
  });
  postToWidget({ type: "dodomain:verified", domain: "acme.com" }, "https://evil.example.com");
  assert.equal(verifiedCalled, false);
  handle.close();
});

test("a matching-origin dodomain:verified message fires onVerified with the domain", () => {
  let seen: { domain?: string } | undefined;
  const handle = showDoDomain({
    token: "t1",
    loadTimeoutMs: 5_000,
    onVerified: (d) => {
      seen = d;
    },
  });
  postToWidget({ type: "dodomain:verified", domain: "acme.com" });
  assert.deepEqual(seen, { domain: "acme.com" });
  handle.close();
});

test("dodomain:close fires onClose and tears down (removes the backdrop)", () => {
  let closedCalled = false;
  showDoDomain({
    token: "t1",
    loadTimeoutMs: 5_000,
    onClose: () => {
      closedCalled = true;
    },
  });
  assert.ok(backdropEl());
  postToWidget({ type: "dodomain:close" });
  assert.equal(closedCalled, true);
  assert.equal(backdropEl(), null);
});

test("backdrop click (outside the iframe) closes and fires onClose", () => {
  let closedCalled = false;
  showDoDomain({
    token: "t1",
    loadTimeoutMs: 5_000,
    onClose: () => {
      closedCalled = true;
    },
  });
  const backdrop = backdropEl();
  assert.ok(backdrop);
  backdrop?.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));
  assert.equal(closedCalled, true);
});

test("F-010: dodomain:ready clears the load timeout — onError never fires", async () => {
  let errored = false;
  const handle = showDoDomain({
    token: "t1",
    loadTimeoutMs: 20,
    onError: () => {
      errored = true;
    },
  });
  postToWidget({ type: "dodomain:ready" });
  await new Promise((r) => setTimeout(r, 70));
  assert.equal(errored, false);
  handle.close();
});

test("F-010: onError({type:'load-timeout'}) fires when no ready/verified arrives within loadTimeoutMs", async () => {
  let err: unknown;
  showDoDomain({
    token: "t1",
    loadTimeoutMs: 15,
    onError: (e) => {
      err = e;
    },
  });
  await new Promise((r) => setTimeout(r, 70));
  assert.deepEqual(err, { type: "load-timeout" });
});

test("F-010: dodomain:error fires onError({type:'session-error',code})", () => {
  let err: unknown;
  const handle = showDoDomain({
    token: "t1",
    loadTimeoutMs: 5_000,
    onError: (e) => {
      err = e;
    },
  });
  postToWidget({ type: "dodomain:error", code: "expired" });
  assert.deepEqual(err, { type: "session-error", code: "expired" });
  handle.close();
});

test("F-010: the iframe's error event fires onError({type:'load-error'}) and clears the load timeout", async () => {
  let err: unknown;
  showDoDomain({
    token: "t1",
    loadTimeoutMs: 20,
    onError: (e) => {
      err ??= e; // only the FIRST onError call matters for this assertion
    },
  });
  const iframe = iframeEl();
  assert.ok(iframe);
  iframe?.dispatchEvent(new dom.window.Event("error"));
  assert.deepEqual(err, { type: "load-error" });
  // the load-timeout must not ALSO fire afterward (clearLoadTimer ran)
  await new Promise((r) => setTimeout(r, 70));
  assert.deepEqual(err, { type: "load-error" });
});

test("close() before the load timeout elapses prevents a late onError", async () => {
  let errored = false;
  const handle = showDoDomain({
    token: "t1",
    loadTimeoutMs: 20,
    onError: () => {
      errored = true;
    },
  });
  handle.close();
  await new Promise((r) => setTimeout(r, 70));
  assert.equal(errored, false);
});
