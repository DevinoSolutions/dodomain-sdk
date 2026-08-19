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

// The host page's CSP refusing our frame (2026-08-17). jsdom ships no
// SecurityPolicyViolationEvent constructor, so this builds the same shape the
// browser dispatches: a document-level "securitypolicyviolation" event
// carrying blockedURI + violatedDirective.
function dispatchCspViolation(violatedDirective: string, blockedURI: string) {
  const event = new dom.window.Event("securitypolicyviolation");
  Object.assign(event, { violatedDirective, blockedURI });
  dom.window.document.dispatchEvent(event);
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

test("frame pins content-box sizing so a host border-box reset cannot shave the reported height into a scrollbar", () => {
  const handle = showDoDomain({ token: "t1", loadTimeoutMs: 5_000 });
  assert.equal(iframeEl()?.style.boxSizing, "content-box");
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
  assert.deepEqual(err, {
    type: "load-timeout",
    code: "MOUNT_BLOCKED",
    hostedUrl: `${HOSTED_ORIGIN}/connect/t1`,
  });
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
  assert.deepEqual(err, {
    type: "session-error",
    code: "expired",
    hostedUrl: `${HOSTED_ORIGIN}/connect/t1`,
  });
  handle.close();
});

test(
  "a dead token's dodomain:error is the ONLY message the hosted page sends, and it alone " +
    "suppresses the load-timeout — the widget reports session-error, never a load failure",
  async () => {
    // Prod E2E wave 2 (2026-08-18): an expired/unknown token surfaced as
    // `load-timeout` because the hosted page's error branch posted nothing at
    // all. It now posts dodomain:error WITHOUT a preceding dodomain:ready (it
    // never mounts the flow, so claiming "ready" would be a lie — see
    // apps/web/src/lib/embed-error-signal.ts). This pins the widget half of
    // that contract: one ERROR, no READY, no late load-timeout.
    const seen: unknown[] = [];
    let closeDetail: unknown;
    const handle = showDoDomain({
      token: "dd_sess_dead",
      loadTimeoutMs: 20,
      onError: (e) => {
        seen.push(e);
      },
      onClose: (d) => {
        closeDetail = d;
      },
    });
    postToWidget({ type: "dodomain:error", code: "not_found" });
    await new Promise((r) => setTimeout(r, 70));
    assert.deepEqual(seen, [
      {
        type: "session-error",
        code: "not_found",
        hostedUrl: `${HOSTED_ORIGIN}/connect/dd_sess_dead`,
      },
    ]);
    // ...and NOT a MOUNT_BLOCKED, which is what a dead token used to look
    // like: the sheet mounted fine, so the hosted-URL fallback would only
    // send the user full-page to the same dead link.
    handle.close();
    assert.deepEqual(closeDetail, { state: "failed" });
  },
);

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
  const expected = {
    type: "load-error",
    code: "MOUNT_BLOCKED",
    hostedUrl: `${HOSTED_ORIGIN}/connect/t1`,
  };
  assert.deepEqual(err, expected);
  // the load-timeout must not ALSO fire afterward (clearLoadTimer ran)
  await new Promise((r) => setTimeout(r, 70));
  assert.deepEqual(err, expected);
});

// ── MOUNT_BLOCKED: a frame that never mounts is typed, not generic ────────
// (2026-08-17, BioFlow: a host CSP whose frame-src omitted our origin failed
// indistinguishably from every other error, so the partner had to build a
// hosted-URL fallback off a generic onError.)

test("a blocked handshake surfaces code MOUNT_BLOCKED plus the full-page hostedUrl to fall back to", async () => {
  let err: { code?: string; hostedUrl?: string } | undefined;
  showDoDomain({
    token: "dd_sess_abc",
    loadTimeoutMs: 15,
    onError: (e) => {
      err = e;
    },
  });
  await new Promise((r) => setTimeout(r, 70));
  assert.equal(err?.code, "MOUNT_BLOCKED");
  // the fallback URL is the SAME session, full-page: no embed/origin/theme
  // params (those put the hosted flow into embedded mode).
  assert.equal(err?.hostedUrl, `${HOSTED_ORIGIN}/connect/dd_sess_abc`);
});

test("hostedUrl follows a custom baseUrl and url-encodes the token", async () => {
  let err: { hostedUrl?: string } | undefined;
  showDoDomain({
    token: "dd_sess_a/b",
    baseUrl: "https://connect.acme.test/",
    loadTimeoutMs: 15,
    onError: (e) => {
      err = e;
    },
  });
  await new Promise((r) => setTimeout(r, 70));
  assert.equal(err?.hostedUrl, "https://connect.acme.test/connect/dd_sess_a%2Fb");
});

test("a host-page CSP violation naming our frame reports MOUNT_BLOCKED immediately, without waiting out the timeout", () => {
  let err: { type?: string; code?: string } | undefined;
  const handle = showDoDomain({
    token: "t1",
    loadTimeoutMs: 60_000, // long on purpose: the CSP signal must not wait for it
    onError: (e) => {
      err = e;
    },
  });
  dispatchCspViolation("frame-src", `${HOSTED_ORIGIN}/connect/t1?embed=1`);
  assert.deepEqual(err, {
    type: "load-error",
    code: "MOUNT_BLOCKED",
    hostedUrl: `${HOSTED_ORIGIN}/connect/t1`,
  });
  handle.close();
});

test("a default-src CSP violation also counts, since CSP falls back frame-src to child-src to default-src", () => {
  let err: { code?: string } | undefined;
  const handle = showDoDomain({
    token: "t1",
    loadTimeoutMs: 60_000,
    onError: (e) => {
      err = e;
    },
  });
  dispatchCspViolation("default-src 'self'", HOSTED_ORIGIN);
  assert.equal(err?.code, "MOUNT_BLOCKED");
  handle.close();
});

test("a CSP violation about some other resource on the host page is ignored", () => {
  let errored = false;
  const handle = showDoDomain({
    token: "t1",
    loadTimeoutMs: 60_000,
    onError: () => {
      errored = true;
    },
  });
  dispatchCspViolation("script-src", `${HOSTED_ORIGIN}/some-script.js`); // wrong directive
  dispatchCspViolation("frame-src", "https://ads.example.com/frame"); // wrong origin
  assert.equal(errored, false);
  handle.close();
});

test("the mount failure is reported once even when the CSP, iframe-error and timeout detectors all fire", async () => {
  let calls = 0;
  showDoDomain({
    token: "t1",
    loadTimeoutMs: 15,
    onError: () => {
      calls += 1;
    },
  });
  dispatchCspViolation("frame-src", HOSTED_ORIGIN);
  iframeEl()?.dispatchEvent(new dom.window.Event("error"));
  await new Promise((r) => setTimeout(r, 70));
  assert.equal(calls, 1);
});

// ── Stateful onClose ──────────────────────────────────────────────────────
// (2026-08-17, BioFlow: "closing proves nothing either way", so partners
// re-polled their own backend after every dismissal.)

test("onClose reports state 'verified' with the domain after a dodomain:verified message", () => {
  let detail: unknown;
  const handle = showDoDomain({
    token: "t1",
    loadTimeoutMs: 5_000,
    onClose: (d) => {
      detail = d;
    },
  });
  postToWidget({ type: "dodomain:ready" });
  postToWidget({ type: "dodomain:verified", domain: "acme.com" });
  handle.close();
  assert.deepEqual(detail, { state: "verified", domain: "acme.com" });
});

test("onClose reports state 'pending' when the flow mounted but reached no outcome", () => {
  let detail: unknown;
  const handle = showDoDomain({
    token: "t1",
    loadTimeoutMs: 5_000,
    onClose: (d) => {
      detail = d;
    },
  });
  postToWidget({ type: "dodomain:ready" });
  handle.close();
  assert.deepEqual(detail, { state: "pending" });
});

test("onClose reports state 'failed' after the flow posts dodomain:error", () => {
  let detail: unknown;
  const handle = showDoDomain({
    token: "t1",
    loadTimeoutMs: 5_000,
    onClose: (d) => {
      detail = d;
    },
  });
  postToWidget({ type: "dodomain:ready" });
  postToWidget({ type: "dodomain:error", code: "dns_mismatch" });
  handle.close();
  assert.deepEqual(detail, { state: "failed" });
});

test("a verify that succeeds after an earlier failure still closes as 'verified' (errors are retryable, not terminal)", () => {
  let detail: unknown;
  const handle = showDoDomain({
    token: "t1",
    loadTimeoutMs: 5_000,
    onClose: (d) => {
      detail = d;
    },
  });
  postToWidget({ type: "dodomain:ready" });
  postToWidget({ type: "dodomain:error", code: "dns_mismatch" });
  postToWidget({ type: "dodomain:verified", domain: "acme.com" });
  postToWidget({ type: "dodomain:error", code: "dns_mismatch" }); // late re-check noise
  handle.close();
  assert.deepEqual(detail, { state: "verified", domain: "acme.com" });
});

test("onClose reports state 'unknown' when the widget never heard from the flow at all", () => {
  let detail: unknown;
  const handle = showDoDomain({
    token: "t1",
    loadTimeoutMs: 60_000,
    onClose: (d) => {
      detail = d;
    },
  });
  handle.close();
  assert.deepEqual(detail, { state: "unknown" });
});

test("a pre-existing zero-argument onClose handler still fires unchanged (backward compatibility)", () => {
  let closedCalled = false;
  // Deliberately written the pre-2026-08-17 way — no parameter at all.
  const zeroArgOnClose = () => {
    closedCalled = true;
  };
  const handle = showDoDomain({ token: "t1", loadTimeoutMs: 5_000, onClose: zeroArgOnClose });
  postToWidget({ type: "dodomain:ready" });
  handle.close();
  assert.equal(closedCalled, true);
});

test("the in-flow dodomain:close message carries the state through onClose too", () => {
  let detail: unknown;
  showDoDomain({
    token: "t1",
    loadTimeoutMs: 5_000,
    onClose: (d) => {
      detail = d;
    },
  });
  postToWidget({ type: "dodomain:ready" });
  postToWidget({ type: "dodomain:verified", domain: "acme.com" });
  postToWidget({ type: "dodomain:close" });
  assert.deepEqual(detail, { state: "verified", domain: "acme.com" });
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
