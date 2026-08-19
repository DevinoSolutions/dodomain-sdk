# @dodomain/connect

Embeddable browser widget for [DoDomain](https://dodomain.io). Opens the hosted connect flow
in a modal iframe and relays its lifecycle events back to your app. Pairs with
[`@dodomain/node`](../node), which mints the session token on your server.

📖 **Guide with runnable examples: [dodomain.io/docs/widget](https://dodomain.io/docs/widget)**
· all docs: [dodomain.io/docs](https://dodomain.io/docs). Using React? [`@dodomain/react`](https://www.npmjs.com/package/@dodomain/react) wraps this widget in a hook.

## Install

```sh
npm install @dodomain/connect
# or: pnpm add @dodomain/connect · yarn add @dodomain/connect
```

Zero runtime dependencies, ~3KB browser bundle (dual ESM+CJS + self-contained `.d.ts`; the
bundle stays **zod-free** — see [`test/build.smoke.test.ts`](test/build.smoke.test.ts)).

## Usage

```ts
import { showDoDomain } from "@dodomain/connect";

// token comes from your server: POST /api/v1/sessions via @dodomain/node
const { token } = await fetch("/my-api/domain-session").then((r) => r.json());

const handle = showDoDomain({
  token,
  onVerified: ({ domain }) => {
    console.log("connected:", domain);
    location.reload();
  },
  onClose: ({ state }) => {
    // "verified" | "pending" | "failed" | "unknown" — closing now tells you
    // something, so you don't have to re-poll your own backend to find out.
    if (state !== "verified") keepTheConnectDomainPromptVisible();
  },
  onError: (err) => {
    if (err.code === "MOUNT_BLOCKED") {
      // The iframe never mounted (host CSP, network, content blocker).
      // Same session, full page — see "Origins & CSP" below.
      location.assign(err.hostedUrl);
      return;
    }
    console.error("connect flow failed:", err.type, err.code);
  },
});

// handle.close() to dismiss it programmatically
```

## API

### `showDoDomain(options) → { close }`

| Option          | Type                                    | Notes                                                                                                                                                                                                              |
| --------------- | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `token`         | `string`                                | Required. Session token (`dd_sess_…`) from `POST /api/v1/sessions`.                                                                                                                                                |
| `baseUrl`       | `string`                                | DoDomain origin. Defaults to `https://app.dodomain.io`.                                                                                                                                                            |
| `onVerified`    | `(detail: { domain?: string }) => void` | Fires when the domain verifies.                                                                                                                                                                                    |
| `onClose`       | `(detail: DoDomainCloseDetail) => void` | Fires when the modal is dismissed (backdrop click, in-flow close, `handle.close()`), with the session's last-known state — see below. A zero-arg `() => …` handler written against an older version keeps working. |
| `onError`       | `(detail: DoDomainWidgetError) => void` | Fires when the flow fails to load or reports a session error — see below. Absent by default (previously: silent).                                                                                                  |
| `loadTimeoutMs` | `number`                                | How long to wait for the hosted flow's load handshake before treating the embed as failed. Default `15000`.                                                                                                        |

Returns a handle with `close()`. Messages from the iframe are **origin-checked** against
`baseUrl`, so only the hosted flow can trigger callbacks. Must run in a browser.

### `onError` — `DoDomainWidgetError`

A cross-origin iframe's HTTP 404/500 doesn't fire `onerror` or expose readable content, so a
broken embed used to be entirely silent. Every `onError` detail carries a `code` and a
`hostedUrl` (the full-page flow for the same session), plus a `type`:

- `{ type: "load-timeout", code: "MOUNT_BLOCKED" }` — no load handshake arrived within
  `loadTimeoutMs` (a 404, DNS failure, offline network, content blocker, or a host-page CSP —
  anything that never gets far enough to run the hosted flow's own JS).
- `{ type: "load-error", code: "MOUNT_BLOCKED" }` — a faster signal for the same fact: the
  iframe's own `error` event fired, **or** your page's CSP reported blocking the frame
  (`securitypolicyviolation` on `frame-src`/`child-src`/`default-src`), which lands in
  milliseconds instead of waiting out `loadTimeoutMs`.
- `{ type: "session-error", code: string }` — the hosted page loaded and reported a failure.
  `code` matches the same vocabulary the hosted page's own in-page error banner uses
  (`expired`, `not_found`, `invalid_request`, `internal`). Two producers: a `verify()` call
  failing mid-flow, and — since 2026-08-18 — a token that was **already dead when the sheet
  opened** (`expired` / `not_found`), which previously reached you as a misleading
  `load-timeout` instead. Treat this one as terminal: close the sheet and mint a fresh session
  rather than retrying the same token.

**`code === "MOUNT_BLOCKED"` is the one check you need for "the embed is impossible here":**
the sheet never came up, so nothing the user does inside it can succeed — send them to
`err.hostedUrl` instead. It is deliberately not called `CSP_BLOCKED`: from the parent page a
CSP block, a DNS failure and an ad blocker are indistinguishable, and all four want the same
fallback.

### `onClose` — `DoDomainCloseDetail`

`onClose` receives `{ state, domain? }`, derived from the flow's own postMessage traffic, so a
dismissal is informative instead of ambiguous:

| `state`    | Meaning                                                                                             |
| ---------- | --------------------------------------------------------------------------------------------------- |
| `verified` | The flow reported the domain verified (`domain` is set). Sticky — a later error can't downgrade it. |
| `pending`  | The flow mounted, but the user closed it before any outcome.                                        |
| `failed`   | The flow reported an error (e.g. a `verify()` failure) and never verified.                          |
| `unknown`  | The widget never heard from the flow at all — pair this with a `MOUNT_BLOCKED` `onError`.           |

The signed `connection.verified` webhook remains the source of truth; `state` is a UI cue, and
anything in a browser can be spoofed.

## Origins & CSP

The widget loads the hosted flow in an iframe from **one** origin, so a Content-Security-Policy
on your page must allow it in `frame-src` (browsers fall back to `child-src`, then
`default-src`, so allow it in whichever of those you actually set):

```
Content-Security-Policy: frame-src https://app.dodomain.io;
```

- `https://app.dodomain.io` is the production origin — the value of `DODOMAIN_DEFAULT_ORIGIN`
  ([`packages/core/src/origin.ts`](../core/src/origin.ts)), which is what `baseUrl` defaults to
  and the single place this repo defines it. `api.dodomain.io` and `connect.dodomain.io` are
  cosmetic names for the same deployment and are **not** served today — don't allowlist them.
- If you pass your own `baseUrl` (self-hosted or staging), allowlist that origin instead.
- The widget injects no scripts, styles, fonts or images into your page, so `frame-src` is the
  only directive it needs. It does listen for your page's own `securitypolicyviolation` events
  to detect a block early — a read-only listener, nothing is reported anywhere.

### Hosted-URL fallback

If the frame can't mount, fall back to the same session full-page — no second API call, the
token is already yours:

```ts
showDoDomain({
  token,
  onError: (err) => {
    if (err.code === "MOUNT_BLOCKED") location.assign(err.hostedUrl); // {baseUrl}/connect/{token}
  },
});
```

`hostedUrl` deliberately omits the `embed`/`origin`/`theme` query params the iframe carries:
those put the flow into embedded mode, which is wrong for a top-level navigation. Pass
`returnUrl` when you mint the session so the user lands back in your app afterwards.

See [`src/index.ts`](src/index.ts) for the implementation.
