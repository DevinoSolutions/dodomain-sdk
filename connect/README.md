# @dodomain/connect

Embeddable browser widget for [DoDomain](https://dodomain.io). Opens the hosted connect flow
in a modal iframe and relays its lifecycle events back to your app. Pairs with
[`@dodomain/node`](../node), which mints the session token on your server.

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
  onClose: () => console.log("user closed the modal"),
  onError: (err) => {
    // { type: "load-timeout" } | { type: "load-error" } | { type: "session-error", code }
    console.error("connect flow failed to load:", err);
  },
});

// handle.close() to dismiss it programmatically
```

## API

### `showDoDomain(options) → { close }`

| Option          | Type                                    | Notes                                                                                                             |
| --------------- | --------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `token`         | `string`                                | Required. Session token (`dd_sess_…`) from `POST /api/v1/sessions`.                                               |
| `baseUrl`       | `string`                                | DoDomain origin. Defaults to `https://app.dodomain.io`.                                                           |
| `onVerified`    | `(detail: { domain?: string }) => void` | Fires when the domain verifies.                                                                                   |
| `onClose`       | `() => void`                            | Fires when the modal is dismissed (backdrop click or in-flow close).                                              |
| `onError`       | `(detail: DoDomainWidgetError) => void` | Fires when the flow fails to load or reports a session error — see below. Absent by default (previously: silent). |
| `loadTimeoutMs` | `number`                                | How long to wait for the hosted flow's load handshake before treating the embed as failed. Default `15000`.       |

Returns a handle with `close()`. Messages from the iframe are **origin-checked** against
`baseUrl`, so only the hosted flow can trigger callbacks. Must run in a browser.

### `onError` — `DoDomainWidgetError`

A cross-origin iframe's HTTP 404/500 doesn't fire `onerror` or expose readable content, so a
broken embed used to be entirely silent. `onError` now fires with one of:

- `{ type: "load-timeout" }` — no load handshake arrived within `loadTimeoutMs` (covers a 404,
  DNS failure, or a hang — anything that never gets far enough to run the hosted flow's own JS).
- `{ type: "load-error" }` — the iframe's own `error` event fired (best-effort; rarely fires for a
  cross-origin navigation, but free to listen for).
- `{ type: "session-error", code: string }` — the flow loaded but reported a failure (e.g. a
  `verify()` call failing mid-flow). `code` matches the same vocabulary the hosted page's own
  in-page error banner uses (`expired`, `not_found`, `invalid_request`, `internal`).

See [`src/index.ts`](src/index.ts) for the implementation.
