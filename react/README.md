# @dodomain/react

Official React bindings for [DoDomain](https://dodomain.io) — a hook (and a drop-in button)
around the [`@dodomain/connect`](https://www.npmjs.com/package/@dodomain/connect) modal widget.
Pairs with [`@dodomain/node`](https://www.npmjs.com/package/@dodomain/node), which mints the
session token on your server. Full product docs: [dodomain.io/docs](https://dodomain.io/docs).

## Install

```sh
npm install @dodomain/react
# or: pnpm add @dodomain/react · yarn add @dodomain/react
```

Peer dependency: `react >= 18`. The only runtime dependency is `@dodomain/connect` itself —
this package is a thin layer of glue (~1KB), the widget is **not** bundled twice, and both
stay zod-free.

## Usage

```tsx
import { useDoDomainConnect, MOUNT_BLOCKED } from "@dodomain/react";

function ConnectDomainCard({ token }: { token: string }) {
  // token comes from your server: POST /api/v1/sessions via @dodomain/node
  const { open, isOpen } = useDoDomainConnect({
    token,
    onVerified: ({ domain }) => console.log("connected:", domain),
    onClose: ({ state }) => {
      if (state !== "verified") keepTheConnectDomainPromptVisible();
    },
    onError: (err) => {
      // The iframe never mounted (host CSP, network, content blocker):
      // same session, full page instead.
      if (err.code === MOUNT_BLOCKED) location.assign(err.hostedUrl);
    },
  });

  return (
    <button onClick={open} disabled={isOpen}>
      Connect your domain
    </button>
  );
}
```

Or, when all you need is a trigger, the unstyled drop-in:

```tsx
import { DoDomainConnectButton } from "@dodomain/react";

<DoDomainConnectButton token={token} onVerified={() => refetch()} className="btn">
  Connect your domain
</DoDomainConnectButton>;
```

## Why a hook (not a modal component)

The widget's own API is imperative — `showDoDomain()` opens a modal iframe over the page and
returns a close handle — so the honest React shape is a hook that owns that handle's
lifecycle. Beyond forwarding the call, the hook guarantees:

- **Latest-props callbacks** — the widget receives stable wrappers that read the _current_
  render's handlers at fire time, so a re-render while the modal is open never strands a
  stale closure. Inline arrow handlers are fine; no `useCallback` needed.
- **One modal at a time** — `open()` while already open is a no-op; a double-click can't
  stack two backdrops.
- **Unmount cleanup** — if the owning component unmounts while the modal is open, the modal
  is torn down through the widget's own close path (`onClose` still fires with the
  last-known state) instead of orphaning a full-screen iframe. StrictMode-safe.

## API

### `useDoDomainConnect(options) → { open, close, isOpen }`

`options` is exactly the widget's
[`ShowDoDomainOptions`](https://www.npmjs.com/package/@dodomain/connect):

| Option          | Type                                    | Notes                                                                      |
| --------------- | --------------------------------------- | -------------------------------------------------------------------------- |
| `token`         | `string`                                | Required. Session token (`dd_sess_…`) from `POST /api/v1/sessions`.        |
| `baseUrl`       | `string`                                | DoDomain origin. Defaults to `https://app.dodomain.io`.                    |
| `theme`         | `"light" \| "dark"`                     | Pass the theme your page is rendering so the sheet matches it.             |
| `onVerified`    | `(detail: { domain?: string }) => void` | Fires when the domain verifies.                                            |
| `onClose`       | `(detail: DoDomainCloseDetail) => void` | Fires on every dismissal, with the session's last-known state.             |
| `onError`       | `(detail: DoDomainWidgetError) => void` | Fires when the flow fails to load or reports a session error.              |
| `loadTimeoutMs` | `number`                                | Load-handshake timeout before the embed counts as failed. Default `15000`. |

Returns:

| Field    | Type         | Notes                                                                                                              |
| -------- | ------------ | ------------------------------------------------------------------------------------------------------------------ |
| `open`   | `() => void` | Opens the modal with the current render's options. No-op while open. Browser-only — call it from an event handler. |
| `close`  | `() => void` | Dismisses programmatically (fires `onClose`, like the widget's `handle.close()`).                                  |
| `isOpen` | `boolean`    | Whether the modal is currently mounted.                                                                            |

The error/close vocabulary (`MOUNT_BLOCKED`, `DoDomainWidgetError`, `DoDomainCloseDetail`,
`DoDomainSessionState`, `ShowDoDomainOptions`) is re-exported from `@dodomain/connect`, so
this package is the only import a React app needs. The widget's own README documents the
semantics — origin-checked messages, the `MOUNT_BLOCKED` hosted-URL fallback, and the
`frame-src https://app.dodomain.io` CSP requirement all apply unchanged.

### `<DoDomainConnectButton {...options} />`

A plain unstyled `<button type="button">` wired to the hook. Extra props: `children` (label,
defaults to "Connect your domain"), `className`, `disabled`. It disables itself while the
modal is open.

See [`src/index.ts`](src/index.ts) for the implementation.
