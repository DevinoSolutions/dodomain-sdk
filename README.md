# DoDomain SDKs

Source for the published DoDomain SDKs:

- [`@dodomain/node`](https://www.npmjs.com/package/@dodomain/node) — server-side SDK
  ([`node/`](node/)): mint domain-connect sessions, verify signed webhooks.
- [`@dodomain/connect`](https://www.npmjs.com/package/@dodomain/connect) — browser widget
  ([`connect/`](connect/)): opens the hosted connect flow in a modal iframe.
- [`@dodomain/react`](https://www.npmjs.com/package/@dodomain/react) — React bindings
  ([`react/`](react/)): a hook (and drop-in button) around the widget.

Install from npm (`npm install @dodomain/node` / `npm install @dodomain/connect` /
`npm install @dodomain/react`) — each package's own README documents its API. MIT-licensed.

**This is a read-only mirror**, synced from the private DoDomain monorepo (the source of
truth) — pull requests here cannot be merged directly, but **issues are welcome** and are
triaged like any other. The private `@dodomain/core` build dependency is not mirrored (it is
inlined into the published bundles), so this repo is for reading the SDK source, not building
it. Releases are published from the monorepo.

Product: [dodomain.io](https://dodomain.io) · Docs: [app.dodomain.io](https://app.dodomain.io)
