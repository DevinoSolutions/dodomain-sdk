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

Every release published from this repo carries a **provenance attestation** linking the
package on npm back to the exact commit and workflow run that built it.

**This is a read-only mirror**, synced from the private DoDomain monorepo (the source of
truth) — pull requests here cannot be merged directly, but **issues are welcome** and are
triaged like any other. Anything edited here is overwritten by the next sync.

[`core/`](core/) is the shared protocol engine the SDKs are built against. It is **not a
published package** and is not intended to be depended on directly — it lives here only so
this repo can build the three packages above. Its compiled form already ships inside them.

Product: [dodomain.io](https://dodomain.io) · Docs: [dodomain.io/docs](https://dodomain.io/docs)
