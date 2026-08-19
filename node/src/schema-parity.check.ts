// Compile-time pins: the import-free public types (public-types.ts) must stay
// mutually assignable with the core zod schemas they mirror — the F-008
// one-schema rule enforced at the type level. This file is typecheck-only:
// it is inside tsconfig's include (so `pnpm typecheck` — and therefore
// prepublishOnly — fails on drift) but is never imported by the entry, so
// nothing here reaches dist or the published d.ts.

import type { verifyWebhook as coreVerifyWebhook } from "@dodomain/core/webhook";
import type { SessionRecord } from "@dodomain/core/records";
import type {
  zCheckDomainInput,
  zCreateSessionInput,
  zListConnectionsQuery,
  zProviderGuide,
  CheckDomainResponse as CoreCheckDomainResponse,
  CreateSessionResponse as CoreCreateSessionResponse,
  ConnectionSummary as CoreConnectionSummary,
  DeleteWebhookEndpointResponse as CoreDeleteWebhookEndpointResponse,
  DisconnectConnectionResponse as CoreDisconnectConnectionResponse,
  IntegratorSession as CoreIntegratorSession,
  ListAppsResponse as CoreListAppsResponse,
  ListConnectionsResponse as CoreListConnectionsResponse,
  ListWebhookEndpointsResponse as CoreListWebhookEndpointsResponse,
  ReverifyConnectionResponse as CoreReverifyConnectionResponse,
  RotateAppSecretKeyResponse as CoreRotateAppSecretKeyResponse,
  WebhookEndpointInput as CoreWebhookEndpointInput,
  WebhookEndpointSecretResponse as CoreWebhookEndpointSecretResponse,
  WebhookEndpointSummary as CoreWebhookEndpointSummary,
  WebhookEvent as CoreWebhookEvent,
  WebhookEventType as CoreWebhookEventType,
  WebhookEventWire as CoreWebhookEventWire,
} from "@dodomain/core/schemas";
import type { z } from "zod";

import type {
  CheckDomainInput,
  CheckDomainResult,
  Connection,
  CreateSessionInput,
  DeleteWebhookEndpointResult,
  DisconnectConnectionResult,
  DnsRecord,
  IntegratorSession,
  ListAppsResult,
  ListConnectionsInput,
  ListConnectionsResult,
  ListWebhookEndpointsResult,
  ProviderGuide,
  ReverifyConnectionResult,
  RotateSecretKeyResult,
  Session,
  VerifyWebhook,
  WebhookEndpoint,
  WebhookEndpointInput,
  WebhookEndpointWithSecret,
  WebhookEvent,
  WebhookEventType,
  WebhookEventWire,
} from "./public-types.ts";

type Expect<T extends true> = T;
type MutuallyAssignable<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;

// Exported so the pins are live code to the typechecker (not unused types) —
// this name is deliberately NOT re-exported from index.ts.
export type SchemaParityPins = [
  Expect<MutuallyAssignable<DnsRecord, SessionRecord>>,
  Expect<MutuallyAssignable<CreateSessionInput, z.infer<typeof zCreateSessionInput>>>,
  Expect<MutuallyAssignable<Session, CoreCreateSessionResponse>>,
  Expect<MutuallyAssignable<VerifyWebhook, typeof coreVerifyWebhook>>,
  // connections namespace (2026-08-17). The list FILTERS pin against z.input,
  // not z.infer: `limit`/`includeDisconnected` carry schema defaults, so the
  // output type has them required while a caller legitimately omits both.
  Expect<MutuallyAssignable<ListConnectionsInput, z.input<typeof zListConnectionsQuery>>>,
  Expect<MutuallyAssignable<Connection, CoreConnectionSummary>>,
  Expect<MutuallyAssignable<ListConnectionsResult, CoreListConnectionsResponse>>,
  Expect<MutuallyAssignable<DisconnectConnectionResult, CoreDisconnectConnectionResponse>>,
  Expect<MutuallyAssignable<ReverifyConnectionResult, CoreReverifyConnectionResponse>>,
  // Webhook envelope types (2026-08-17): partners were hand-writing these from
  // the docs, which is how a receiver silently drifts from what we send.
  Expect<MutuallyAssignable<WebhookEventType, CoreWebhookEventType>>,
  Expect<MutuallyAssignable<WebhookEvent, CoreWebhookEvent>>,
  Expect<MutuallyAssignable<WebhookEventWire, CoreWebhookEventWire>>,
  // Full v1 parity (0.3.0): the remaining integrator-callable surface — the
  // authed session read, apps, the domain pre-flight, webhook-endpoint
  // lifecycle and key rotation. Same one-schema rule; a route contract that
  // moves without this file moving fails `pnpm typecheck`.
  Expect<MutuallyAssignable<IntegratorSession, CoreIntegratorSession>>,
  Expect<MutuallyAssignable<ListAppsResult, CoreListAppsResponse>>,
  // The check INPUT pins against z.input: `domain` carries a `.trim()`
  // transform, so z.infer describes what the server sees, not what a caller
  // may hand us (the ListConnectionsInput reasoning).
  Expect<MutuallyAssignable<CheckDomainInput, z.input<typeof zCheckDomainInput>>>,
  Expect<MutuallyAssignable<CheckDomainResult, CoreCheckDomainResponse>>,
  Expect<MutuallyAssignable<ProviderGuide, z.infer<typeof zProviderGuide>>>,
  Expect<MutuallyAssignable<WebhookEndpoint, CoreWebhookEndpointSummary>>,
  Expect<MutuallyAssignable<ListWebhookEndpointsResult, CoreListWebhookEndpointsResponse>>,
  Expect<MutuallyAssignable<WebhookEndpointInput, CoreWebhookEndpointInput>>,
  Expect<MutuallyAssignable<WebhookEndpointWithSecret, CoreWebhookEndpointSecretResponse>>,
  Expect<MutuallyAssignable<DeleteWebhookEndpointResult, CoreDeleteWebhookEndpointResponse>>,
  Expect<MutuallyAssignable<RotateSecretKeyResult, CoreRotateAppSecretKeyResponse>>,
];
