// Compile-time pins: the import-free public types (public-types.ts) must stay
// mutually assignable with the core zod schemas they mirror — the F-008
// one-schema rule enforced at the type level. This file is typecheck-only:
// it is inside tsconfig's include (so `pnpm typecheck` — and therefore
// prepublishOnly — fails on drift) but is never imported by the entry, so
// nothing here reaches dist or the published d.ts.

import type { verifyWebhook as coreVerifyWebhook } from "@dodomain/core/webhook";
import type { SessionRecord } from "@dodomain/core/records";
import type {
  zCreateSessionInput,
  CreateSessionResponse as CoreCreateSessionResponse,
} from "@dodomain/core/schemas";
import type { z } from "zod";

import type { CreateSessionInput, DnsRecord, Session, VerifyWebhook } from "./public-types.ts";

type Expect<T extends true> = T;
type MutuallyAssignable<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;

// Exported so the pins are live code to the typechecker (not unused types) —
// this name is deliberately NOT re-exported from index.ts.
export type SchemaParityPins = [
  Expect<MutuallyAssignable<DnsRecord, SessionRecord>>,
  Expect<MutuallyAssignable<CreateSessionInput, z.infer<typeof zCreateSessionInput>>>,
  Expect<MutuallyAssignable<Session, CoreCreateSessionResponse>>,
  Expect<MutuallyAssignable<VerifyWebhook, typeof coreVerifyWebhook>>,
];
