// The SDK's error types. Their own module (not index.ts) so keyless.ts can
// throw them without an import cycle back through the entry point.

export class DoDomainError extends Error {
  readonly status: number;
  readonly body: unknown;
  constructor(message: string, status: number, body: unknown) {
    super(message);
    this.name = "DoDomainError";
    this.status = status;
    this.body = body;
  }
}

/**
 * The codes a keyless failure carries. The first seven are the API's own
 * (`body.code` on a keyless refusal); the last five are raised by this SDK
 * before or instead of a request, always with `status: 0`.
 */
export type KeylessErrorCode =
  | "KEYLESS_PROOF_REQUIRED"
  | "KEYLESS_LIMIT_REACHED"
  | "KEYLESS_START_RATE_LIMITED"
  | "KEYLESS_CAPACITY_REACHED"
  | "KEYLESS_KEY_CLAIMED"
  | "KEYLESS_KEY_NOT_ACCEPTED"
  | "KEYLESS_DISABLED"
  | "KEYLESS_PROOF_TIMEOUT"
  | "KEYLESS_PROOF_ABORTED"
  | "KEYLESS_PROOF_UNSUPPORTED"
  | "KEYLESS_KEY_MISSING"
  | "KEYLESS_MODE";

/**
 * A keyless-start failure: a `KEYLESS_*` refusal from the API, or one this SDK
 * raised itself (`status: 0`, no request sent). Still a `DoDomainError`, so an
 * existing `instanceof DoDomainError` branch keeps catching it; branch on
 * `code` for the keyless specifics. `details` is the refusal's `details`
 * object (the limit, what unlocks more, `claimUrl` / `signUpUrl`), when the
 * API sent one.
 */
export class DoDomainKeylessError extends DoDomainError {
  readonly code: KeylessErrorCode;
  readonly details: Record<string, unknown> | undefined;
  constructor(
    message: string,
    status: number,
    body: unknown,
    code: KeylessErrorCode,
    details?: Record<string, unknown>,
  ) {
    super(message, status, body);
    this.name = "DoDomainKeylessError";
    this.code = code;
    this.details = details;
  }
}

const API_KEYLESS_CODES: ReadonlySet<string> = new Set<KeylessErrorCode>([
  "KEYLESS_PROOF_REQUIRED",
  "KEYLESS_LIMIT_REACHED",
  "KEYLESS_START_RATE_LIMITED",
  "KEYLESS_CAPACITY_REACHED",
  "KEYLESS_KEY_CLAIMED",
  "KEYLESS_KEY_NOT_ACCEPTED",
  "KEYLESS_DISABLED",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** A keyless key anywhere in a string: the prefix and its secret part. */
const KEYLESS_KEY_PATTERN = /dd_ks_[A-Za-z0-9_-]+/g;

/** What a redacted keyless key reads as: the prefix only. */
const REDACTED_KEYLESS_KEY = "dd_ks_…";

/**
 * A copy of `value` with every `dd_ks_` key cut to its prefix (`dd_ks_…`),
 * in every string at any depth (a refusal's `details.unlock.claimUrl`
 * carries the key after its `#`). Errors are logged, reported and pasted into
 * issues; the key is a bearer credential for the keyless app, so an error must
 * never carry it whole. Successful responses are left alone: the caller needs
 * the key and the claim link from those.
 */
export function redactKeylessKeys(value: unknown): unknown {
  if (typeof value === "string") return value.replace(KEYLESS_KEY_PATTERN, REDACTED_KEYLESS_KEY);
  if (Array.isArray(value)) return value.map(redactKeylessKeys);
  if (isRecord(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([name, inner]) => [name, redactKeylessKeys(inner)]),
    );
  }
  return value;
}

/** The error a non-2xx JSON answer becomes: typed when the body names a
 * keyless code, the plain `DoDomainError` otherwise. Any `dd_ks_` key in the
 * answer is redacted (redactKeylessKeys) before it reaches the error. */
export function errorFromResponse(status: number, json: unknown): DoDomainError {
  const redacted = redactKeylessKeys(json);
  const body = isRecord(redacted) ? redacted : {};
  const message = typeof body.error === "string" ? body.error : `HTTP ${status}`;
  if (typeof body.code === "string" && API_KEYLESS_CODES.has(body.code)) {
    return new DoDomainKeylessError(
      message,
      status,
      redacted,
      body.code as KeylessErrorCode,
      isRecord(body.details) ? body.details : undefined,
    );
  }
  return new DoDomainError(message, status, redacted);
}
