// The SDK's error types. Their own module (not index.ts) so keyless.ts can
// throw them without an import cycle back through the entry point.

/** The API's machine-readable values on a refusal, when it sent them. */
export interface DoDomainErrorFields {
  /** The machine error (`body.error`, e.g. `"invalid_request"`, `"quota_exceeded"`). */
  error?: string;
  /** The stable denial code (`body.code`, e.g. `"KEYLESS_LIMIT_REACHED"`). */
  code?: string;
}

/**
 * Any failed call. For an API refusal, `message` is the machine error followed
 * by the API's own human text (`"invalid_request: \"customer.com\" is a
 * placeholder ..."`), so a logged `e.message` says what went wrong and what to
 * do; with no human text it is the machine error alone, or `HTTP <status>`.
 * Branch on `error` and `code` rather than parsing `message`. `error` and
 * `code` are `undefined` on errors this SDK raised itself (`status: 0`) and on
 * answers that carry none.
 */
export class DoDomainError extends Error {
  readonly status: number;
  readonly body: unknown;
  readonly error: string | undefined;
  readonly code: string | undefined;
  constructor(message: string, status: number, body: unknown, fields: DoDomainErrorFields = {}) {
    super(message);
    this.name = "DoDomainError";
    this.status = status;
    this.body = body;
    this.error = fields.error;
    this.code = fields.code;
  }
}

/**
 * The codes a keyless failure carries. The first eight are the API's own
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
  | "KEYLESS_PLACEHOLDER_DOMAIN"
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
  declare readonly code: KeylessErrorCode;
  readonly details: Record<string, unknown> | undefined;
  constructor(
    message: string,
    status: number,
    body: unknown,
    code: KeylessErrorCode,
    details?: Record<string, unknown>,
    error?: string,
  ) {
    super(message, status, body, { code, error });
    this.name = "DoDomainKeylessError";
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
  "KEYLESS_PLACEHOLDER_DOMAIN",
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

/** The human text of a refusal: RFC 9457 `detail`, else the house `message`. */
function humanText(body: Record<string, unknown>): string | undefined {
  for (const text of [body.detail, body.message]) {
    if (typeof text === "string" && text.trim() !== "") return text.trim();
  }
  return undefined;
}

/** The error a non-2xx JSON answer becomes: typed when the body names a
 * keyless code, the plain `DoDomainError` otherwise. Any `dd_ks_` key in the
 * answer is redacted (redactKeylessKeys) before it reaches the error, the
 * message included: it is built from the redacted body. */
export function errorFromResponse(status: number, json: unknown): DoDomainError {
  const redacted = redactKeylessKeys(json);
  const body = isRecord(redacted) ? redacted : {};
  const error = typeof body.error === "string" ? body.error : undefined;
  const code = typeof body.code === "string" ? body.code : undefined;
  const human = humanText(body);
  const machine = error ?? `HTTP ${status}`;
  const message = human === undefined || human === machine ? machine : `${machine}: ${human}`;
  if (code !== undefined && API_KEYLESS_CODES.has(code)) {
    return new DoDomainKeylessError(
      message,
      status,
      redacted,
      code as KeylessErrorCode,
      isRecord(body.details) ? body.details : undefined,
      error,
    );
  }
  return new DoDomainError(message, status, redacted, { error, code });
}
