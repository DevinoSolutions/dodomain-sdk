// Keyless start (T-18036): the proof of work an anonymous
// `POST /api/v1/keyless/sessions` must carry, solved on this machine.
//
// The API answers a first call without a key `428 KEYLESS_PROOF_REQUIRED` with
// a challenge: find a decimal nonce such that SHA-256 over the UTF-8 bytes of
// `<challenge>:<nonce>` starts with `difficultyBits` zero bits, then send the
// same request again with the header `DoDomain-Keyless-Proof:
// <challenge>:<nonce>`. The server asks for 20 bits normally, 22 when busy and
// never more than 24 (apps/web/src/lib/keyless-proof.ts), which is about 1 to
// 60 seconds on one core. The search runs in slices that yield to the event
// loop, so it can be aborted and timed out, and never blocks a server's other
// requests for more than a few milliseconds.

import * as nodeCrypto from "node:crypto";

import { DoDomainKeylessError } from "./errors.ts";

/** The hardest proof the API ever asks for. A challenge above it is refused
 * here rather than searched for minutes. */
export const KEYLESS_MAX_DIFFICULTY_BITS = 24;

/** How long a solve may take by default: past the worst case at 24 bits on a
 * slow core, inside the challenge's 5-minute life. */
export const KEYLESS_PROOF_DEFAULT_TIMEOUT_MS = 120_000;

/** The longest `proofTimeoutMs` a client accepts: a challenge lives 5 minutes,
 * so a proof found later is refused as expired anyway. */
export const KEYLESS_PROOF_MAX_TIMEOUT_MS = 300_000;

/** Hashes per slice between two yields to the event loop. */
const SLICE = 4096;

export interface SolveKeylessProofOptions {
  /** Abort the search; it rejects with `KEYLESS_PROOF_ABORTED`. */
  signal?: AbortSignal;
  /** Give up after this many milliseconds with `KEYLESS_PROOF_TIMEOUT`
   * (default 120 000). */
  timeoutMs?: number;
}

type HexSha256 = (input: string) => string;

/** The node:crypto surface the solver uses, so both branches are testable. */
export interface Sha256Source {
  hash?: (algorithm: string, data: string, outputEncoding?: "hex") => string;
  createHash: typeof nodeCrypto.createHash;
}

/** SHA-256 as hex: the one-shot `crypto.hash` where it exists (Node 21.7+,
 * measurably faster for short inputs), `createHash` otherwise (Node 20). */
export function pickSha256(source: Sha256Source): HexSha256 {
  const oneShot = source.hash;
  if (typeof oneShot === "function") return (input) => oneShot("sha256", input, "hex");
  return (input) => source.createHash("sha256").update(input).digest("hex");
}

const sha256Hex = pickSha256(nodeCrypto as unknown as Sha256Source);

/** Whether a hex digest starts with `bits` zero bits (1 to 24). */
function hasLeadingZeroBits(hex: string, bits: number): boolean {
  return Number.parseInt(hex.slice(0, 8), 16) >>> (32 - bits) === 0;
}

function yieldToEventLoop(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

function unsupported(message: string): DoDomainKeylessError {
  return new DoDomainKeylessError(
    "keyless_proof_unsupported",
    0,
    { message },
    "KEYLESS_PROOF_UNSUPPORTED",
  );
}

/**
 * Solve one keyless proof-of-work challenge. Resolves with the FULL header
 * value, `<challenge>:<nonce>`, for the smallest nonce that works. Rejects
 * with a `DoDomainKeylessError` (`status: 0`): `KEYLESS_PROOF_UNSUPPORTED` for
 * an empty challenge or a difficulty outside 0 to 24, `KEYLESS_PROOF_ABORTED`
 * when `signal` fires, `KEYLESS_PROOF_TIMEOUT` past `timeoutMs`.
 */
export async function solveKeylessProof(
  challenge: string,
  difficultyBits: number,
  options: SolveKeylessProofOptions = {},
): Promise<string> {
  if (typeof challenge !== "string" || challenge === "") {
    throw unsupported("The challenge is empty.");
  }
  if (
    !Number.isInteger(difficultyBits) ||
    difficultyBits < 0 ||
    difficultyBits > KEYLESS_MAX_DIFFICULTY_BITS
  ) {
    throw unsupported(
      `difficultyBits must be a whole number from 0 to ${KEYLESS_MAX_DIFFICULTY_BITS}, got ${String(difficultyBits)}.`,
    );
  }
  const { signal } = options;
  const timeoutMs = options.timeoutMs ?? KEYLESS_PROOF_DEFAULT_TIMEOUT_MS;
  const deadline = Date.now() + timeoutMs;
  const prefix = `${challenge}:`;
  if (difficultyBits === 0) return `${prefix}0`;

  for (let nonce = 0; ;) {
    if (signal?.aborted) {
      throw new DoDomainKeylessError(
        "keyless_proof_aborted",
        0,
        { message: "The proof-of-work search was aborted." },
        "KEYLESS_PROOF_ABORTED",
      );
    }
    if (Date.now() > deadline) {
      throw new DoDomainKeylessError(
        "keyless_proof_timeout",
        0,
        {
          message: `No proof found within ${timeoutMs} ms at ${difficultyBits} bits. Retry later, or create a free account and use an API key.`,
        },
        "KEYLESS_PROOF_TIMEOUT",
      );
    }
    const end = nonce + SLICE;
    for (; nonce < end; nonce++) {
      if (hasLeadingZeroBits(sha256Hex(prefix + nonce), difficultyBits)) return prefix + nonce;
    }
    await yieldToEventLoop();
  }
}

/** The fields of a `428 KEYLESS_PROOF_REQUIRED` answer the solver needs. */
export interface KeylessProofChallenge {
  challenge: string;
  difficultyBits: number;
  /** The request header the proof goes in (`DoDomain-Keyless-Proof`). */
  header: string;
}

/** Read the challenge out of a 428's `details`, or throw the error unchanged
 * when it does not carry one the solver can use. */
export function readProofChallenge(error: DoDomainKeylessError): KeylessProofChallenge {
  const details = error.details ?? {};
  const { challenge, difficultyBits, header, algorithm } = details;
  if (
    typeof challenge !== "string" ||
    typeof difficultyBits !== "number" ||
    typeof header !== "string" ||
    header === "" ||
    (algorithm !== undefined && algorithm !== "sha256")
  ) {
    throw error;
  }
  return { challenge, difficultyBits, header };
}
