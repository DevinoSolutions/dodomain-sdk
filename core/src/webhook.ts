import { createHmac, timingSafeEqual } from "node:crypto";

// Stripe-style signature: header "t=<unixMs>,v1=<hex hmac of `${t}.${body}`>".
// Replay-protected by the timestamp (verify side rejects old t).
export function signWebhook(secret: string, body: string, tsMs: number): string {
  const v1 = createHmac("sha256", secret).update(`${tsMs}.${body}`).digest("hex");
  return `t=${tsMs},v1=${v1}`;
}

export function verifyWebhook(
  secret: string,
  body: string,
  header: string,
  toleranceMs = 5 * 60 * 1000,
  nowMs = Date.now(),
): boolean {
  const parts = Object.fromEntries(
    header.split(",").map((kv) => kv.split("=").map((s) => s.trim())),
  );
  const t = Number(parts.t);
  if (!t || Math.abs(nowMs - t) > toleranceMs) return false;
  const got = String(parts.v1 ?? "");
  // Shape-gate the header value BEFORE building buffers. `expected` is always
  // 64 lowercase hex chars, but a JS string LENGTH check does not bound the
  // BYTE length: Buffer.from is utf-8, so a 64-character v1 containing any
  // multi-byte codepoint yields a longer buffer and timingSafeEqual throws
  // RangeError — inside the INTEGRATOR's request handler, turning an attacker-
  // controlled header into a 500. A malformed signature is not an error, it is
  // a failed verification, so it returns false like every other mismatch.
  if (!/^[0-9a-f]{64}$/.test(got)) return false;
  const expected = createHmac("sha256", secret).update(`${t}.${body}`).digest("hex");
  return timingSafeEqual(Buffer.from(got, "hex"), Buffer.from(expected, "hex"));
}
