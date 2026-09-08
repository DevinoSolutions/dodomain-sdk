// Narrowing helpers for Cloudflare's JSON responses.
//
// Cloudflare's bodies arrive as `unknown` (JSON.parse). These two guards are the
// ONLY way this connector reads a field off one: no `any`, no cast that claims
// more than was checked. A missing/oddly-shaped field reads as `undefined` and
// the caller's own check throws a CfDnsError/CfOAuthError with the raw text —
// which is the failure mode we want, rather than a `TypeError: undefined is not
// an object` three frames deeper.

/** True when the parsed body is a plain JSON object (not null, not an array). Internal to this module. */
function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Read one field off a parsed body, or `undefined` if the body isn't an object. */
export function readField(value: unknown, key: string): unknown {
  return isJsonObject(value) ? value[key] : undefined;
}

/**
 * Render an upstream field for an error message. Absent/null reads as "" so the
 * caller can fall back to the raw body; anything non-string is JSON-encoded
 * rather than allowed to become the useless "[object Object]".
 */
export function describeField(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === undefined || value === null) return "";
  return JSON.stringify(value) ?? "";
}
