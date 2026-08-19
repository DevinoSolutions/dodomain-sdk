// Domain Connect synchronous-flow request signing.
//
// Per the spec + Cloudflare docs (verified 2026-06-25): when a template sets
// `syncPubKeyDomain`, the apply request MUST be signed. The DNS Provider fetches
// the public key from a TXT record at `{key}.{syncPubKeyDomain}` and verifies the
// signature over the query string. The widely-deployed scheme (GoDaddy, Cloudflare)
// is RSASSA-PKCS1-v1_5 with SHA-256; the IETF draft generalises the algorithm via
// key-record fields, so this is implemented as the default/pluggable signer.
//
// SECURITY: the private key NEVER leaves the server. It is never sent to the
// browser and never logged.

import { createSign, createVerify, generateKeyPairSync } from "node:crypto";

export interface KeyPair {
  publicKeyPem: string;
  privateKeyPem: string;
}

export function generateKeyPair(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKeyPem: publicKey, privateKeyPem: privateKey };
}

/** Sign the exact query-string payload. Returns base64 signature. */
export function signQueryString(privateKeyPem: string, payload: string): string {
  const s = createSign("RSA-SHA256");
  s.update(payload, "utf8");
  s.end();
  return s.sign(privateKeyPem, "base64");
}

/** Verify a signature — used by tests and (conceptually) by the DNS Provider. */
export function verifyQueryString(
  publicKeyPem: string,
  payload: string,
  sigBase64: string,
): boolean {
  const v = createVerify("RSA-SHA256");
  v.update(payload, "utf8");
  v.end();
  try {
    return v.verify(publicKeyPem, sigBase64, "base64");
  } catch {
    return false;
  }
}

/**
 * Produce the base64 (DER/SPKI without PEM armor) value to publish as the TXT
 * record at `{key}.{syncPubKeyDomain}`. The exact on-wire fragmentation format
 * (`dc-pubkey-record` with p/d fields) is a DNS-Provider onboarding detail; for
 * the POC we expose the raw base64 key so it can be placed in the onboarding doc.
 */
export function publicKeyTxtValue(publicKeyPem: string): string {
  return publicKeyPem
    .replace(/-----BEGIN PUBLIC KEY-----/, "")
    .replace(/-----END PUBLIC KEY-----/, "")
    .replace(/\s+/g, "");
}
