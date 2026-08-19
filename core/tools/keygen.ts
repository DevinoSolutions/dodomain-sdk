// Generate the server-side signing keypair and print the public TXT value.
// Run:  npm run keys
//
// The private key is written to .keys/private.pem (gitignored) and NEVER exposed
// to the browser or logged. The printed TXT value is what you would publish at
// {keyHost}.{syncPubKeyDomain} during provider onboarding.

import { mkdirSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeyPair, publicKeyTxtValue } from "../src/sign.ts";

const __dir = dirname(fileURLToPath(import.meta.url));
const keysDir = join(__dir, "..", ".keys");
const privPath = join(keysDir, "private.pem");
const pubPath = join(keysDir, "public.pem");

if (existsSync(privPath) && !process.argv.includes("--force")) {
  console.log(`Keys already exist at ${privPath} (use --force to regenerate).`);
  process.exit(0);
}

const { publicKeyPem, privateKeyPem } = generateKeyPair();
mkdirSync(keysDir, { recursive: true });
writeFileSync(privPath, privateKeyPem, { mode: 0o600 });
writeFileSync(pubPath, publicKeyPem);

const keyHost = process.env.DODOMAIN_KEY_HOST ?? "_dck1";
const syncPubKeyDomain = process.env.DODOMAIN_PUBKEY_DOMAIN ?? "dckeys.dodomain.io";

console.log("Generated RSA-2048 signing keypair.");
console.log(`  private: ${privPath} (mode 600, gitignored — keep secret)`);
console.log(`  public:  ${pubPath}`);
console.log("\nPublish this TXT record during onboarding (base64 SPKI public key):");
console.log(`  ${keyHost}.${syncPubKeyDomain}.  IN TXT  "${publicKeyTxtValue(publicKeyPem)}"`);
console.log(
  `\n(Exact on-wire fragmentation is a per-provider onboarding detail — see docs/domain-connect-provider-onboarding.md)`,
);
