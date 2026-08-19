// Live discovery probe — proves Stage 2 against real DNS.
//   node --experimental-strip-types tools/probe.ts <domain> [serviceId]
//
// Runs the real protocol: _domainconnect TXT -> /v2/{domain}/settings ->
// template-support check. No credentials, no writes.

import { discover, isTemplateSupported } from "../src/discovery.ts";

const domain = process.argv[2];
const serviceId = process.argv[3] ?? "custom-subdomain-cname";
if (!domain) {
  console.error("usage: probe.ts <domain> [serviceId]");
  process.exit(1);
}

try {
  const { providerHost, settings } = await discover(domain);
  console.log(`✓ discovered: ${domain}`);
  console.log(`  _domainconnect host : ${providerHost}`);
  console.log(`  providerId          : ${settings.providerId}`);
  console.log(`  providerName        : ${settings.providerName}`);
  console.log(`  urlSyncUX           : ${settings.urlSyncUX}`);
  console.log(`  urlAPI              : ${settings.urlAPI}`);
  try {
    const ok = await isTemplateSupported(settings.urlAPI, settings.providerId, serviceId);
    console.log(
      `  template "${serviceId}" supported: ${ok ? "YES (200)" : "no (404 — not onboarded, expected)"}`,
    );
  } catch (e) {
    console.log(`  template support check error: ${(e as Error).message}`);
  }
} catch (e) {
  console.log(`✗ ${domain}: ${(e as Error).message}`);
}
