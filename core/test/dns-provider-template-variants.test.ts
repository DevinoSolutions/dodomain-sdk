// Which template a DNS provider is SENT for a compiled recipe (T-15462).
//
// GoDaddy's Domain Connect signature check reserves the parameter name `token`,
// so the three templates that carry `dodomain-verify=%token%` are refused there.
// GoDaddy gets their `-v2` siblings, the value sent as `verification`; every
// other provider keeps the originals and `token`; a recipe without `token`
// (custom-subdomain-cname, email-authentication) is the same URL everywhere.
// One home: core domain-connect-templates.ts `templateApplyForDnsProvider` /
// `templateServiceIdForDnsProvider`; the support probe (discovery.ts
// `isTemplateServedBy`) asks about the same serviceId the apply URL names.

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  buildApplyUrl,
  payloadFromUrl,
  signatureEmissionOrderForDnsProvider,
} from "../src/applyUrl.ts";
import { isTemplateServedBy, type DiscoveryDeps } from "../src/discovery.ts";
import {
  templateApplyForDnsProvider,
  templateServiceIdForDnsProvider,
  templateVariantForDnsProvider,
} from "../src/domain-connect-templates.ts";
import {
  compileToRecipe,
  VERIFY_PREFIX,
  VERIFY_TXT_HOST,
  type SimpleRecord,
} from "../src/recipes.ts";
import { generateKeyPair, verifyQueryString } from "../src/sign.ts";

const PROVIDER_ID = "dodomain.io";
const SYNC = "https://dcc.example/manage";
const REDIRECT = "https://app.dodomain.io/api/v1/sessions/t/domain-connect/callback";
const { publicKeyPem, privateKeyPem } = generateKeyPair();

const TOKEN = "dd_verify_8f3a";
/** The canonical record set of each template the matcher compiles to. */
const RECORDS: Record<string, SimpleRecord[]> = {
  "domain-verification": [
    { type: "TXT", name: VERIFY_TXT_HOST, value: `${VERIFY_PREFIX}${TOKEN}` },
  ],
  "custom-subdomain-cname-with-verification": [
    { type: "CNAME", name: "status", value: "cname.integrator.example" },
    { type: "TXT", name: `${VERIFY_TXT_HOST}.status`, value: `${VERIFY_PREFIX}${TOKEN}` },
  ],
  "apex-a-with-verification": [
    { type: "A", name: "@", value: "203.0.113.10" },
    { type: "AAAA", name: "@", value: "2001:db8::10" },
    { type: "TXT", name: VERIFY_TXT_HOST, value: `${VERIFY_PREFIX}${TOKEN}` },
  ],
  "custom-subdomain-cname": [{ type: "CNAME", name: "www", value: "cname.integrator.example" }],
  "email-authentication": [
    { type: "TXT", name: "@", value: "v=spf1 include:_spf.mailer.example ~all" },
    { type: "CNAME", name: "s1._domainkey", value: "s1.dkim.mailer.example" },
    { type: "TXT", name: "_dmarc", value: "v=DMARC1; p=none" },
  ],
};
const TOKEN_TEMPLATES = [
  "domain-verification",
  "custom-subdomain-cname-with-verification",
  "apex-a-with-verification",
] as const;

/** The apply URL exactly as the start route builds it for one DNS provider. */
function applyUrlFor(dnsProviderId: string, serviceId: string) {
  const recipe = compileToRecipe(RECORDS[serviceId]!, PROVIDER_ID);
  assert.equal(recipe.serviceId, serviceId, "fixture compiles to the template it is named for");
  const sent = templateApplyForDnsProvider(dnsProviderId, recipe);
  return buildApplyUrl({
    urlSyncUX: SYNC,
    providerId: PROVIDER_ID,
    serviceId: sent.serviceId,
    domain: "customer.example",
    ...(recipe.host !== undefined ? { host: recipe.host } : {}),
    ...(recipe.groupIds !== undefined ? { groupIds: recipe.groupIds } : {}),
    variables: sent.variables,
    redirectUri: REDIRECT,
    state: "s1",
    allowedRedirectHosts: ["app.dodomain.io"],
    signing: {
      privateKeyPem,
      keyHost: "_dck1",
      emissionOrder: signatureEmissionOrderForDnsProvider(dnsProviderId),
    },
  });
}

function queryNames(url: string): string[] {
  return url
    .slice(url.indexOf("?") + 1)
    .split("&")
    .map((pair) => pair.split("=")[0]!);
}

for (const serviceId of TOKEN_TEMPLATES) {
  test(`GoDaddy gets ${serviceId}-v2 with the value under "verification", signed`, () => {
    const apply = applyUrlFor("godaddy.com", serviceId);
    assert.equal(
      apply.base,
      `${SYNC}/v2/domainTemplates/providers/dodomain.io/services/${serviceId}-v2/apply`,
    );
    const names = queryNames(apply.url);
    assert.ok(names.includes("verification"), apply.url);
    assert.equal(names.includes("token"), false, `GoDaddy reserves "token": ${apply.url}`);
    assert.match(apply.payload, new RegExp(`(^|&)verification=${TOKEN}(&|$)`));
    // The signature covers the RENAMED parameter: a provider verifying the
    // query it receives (sig and key removed by name) accepts it.
    assert.equal(payloadFromUrl(apply.url), apply.payload);
    assert.equal(verifyQueryString(publicKeyPem, apply.payload, apply.sig!), true);
    // ...and the same bytes with the old name do not verify.
    const asToken = apply.payload.replace("verification=", "token=");
    assert.equal(verifyQueryString(publicKeyPem, asToken, apply.sig!), false);
  });

  test(`${serviceId}: the renamed variable keeps its place in the signed payload`, () => {
    const original = applyUrlFor("cloudflare.com", serviceId);
    const godaddy = applyUrlFor("godaddy.com", serviceId);
    assert.deepEqual(
      queryNames(godaddy.payload),
      queryNames(original.payload).map((name) => (name === "token" ? "verification" : name)),
    );
  });

  for (const dnsProviderId of ["cloudflare.com", "glauca.digital", "vercel.com", "namesilo.com"]) {
    test(`${dnsProviderId} keeps the original ${serviceId} and "token"`, () => {
      assert.equal(templateVariantForDnsProvider(dnsProviderId, serviceId), undefined);
      assert.equal(templateServiceIdForDnsProvider(dnsProviderId, serviceId), serviceId);
      const apply = applyUrlFor(dnsProviderId, serviceId);
      assert.equal(
        apply.base,
        `${SYNC}/v2/domainTemplates/providers/dodomain.io/services/${serviceId}/apply`,
      );
      const names = queryNames(apply.url);
      assert.ok(names.includes("token"), apply.url);
      assert.equal(names.includes("verification"), false, apply.url);
      assert.equal(verifyQueryString(publicKeyPem, apply.payload, apply.sig!), true);
    });
  }
}

for (const serviceId of ["custom-subdomain-cname", "email-authentication"]) {
  test(`GoDaddy's ${serviceId} apply URL is unchanged: no token, no sibling`, () => {
    assert.equal(templateVariantForDnsProvider("godaddy.com", serviceId), undefined);
    assert.equal(templateServiceIdForDnsProvider("godaddy.com", serviceId), serviceId);
    const recipe = compileToRecipe(RECORDS[serviceId]!, PROVIDER_ID);
    assert.deepEqual(templateApplyForDnsProvider("godaddy.com", recipe), {
      serviceId,
      variables: recipe.variables,
    });
    // Byte-identical to the URL built straight from the recipe (RSA PKCS#1 v1.5
    // signatures are deterministic, so the sig matches too).
    const direct = buildApplyUrl({
      urlSyncUX: SYNC,
      providerId: PROVIDER_ID,
      serviceId: recipe.serviceId,
      domain: "customer.example",
      ...(recipe.host !== undefined ? { host: recipe.host } : {}),
      ...(recipe.groupIds !== undefined ? { groupIds: recipe.groupIds } : {}),
      variables: recipe.variables,
      redirectUri: REDIRECT,
      state: "s1",
      allowedRedirectHosts: ["app.dodomain.io"],
      signing: { privateKeyPem, keyHost: "_dck1" },
    });
    assert.equal(applyUrlFor("godaddy.com", serviceId).url, direct.url);
  });
}

test("the GoDaddy match is on its settings providerId, trimmed and case-insensitive", () => {
  assert.equal(
    templateServiceIdForDnsProvider(" GoDaddy.com ", "domain-verification"),
    "domain-verification-v2",
  );
  // Not a suffix or substring match: a lookalike provider gets the originals.
  assert.equal(
    templateServiceIdForDnsProvider("notgodaddy.com", "domain-verification"),
    "domain-verification",
  );
  // An unknown serviceId passes through untouched (dns-records, prepared ones).
  assert.equal(templateServiceIdForDnsProvider("godaddy.com", "dns-records"), "dns-records");
});

test("a recipe that no longer fits the sibling fails loudly instead of sending a wrong name", () => {
  assert.throws(
    () =>
      templateApplyForDnsProvider("godaddy.com", {
        serviceId: "domain-verification",
        variables: { tok: "x" },
      }),
    /has no "token"/,
  );
  assert.throws(
    () =>
      templateApplyForDnsProvider("godaddy.com", {
        serviceId: "domain-verification",
        variables: { token: "x", verification: "y" },
      }),
    /already carries "verification"/,
  );
});

test("isTemplateServedBy probes the serviceId the provider is SENT: -v2 at GoDaddy, the original elsewhere", async () => {
  const fetched: string[] = [];
  const deps: DiscoveryDeps = {
    fetchJson: async (url) => {
      fetched.push(url);
      return { ok: true, status: 200, json: null };
    },
  };
  const godaddy = { providerId: "godaddy.com", urlAPI: "https://domainconnect.api.godaddy.com" };
  const cloudflare = {
    providerId: "cloudflare.com",
    urlAPI: "https://api.cloudflare.com/client/v4/dns/domainconnect",
  };
  for (const serviceId of [...TOKEN_TEMPLATES, "custom-subdomain-cname", "email-authentication"]) {
    assert.equal(await isTemplateServedBy(godaddy, PROVIDER_ID, serviceId, deps), true);
    assert.equal(await isTemplateServedBy(cloudflare, PROVIDER_ID, serviceId, deps), true);
  }
  const path = (id: string) => `/v2/domainTemplates/providers/dodomain.io/services/${id}`;
  assert.deepEqual(fetched, [
    `${godaddy.urlAPI}${path("domain-verification-v2")}`,
    `${cloudflare.urlAPI}${path("domain-verification")}`,
    `${godaddy.urlAPI}${path("custom-subdomain-cname-with-verification-v2")}`,
    `${cloudflare.urlAPI}${path("custom-subdomain-cname-with-verification")}`,
    `${godaddy.urlAPI}${path("apex-a-with-verification-v2")}`,
    `${cloudflare.urlAPI}${path("apex-a-with-verification")}`,
    `${godaddy.urlAPI}${path("custom-subdomain-cname")}`,
    `${cloudflare.urlAPI}${path("custom-subdomain-cname")}`,
    `${godaddy.urlAPI}${path("email-authentication")}`,
    `${cloudflare.urlAPI}${path("email-authentication")}`,
  ]);
  // GoDaddy's refusal of dns-records still wins before any probe.
  fetched.length = 0;
  assert.equal(await isTemplateServedBy(godaddy, PROVIDER_ID, "dns-records", deps), false);
  assert.deepEqual(fetched, []);
});

test("a GoDaddy 404 on the -v2 sibling reads as not served, even though the original answers 200", async () => {
  const deps: DiscoveryDeps = {
    fetchJson: async (url) =>
      url.endsWith("-v2")
        ? { ok: false, status: 404, json: null }
        : { ok: true, status: 200, json: null },
  };
  const godaddy = { providerId: "godaddy.com", urlAPI: "https://domainconnect.api.godaddy.com" };
  for (const serviceId of TOKEN_TEMPLATES) {
    assert.equal(await isTemplateServedBy(godaddy, PROVIDER_ID, serviceId, deps), false, serviceId);
  }
  assert.equal(
    await isTemplateServedBy(godaddy, PROVIDER_ID, "custom-subdomain-cname", deps),
    true,
  );
});
