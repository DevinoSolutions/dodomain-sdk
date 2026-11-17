// The registry ↔ JSON drift check the templates README asks for.
//
// Every entry in DOMAIN_CONNECT_TEMPLATES is the in-code twin of one file in
// docs/domain-connect/templates/ — the payload providers onboard. A provider
// that receives a variable, host or group its copy of the template doesn't
// define rejects the apply, and nothing on our side would notice until a user
// hit a dead end. So: render each registry entry's records and compare them
// with the committed file (deep-equal), plus the serviceId / hostRequired /
// variable lockstep, plus "each canonical record set matches exactly itself".

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import {
  DOMAIN_CONNECT_TEMPLATE_VARIANTS,
  DOMAIN_CONNECT_TEMPLATES,
  domainConnectTemplate,
  renderTemplateRecords,
  templateVariableNames,
  type DomainConnectServiceId,
  type DomainConnectTemplate,
} from "../src/domain-connect-templates.ts";
import { compileToRecipe, VERIFY_PREFIX, VERIFY_TXT_HOST } from "../src/recipes.ts";

const TEMPLATES_DIR = join(
  import.meta.dirname,
  "..",
  "..",
  "..",
  "docs",
  "domain-connect",
  "templates",
);
const PROVIDER_ID = "dodomain.io";

interface TemplateFile {
  providerId: string;
  serviceId: string;
  serviceName: string;
  version: number;
  description: string;
  hostRequired: boolean;
  multiInstance?: boolean;
  shared?: boolean;
  sharedProviderName?: boolean;
  syncPubKeyDomain: string;
  variableDescription: string;
  records: Record<string, unknown>[];
}

function readTemplateFile(serviceId: string): TemplateFile {
  const raw = readFileSync(join(TEMPLATES_DIR, `${PROVIDER_ID}.${serviceId}.json`), "utf8");
  return JSON.parse(raw) as TemplateFile;
}

/** The registry AND its DNS-provider siblings: every one is a JSON file a
 * provider onboards, so every one gets the same lockstep checks. */
const EVERY_TEMPLATE: readonly DomainConnectTemplate[] = [
  ...DOMAIN_CONNECT_TEMPLATES,
  ...DOMAIN_CONNECT_TEMPLATE_VARIANTS,
];

test("every registry entry and sibling has a committed JSON twin, and every JSON file has one", () => {
  const files = readdirSync(TEMPLATES_DIR)
    .filter((f) => f.endsWith(".json"))
    .sort();
  const expected = EVERY_TEMPLATE.map((t) => `${PROVIDER_ID}.${t.serviceId}.json`).sort();
  assert.deepEqual(files, expected);
});

for (const template of EVERY_TEMPLATE) {
  test(`${template.serviceId}: the JSON records are exactly what the registry renders`, () => {
    const file = readTemplateFile(template.serviceId);
    assert.equal(file.providerId, PROVIDER_ID);
    assert.equal(file.serviceId, template.serviceId);
    assert.equal(file.hostRequired, template.hostRequired);
    assert.equal(file.multiInstance ?? false, template.multiInstance ?? false);
    // `shared` is the deprecated v2.1 spelling the spec says to set beside it.
    const sharedProviderName = template.sharedProviderName ?? false;
    assert.equal(file.sharedProviderName ?? false, sharedProviderName);
    assert.equal(file.shared ?? false, sharedProviderName);
    // Every apply is signed — the templates README's whole prerequisite section.
    assert.equal(file.syncPubKeyDomain, "dckeys.dodomain.io");
    assert.deepEqual(file.records, renderTemplateRecords(template));
  });

  test(`${template.serviceId}: every variable the registry extracts is described AND used in the JSON`, () => {
    const file = readTemplateFile(template.serviceId);
    for (const variable of templateVariableNames(template)) {
      assert.match(
        file.variableDescription,
        new RegExp(`\\b${variable}\\b`),
        `variableDescription must name "${variable}"`,
      );
      assert.ok(
        JSON.stringify(file.records).includes(`%${variable}%`),
        `no record in ${template.serviceId} uses %${variable}%`,
      );
    }
  });

  test(`${template.serviceId}: a CNAME at "@" is only ever declared with hostRequired (spec)`, () => {
    for (const record of renderTemplateRecords(template)) {
      if (record.type === "CNAME" && record.host === "@") {
        assert.equal(template.hostRequired, true);
      }
    }
  });

  // A bad MX write black-holes mail, so the shaped templates never write one
  // where the domain receives mail. Two exceptions: `dns-records`, whose MX
  // slots are only ever filled from an integrator's explicit MX record, and a
  // `subdomainHost` MX (email-sending's MAIL FROM), which never lands at the
  // root.
  test(`${template.serviceId}: an MX is written only by dns-records or at a subdomain-only host`, () => {
    if (template.serviceId === "dns-records") return;
    for (const shape of template.records) {
      if (shape.templateType === "MX") {
        assert.equal(shape.subdomainHost, true, shape.groupId);
      }
    }
  });

  // The Domain Connect Online Editor validates a numeric field (ttl, priority,
  // weight, port) as oneOf [a %variable% string, a string matching an
  // UNANCHORED \d], so a variable there whose name holds a digit matches both
  // branches and the editor rejects the whole template (found 2026-10-27).
  test(`${template.serviceId}: no variable in a numeric field has a digit in its name`, () => {
    for (const record of renderTemplateRecords(template)) {
      for (const field of ["ttl", "priority", "weight", "port"]) {
        const value = record[field];
        if (typeof value === "string")
          assert.doesNotMatch(value, /\d/, `${record.groupId}.${field}`);
      }
    }
  });

  // Every apply of a template with a variable host may land somewhere new on a
  // domain that already carries an earlier apply; without multiInstance a
  // state-tracking provider removes that earlier instance (spec §"Template
  // scope"). So a whole-variable host requires multiInstance — a MAIL FROM
  // subdomain included: two integrations at different bounce hosts compile to
  // the same domain-scoped template instance.
  test(`${template.serviceId}: a whole-variable record host is only declared with multiInstance`, () => {
    if (template.records.some((shape) => /^%[A-Za-z0-9]+%$/.test(shape.host))) {
      assert.equal(template.multiInstance, true);
    }
  });
}

// The templates whose applies are per integration, not per domain, and so must
// never replace an earlier instance on the same domain: the three whose hosts or
// tokens differ between two integrators. A template added to this list needs a
// reason; one that drops out is a state-tracking provider deleting a customer's
// records.
test("exactly dns-records, email-sending and site-verification are multiInstance", () => {
  const multi = DOMAIN_CONNECT_TEMPLATES.filter(
    (t) => (t as DomainConnectTemplate).multiInstance === true,
  )
    .map((t) => t.serviceId)
    .sort();
  assert.deepEqual(multi, ["dns-records", "email-sending", "site-verification"]);
});

// ── the frozen surface: serviceIds + variables the merged templates depend on ──

test("the two upstream-merged templates keep their serviceIds and variable names byte-identical", () => {
  const byId = new Map(DOMAIN_CONNECT_TEMPLATES.map((t) => [t.serviceId as string, t]));
  assert.deepEqual(templateVariableNames(byId.get("custom-subdomain-cname")!), ["target"]);
  assert.deepEqual(templateVariableNames(byId.get("domain-verification")!), ["token"]);
  assert.equal(VERIFY_PREFIX, "dodomain-verify=");
  assert.equal(VERIFY_TXT_HOST, "_dodomain-challenge");
  const verification = readTemplateFile("domain-verification").records[0]!;
  assert.equal(verification.host, VERIFY_TXT_HOST);
  assert.equal(verification.data, `${VERIFY_PREFIX}%token%`);
});

// ── the five live originals are frozen; each -v2 sibling renames ONE variable ──

// A content hash of each original's JSON (parsed and re-serialised, so only the
// document counts, not its whitespace), taken from origin/dev on 2026-11-09
// before the siblings were added. These five files are live at Cloudflare,
// Glauca, Vercel, GoDaddy and the registry auto-syncers; any edit to one, even
// a description, is a new template version every provider must re-review, so
// it must never ride along with other work. Owner ruling, T-15462.
const FROZEN_ORIGINAL_SHA256: Record<string, string> = {
  "custom-subdomain-cname": "2752447559f57a3299f595b25322011e99a01ed798f40e3481fdacbab970f124",
  "domain-verification": "5b71451f953a5f8366d1cd7079d01806f59e6316e0dc7d02700e8ed4595a0cd5",
  "custom-subdomain-cname-with-verification":
    "f2044c0b041c4897ca4b7ceaeb10d0f035a7a45faec2c0f27c3b91d2b7acb97e",
  "apex-a-with-verification": "09e69ec9160215f16decdab85458b0e41c82af28586655a3a3ae1c6756f4b390",
  "email-authentication": "62ca09a0f066a5551fdfdd8ea68b9e0653f03e5e5258edae77d975ec17363b45",
};

for (const [serviceId, sha256] of Object.entries(FROZEN_ORIGINAL_SHA256)) {
  test(`${serviceId}: the live original JSON is byte-for-byte unchanged`, () => {
    const document = JSON.stringify(readTemplateFile(serviceId));
    assert.equal(createHash("sha256").update(document).digest("hex"), sha256);
  });
}

test("exactly the three token-carrying templates have a -v2 sibling", () => {
  assert.deepEqual(
    DOMAIN_CONNECT_TEMPLATE_VARIANTS.map((v) => [v.variantOf, v.serviceId]),
    [
      ["domain-verification", "domain-verification-v2"],
      ["custom-subdomain-cname-with-verification", "custom-subdomain-cname-with-verification-v2"],
      ["apex-a-with-verification", "apex-a-with-verification-v2"],
    ],
  );
  // Every template that names `token` has its sibling, so no apply to a
  // provider that reserves the name can still carry it.
  const withToken = DOMAIN_CONNECT_TEMPLATES.filter(
    (t) => !(t as DomainConnectTemplate).prepared && templateVariableNames(t).includes("token"),
  ).map((t) => t.serviceId);
  assert.deepEqual(
    withToken,
    DOMAIN_CONNECT_TEMPLATE_VARIANTS.map((v) => v.variantOf),
  );
  // A sibling serviceId never collides with a registry one.
  const registryIds = new Set<string>(DOMAIN_CONNECT_TEMPLATES.map((t) => t.serviceId));
  for (const variant of DOMAIN_CONNECT_TEMPLATE_VARIANTS) {
    assert.equal(registryIds.has(variant.serviceId), false, variant.serviceId);
  }
});

for (const variant of DOMAIN_CONNECT_TEMPLATE_VARIANTS) {
  test(`${variant.serviceId}: differs from ${variant.variantOf} ONLY in the token variable's name`, () => {
    assert.deepEqual(variant.renamedVariables, { token: "verification" });

    // The registry entries: same shape in every field but the value variable.
    const original = domainConnectTemplate(variant.variantOf);
    const { serviceId: _o, records: originalRecords, ...originalRest } = original;
    const {
      serviceId: _v,
      records,
      variantOf: _of,
      renamedVariables: _r,
      ...variantRest
    } = variant;
    assert.deepEqual(variantRest, originalRest);
    assert.deepEqual(
      records,
      originalRecords.map((shape) =>
        shape.value.variable === "token"
          ? { ...shape, value: { ...shape.value, variable: "verification" } }
          : shape,
      ),
    );
    assert.deepEqual(
      templateVariableNames(variant),
      templateVariableNames(original).map((name) => (name === "token" ? "verification" : name)),
    );

    // The JSON twins: every field equal except the identity and the prose a
    // reviewer reads, and the records equal once %token% reads %verification%.
    const originalFile = readTemplateFile(variant.variantOf);
    const file = readTemplateFile(variant.serviceId);
    const prose = ["serviceId", "serviceName", "description", "variableDescription", "records"];
    const strip = (f: TemplateFile) =>
      Object.fromEntries(Object.entries(f).filter(([key]) => !prose.includes(key)));
    assert.deepEqual(strip(file), strip(originalFile));
    // Same key order too: a provider reviewing both files side by side sees
    // the one difference and nothing else.
    assert.deepEqual(Object.keys(file), Object.keys(originalFile));
    assert.equal(
      file.version,
      1,
      "a new serviceId starts at version 1 (Templates-repo convention)",
    );
    assert.equal(
      JSON.stringify(file.records),
      JSON.stringify(originalFile.records).replaceAll("%token%", "%verification%"),
    );
    assert.equal(JSON.stringify(originalFile.records).split("%token%").length, 2, "one %token%");
    assert.doesNotMatch(JSON.stringify(file), /%token%/);
    // The prose names it a variant of its original, so a reviewer knows why
    // two near-identical templates exist.
    assert.notEqual(file.serviceName, originalFile.serviceName);
    assert.ok(
      file.description.includes(`Variant of dodomain.io/${variant.variantOf}, `),
      file.description,
    );
  });
}

// ── every template's canonical record set matches ITSELF, in any order ──────

// `caa` has none: no session record carries CAA yet (its TODO(scope)).
const CANONICAL: Record<
  Exclude<DomainConnectServiceId, "caa">,
  Parameters<typeof compileToRecipe>[0]
> = {
  "custom-subdomain-cname": [{ type: "CNAME", name: "www", value: "t.example" }],
  "domain-verification": [{ type: "TXT", name: VERIFY_TXT_HOST, value: `${VERIFY_PREFIX}tok` }],
  "email-authentication": [
    { type: "TXT", name: "@", value: "v=spf1 include:_spf.mailer.example ~all" },
    { type: "CNAME", name: "s1._domainkey", value: "s1.dkim.mailer.example" },
    { type: "TXT", name: "_dmarc", value: "v=DMARC1; p=none; rua=mailto:dmarc@mailer.example" },
  ],
  "custom-subdomain-cname-with-verification": [
    { type: "CNAME", name: "status", value: "t.example" },
    { type: "TXT", name: `${VERIFY_TXT_HOST}.status`, value: `${VERIFY_PREFIX}tok` },
  ],
  "apex-a-with-verification": [
    { type: "A", name: "@", value: "203.0.113.10" },
    { type: "AAAA", name: "@", value: "2001:db8::10" },
    { type: "TXT", name: VERIFY_TXT_HOST, value: `${VERIFY_PREFIX}tok` },
  ],
  // Amazon SES-style sending: MAIL FROM MX + SPF on a subdomain, three DKIM
  // CNAMEs and DMARC, in one apply.
  "email-sending": [
    { type: "MX", name: "mail", value: "feedback-smtp.us-east-1.amazonses.com", priority: 10 },
    { type: "TXT", name: "mail", value: "v=spf1 include:amazonses.com ~all" },
    { type: "CNAME", name: "k1._domainkey", value: "k1.dkim.amazonses.com" },
    { type: "CNAME", name: "k2._domainkey", value: "k2.dkim.amazonses.com" },
    { type: "CNAME", name: "k3._domainkey", value: "k3.dkim.amazonses.com" },
    { type: "TXT", name: "_dmarc", value: "v=DMARC1; p=none" },
  ],
  website: [
    { type: "A", name: "@", value: "198.185.159.144" },
    { type: "A", name: "@", value: "198.185.159.145" },
    { type: "A", name: "@", value: "198.49.23.144" },
    { type: "A", name: "@", value: "198.49.23.145" },
    { type: "CNAME", name: "www", value: "ext-sq.squarespace.com" },
  ],
  "site-verification": [
    { type: "TXT", name: "@", value: "google-site-verification=abc123" },
    { type: "TXT", name: "@", value: "MS=ms12345678" },
  ],
  // Several subdomains at once: nothing narrower expresses it.
  "dns-records": [
    { type: "CNAME", name: "app", value: "app.example.net" },
    { type: "CNAME", name: "docs", value: "docs.example.net" },
  ],
};

for (const template of DOMAIN_CONNECT_TEMPLATES) {
  if (template.serviceId === "caa") continue;
  test(`${template.serviceId}: its canonical record set compiles to itself, in any order`, () => {
    const records = CANONICAL[template.serviceId];
    assert.equal(compileToRecipe(records, PROVIDER_ID).serviceId, template.serviceId);
    assert.equal(
      compileToRecipe([...records].reverse(), PROVIDER_ID).serviceId,
      template.serviceId,
    );
  });
}
