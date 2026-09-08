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
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import {
  DOMAIN_CONNECT_TEMPLATES,
  renderTemplateRecords,
  templateVariableNames,
  type DomainConnectServiceId,
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
  hostRequired: boolean;
  syncPubKeyDomain: string;
  variableDescription: string;
  records: Record<string, unknown>[];
}

function readTemplateFile(serviceId: string): TemplateFile {
  const raw = readFileSync(join(TEMPLATES_DIR, `${PROVIDER_ID}.${serviceId}.json`), "utf8");
  return JSON.parse(raw) as TemplateFile;
}

test("every registry entry has a committed JSON twin, and every JSON file has a registry entry", () => {
  const files = readdirSync(TEMPLATES_DIR)
    .filter((f) => f.endsWith(".json"))
    .sort();
  const expected = DOMAIN_CONNECT_TEMPLATES.map((t) => `${PROVIDER_ID}.${t.serviceId}.json`).sort();
  assert.deepEqual(files, expected);
});

for (const template of DOMAIN_CONNECT_TEMPLATES) {
  test(`${template.serviceId}: the JSON records are exactly what the registry renders`, () => {
    const file = readTemplateFile(template.serviceId);
    assert.equal(file.providerId, PROVIDER_ID);
    assert.equal(file.serviceId, template.serviceId);
    assert.equal(file.hostRequired, template.hostRequired);
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

  test(`${template.serviceId}: never writes MX (a bad MX write black-holes mail — v1 exclusion)`, () => {
    assert.ok(template.records.every((shape) => shape.templateType !== "MX"));
  });
}

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

// ── every template's canonical record set matches ITSELF, in any order ──────

const CANONICAL: Record<DomainConnectServiceId, Parameters<typeof compileToRecipe>[0]> = {
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
};

for (const template of DOMAIN_CONNECT_TEMPLATES) {
  test(`${template.serviceId}: its canonical record set compiles to itself, in any order`, () => {
    const records = CANONICAL[template.serviceId];
    assert.equal(compileToRecipe(records, PROVIDER_ID).serviceId, template.serviceId);
    assert.equal(
      compileToRecipe([...records].reverse(), PROVIDER_ID).serviceId,
      template.serviceId,
    );
  });
}
