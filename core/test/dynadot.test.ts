import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import {
  applyDynadotRecords,
  buildDynadotAuthorizeUrl,
  dynadotPkce,
  dynadotRecordBodies,
  parseDynadotRecords,
  parseMcpMessages,
  DYNADOT_AUTHORIZE_URL,
  DYNADOT_MCP_RESOURCE,
  DYNADOT_MCP_URL,
  DYNADOT_TOKEN_URL,
  DynadotError,
} from "../src/dynadot.ts";
import { detectProvider } from "../src/detect.ts";
import { RECORD_TYPES, TIER_WRITABLE_TYPES } from "../src/record-capabilities.ts";
import type { SessionRecord } from "../src/records.ts";

const config = {
  clientId: "mock-public-client",
  redirectUri: "https://dev-app.dodomain.io/api/v1/dynadot/callback",
};
const mockCredential = "MOCK-DYNADOT-JWT-NEVER-LOG";
const baseInput = {
  config,
  code: "mock-code",
  verifier: "mock-verifier",
  domain: "app.customer.com",
  records: [{ type: "TXT", host: "_dodomain-challenge", value: "mock-proof" }] as SessionRecord[],
  expiresAt: new Date(Date.now() + 3600_000),
};

function urlOf(input: Parameters<typeof fetch>[0]): URL {
  return new URL(input instanceof Request ? input.url : input.toString());
}
function bodyOf(init?: RequestInit): string {
  assert.equal(typeof init?.body, "string");
  return init!.body as string;
}

interface ToolCall {
  name: string;
  arguments: Record<string, unknown>;
}

// MOCK Dynadot OAuth + MCP over HTTP. Every call is confined to these fake
// responses: no real provider, resolver, database, credentials or queue.
function mockDynadot(
  options: {
    /** What get_domain_records returns as its tool result. */
    readResult?: unknown;
    /** Make one stage answer with an HTTP status. */
    failStage?: "exchange" | "initialize" | "read" | "write";
    status?: number;
    /** Make one tool answer HTTP 200 with isError and this text. */
    toolError?: { tool: string; text: string };
    /** Answer JSON-RPC with SSE (default) or plain JSON. */
    sse?: boolean;
  } = {},
) {
  const calls: string[] = [];
  const tools: ToolCall[] = [];
  const sessionIds: (string | null)[] = [];
  const fetcher: typeof fetch = async (rawUrl, init) => {
    const url = urlOf(rawUrl);
    assert.equal(init?.cache, "no-store");
    assert.equal(init?.redirect, "error");
    assert.ok(init?.signal);
    assert.equal(init?.method, "POST");
    if (url.href === DYNADOT_TOKEN_URL) {
      calls.push("exchange");
      const headers = new Headers(init?.headers);
      assert.equal(headers.get("content-type"), "application/x-www-form-urlencoded");
      const body = new URLSearchParams(bodyOf(init));
      assert.equal(body.get("grant_type"), "authorization_code");
      assert.equal(body.get("code"), baseInput.code);
      assert.equal(body.get("redirect_uri"), config.redirectUri);
      assert.equal(body.get("client_id"), config.clientId);
      assert.equal(body.get("code_verifier"), baseInput.verifier);
      assert.equal(body.get("resource"), DYNADOT_MCP_RESOURCE);
      assert.equal(body.has("client_secret"), false);
      if (options.failStage === "exchange")
        return Response.json({ error: mockCredential }, { status: options.status ?? 400 });
      return Response.json({
        access_token: mockCredential,
        token_type: "Bearer",
        expires_in: 1799,
      });
    }
    assert.equal(url.href, DYNADOT_MCP_URL);
    const headers = new Headers(init?.headers);
    assert.equal(headers.get("authorization"), `Bearer ${mockCredential}`);
    assert.equal(headers.get("content-type"), "application/json");
    assert.equal(headers.get("accept"), "application/json, text/event-stream");
    assert.equal(headers.get("mcp-protocol-version"), "2025-06-18");
    const message = JSON.parse(bodyOf(init)) as {
      id?: number;
      method: string;
      params?: Record<string, unknown>;
    };
    calls.push(message.method);
    sessionIds.push(headers.get("mcp-session-id"));
    const reply = (result: unknown, extra: Record<string, string> = {}) => {
      const payload = { jsonrpc: "2.0", id: message.id, result };
      return options.sse === false
        ? Response.json(payload, { headers: extra })
        : new Response(`event: message\ndata: ${JSON.stringify(payload)}\n\n`, {
            headers: { "content-type": "text/event-stream", ...extra },
          });
    };
    if (message.method === "initialize") {
      if (options.failStage === "initialize")
        return new Response(mockCredential, { status: options.status ?? 500 });
      assert.equal(message.params?.protocolVersion, "2025-06-18");
      return reply(
        { protocolVersion: "2025-06-18", capabilities: {}, serverInfo: { name: "mock" } },
        { "mcp-session-id": "mock-session-1" },
      );
    }
    if (message.method === "notifications/initialized") {
      assert.equal(message.id, undefined);
      return new Response(null, { status: 202 });
    }
    assert.equal(message.method, "tools/call");
    const call = message.params as unknown as ToolCall;
    tools.push(call);
    const stage = call.name === "get_domain_records" ? "read" : "write";
    if (options.failStage === stage)
      return new Response(mockCredential, { status: options.status ?? 500 });
    if (options.toolError?.tool === call.name)
      return reply({ isError: true, content: [{ type: "text", text: options.toolError.text }] });
    if (call.name === "get_domain_records")
      return reply(
        options.readResult ?? {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                dns_main_list: [{ record_type: "A", record_value1: "192.0.2.1" }],
                dns_sub_list: [],
                ttl: 3600,
              }),
            },
          ],
        },
      );
    return reply({ content: [{ type: "text", text: "ok" }] });
  };
  return { calls, tools, sessionIds, fetcher };
}

function textResult(value: unknown) {
  return { content: [{ type: "text", text: JSON.stringify(value) }] };
}

test("Dynadot nameservers are detected at tier 3 with high confidence; lookalikes stay unknown", async () => {
  for (const ns of ["ns1.dyna-ns.net", "NS2.DYNA-NS.NET.", "ns1.dyna-ns.net.evil.example"]) {
    const match = await detectProvider("customer.com", {
      // MOCK DNS and discovery, no external requests.
      resolveNs: async () => [ns],
      parentNs: async () => [ns],
      discover: async () => {
        throw new Error("MOCK no Domain Connect");
      },
    });
    assert.equal(match.provider, ns.includes("evil") ? "unknown" : "dynadot");
    if (!ns.includes("evil")) assert.equal(match.confidence, "high");
  }
});

test("the authorize URL carries exactly the parameters proven live: PKCE S256, resource, no scope", () => {
  const { verifier, challenge } = dynadotPkce();
  assert.equal(challenge, createHash("sha256").update(verifier).digest("base64url"));
  const url = new URL(buildDynadotAuthorizeUrl(config, "a".repeat(32), challenge));
  assert.equal(`${url.origin}${url.pathname}`, DYNADOT_AUTHORIZE_URL);
  assert.deepEqual(Object.fromEntries(url.searchParams), {
    response_type: "code",
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    code_challenge: challenge,
    code_challenge_method: "S256",
    state: "a".repeat(32),
    resource: "https://mcp.dynadot.com",
  });
  assert.equal(url.searchParams.has("scope"), false);
  assert.throws(() => buildDynadotAuthorizeUrl(config, "a".repeat(32), "short"));
  assert.throws(() => buildDynadotAuthorizeUrl(config, "bad state!", challenge));
});

test("records map to apex main rows and relative sub rows; MX priority is record_value2", () => {
  const { zone, bodies } = dynadotRecordBodies("app.customer.com", [
    { type: "A", host: "@", value: "192.0.2.10" },
    { type: "CNAME", host: "www", value: "target.example.net." },
    { type: "MX", host: "@", value: "mx.example.net.", priority: 10 },
    { type: "TXT", host: "_dodomain-challenge", value: "v=proof" },
  ]);
  assert.equal(zone, "customer.com");
  assert.deepEqual(bodies, [
    { list: "sub", row: { sub_host: "app", record_type: "A", record_value1: "192.0.2.10" } },
    {
      list: "sub",
      row: { sub_host: "www.app", record_type: "CNAME", record_value1: "target.example.net" },
    },
    {
      list: "sub",
      row: {
        sub_host: "app",
        record_type: "MX",
        record_value1: "mx.example.net",
        record_value2: "10",
      },
    },
    {
      list: "sub",
      row: {
        sub_host: "_dodomain-challenge.app",
        record_type: "TXT",
        record_value1: "v=proof",
      },
    },
  ]);
  const apex = dynadotRecordBodies("customer.com", [{ type: "A", host: "@", value: "192.0.2.10" }]);
  assert.deepEqual(apex.bodies, [
    { list: "main", row: { record_type: "A", record_value1: "192.0.2.10" } },
  ]);
});

test("only A, AAAA, CNAME, TXT and MX are Dynadot-writable; every other type is refused", () => {
  assert.deepEqual(TIER_WRITABLE_TYPES.dynadot_oauth, ["A", "AAAA", "CNAME", "TXT", "MX"]);
  for (const type of RECORD_TYPES.filter((t) => !TIER_WRITABLE_TYPES.dynadot_oauth.includes(t))) {
    assert.throws(
      () => dynadotRecordBodies("customer.com", [{ type, host: "x", value: "v" } as SessionRecord]),
      (error: unknown) => error instanceof DynadotError && error.stage === "records",
    );
  }
});

test("MCP responses parse from SSE data lines and from plain JSON", () => {
  assert.deepEqual(
    parseMcpMessages("text/event-stream; charset=utf-8", 'event: message\ndata: {"id":1}\n\n'),
    [{ id: 1 }],
  );
  assert.deepEqual(parseMcpMessages("application/json", '{"id":2}'), [{ id: 2 }]);
  assert.deepEqual(parseMcpMessages("application/json", '[{"id":3}]'), [{ id: 3 }]);
  assert.equal(parseMcpMessages("application/json", "not json"), null);
});

test("existing records parse from the set vocabulary and from the api3 get_dns shape", () => {
  assert.deepEqual(
    parseDynadotRecords(
      textResult({
        dns_main_list: [{ record_type: "a", record_value1: "192.0.2.1" }],
        dns_sub_list: [
          { sub_host: "WWW", record_type: "MX", record_value1: "mx.example", record_value2: 5 },
        ],
        ttl: "300",
      }),
    ),
    {
      main: [{ name: "@", type: "A", value1: "192.0.2.1", value2: undefined }],
      sub: [{ name: "www", type: "MX", value1: "mx.example", value2: "5" }],
      ttl: 300,
    },
  );
  assert.deepEqual(
    parseDynadotRecords({
      structuredContent: {
        GetDnsResponse: {
          GetDns: {
            NameServerSettings: {
              MainDomains: [{ RecordType: "TXT", Value: "v=spf1 -all" }],
              SubDomains: [{ Subhost: "app", RecordType: "CNAME", Value: "x.example" }],
            },
          },
        },
      },
    }),
    {
      main: [{ name: "@", type: "TXT", value1: "v=spf1 -all", value2: undefined }],
      sub: [{ name: "app", type: "CNAME", value1: "x.example", value2: undefined }],
      ttl: undefined,
    },
  );
  // Unreadable: no record lists, a row without a value, or prose.
  assert.equal(parseDynadotRecords(textResult({ status: "ok" })), null);
  assert.equal(parseDynadotRecords(textResult({ dns_main_list: [{ record_type: "A" }] })), null);
  assert.equal(parseDynadotRecords({ content: [{ type: "text", text: "Records: none" }] }), null);
});

test("a sub-host apply runs the MCP handshake, reads, then ONE add-mode write echoing the apex rows", async () => {
  const mock = mockDynadot();
  const outcome = await applyDynadotRecords(baseInput, mock.fetcher);
  assert.deepEqual(outcome, { ok: true });
  assert.deepEqual(mock.calls, [
    "exchange",
    "initialize",
    "notifications/initialized",
    "tools/call",
    "tools/call",
  ]);
  // The session id from initialize rides every later MCP call.
  assert.deepEqual(mock.sessionIds, [null, "mock-session-1", "mock-session-1", "mock-session-1"]);
  assert.deepEqual(mock.tools, [
    { name: "get_domain_records", arguments: { domain_name: "customer.com" } },
    {
      name: "set_domain_records",
      arguments: {
        domain_name: "customer.com",
        dns_main_list: [{ record_type: "A", record_value1: "192.0.2.1" }],
        dns_sub_list: [
          { sub_host: "_dodomain-challenge.app", record_type: "TXT", record_value1: "mock-proof" },
        ],
        ttl: 3600,
        add_dns_to_current_setting: true,
      },
    },
  ]);
});

test("plain-JSON MCP replies work the same as SSE", async () => {
  const mock = mockDynadot({ sse: false });
  assert.deepEqual(await applyDynadotRecords(baseInput, mock.fetcher), { ok: true });
  assert.equal(mock.tools.length, 2);
});

test("every set_domain_records call sends add_dns_to_current_setting true, apex writes included", async () => {
  const mock = mockDynadot();
  const outcome = await applyDynadotRecords(
    {
      ...baseInput,
      domain: "customer.com",
      records: [
        { type: "TXT", host: "@", value: "dodomain-verify=abc" },
        { type: "CNAME", host: "app", value: "edge.example.net" },
      ],
    },
    mock.fetcher,
  );
  assert.deepEqual(outcome, { ok: true });
  const write = mock.tools.find((call) => call.name === "set_domain_records")!;
  assert.equal(write.arguments.add_dns_to_current_setting, true);
  assert.deepEqual(write.arguments.dns_main_list, [
    { record_type: "A", record_value1: "192.0.2.1" },
    { record_type: "TXT", record_value1: "dodomain-verify=abc" },
  ]);
  assert.deepEqual(write.arguments.dns_sub_list, [
    { sub_host: "app", record_type: "CNAME", record_value1: "edge.example.net" },
  ]);
  for (const call of mock.tools)
    assert.ok(["get_domain_records", "set_domain_records"].includes(call.name));
});

test("records already present are not written again, and nothing at all is written when all are", async () => {
  const mock = mockDynadot({
    readResult: textResult({
      dns_main_list: [],
      dns_sub_list: [
        { sub_host: "_dodomain-challenge.app", record_type: "TXT", record_value1: "mock-proof" },
      ],
    }),
  });
  assert.deepEqual(await applyDynadotRecords(baseInput, mock.fetcher), { ok: true });
  assert.deepEqual(
    mock.tools.map((call) => call.name),
    ["get_domain_records"],
  );
});

test("conflicts refuse before any write: a different CNAME, a CNAME beside other data, a second SPF, a forward row", async () => {
  const cases: { existing: unknown; records: SessionRecord[] }[] = [
    {
      existing: {
        dns_sub_list: [{ sub_host: "app", record_type: "CNAME", record_value1: "old.example" }],
      },
      records: [{ type: "CNAME", host: "app", value: "new.example" }],
    },
    {
      existing: {
        dns_sub_list: [{ sub_host: "app", record_type: "A", record_value1: "192.0.2.9" }],
      },
      records: [{ type: "CNAME", host: "app", value: "new.example" }],
    },
    {
      existing: {
        dns_sub_list: [{ sub_host: "app", record_type: "A", record_value1: "192.0.2.9" }],
      },
      records: [{ type: "A", host: "app", value: "192.0.2.10" }],
    },
    {
      existing: {
        dns_main_list: [{ record_type: "TXT", record_value1: "v=spf1 include:old -all" }],
      },
      records: [{ type: "TXT", host: "@", value: "v=spf1 include:new -all" }],
    },
    {
      existing: { dns_main_list: [{ record_type: "FORWARD", record_value1: "https://x.example" }] },
      records: [{ type: "TXT", host: "@", value: "dodomain-verify=abc" }],
    },
  ];
  for (const { existing, records } of cases) {
    const mock = mockDynadot({ readResult: textResult(existing) });
    const outcome = await applyDynadotRecords(
      { ...baseInput, domain: "customer.com", records },
      mock.fetcher,
    );
    assert.equal(outcome.ok, false);
    assert.ok(!outcome.ok && outcome.error.stage === "conflict");
    assert.ok(!mock.tools.some((call) => call.name === "set_domain_records"));
  }
});

test("an unrelated TXT coexists: the new value is added beside it", async () => {
  const mock = mockDynadot({
    readResult: textResult({
      dns_main_list: [{ record_type: "TXT", record_value1: "google-site-verification=x" }],
    }),
  });
  const outcome = await applyDynadotRecords(
    { ...baseInput, domain: "customer.com", records: [{ type: "TXT", host: "@", value: "dd=1" }] },
    mock.fetcher,
  );
  assert.deepEqual(outcome, { ok: true });
  const write = mock.tools.find((call) => call.name === "set_domain_records")!;
  assert.deepEqual(write.arguments.dns_main_list, [
    { record_type: "TXT", record_value1: "google-site-verification=x" },
    { record_type: "TXT", record_value1: "dd=1" },
  ]);
});

test("unreadable existing records refuse as a conflict rather than guess", async () => {
  const mock = mockDynadot({ readResult: { content: [{ type: "text", text: "mystery" }] } });
  const outcome = await applyDynadotRecords(baseInput, mock.fetcher);
  assert.ok(!outcome.ok && outcome.error.stage === "conflict");
  assert.ok(!mock.tools.some((call) => call.name === "set_domain_records"));
});

test("MCP_NOT_ENABLED becomes its own stage, other read refusals the domain stage; no provider text escapes", async () => {
  const disabled = mockDynadot({
    toolError: {
      tool: "get_domain_records",
      text: `MCP_NOT_ENABLED: MCP is not active for this Dynadot account. ${mockCredential}`,
    },
  });
  const outcome = await applyDynadotRecords(baseInput, disabled.fetcher);
  assert.ok(!outcome.ok && outcome.error.stage === "mcp_not_enabled");
  assert.ok(!outcome.ok && !outcome.error.message.includes(mockCredential));

  const refused = mockDynadot({
    toolError: { tool: "get_domain_records", text: `NOT_FOUND: ${mockCredential}` },
  });
  const other = await applyDynadotRecords(baseInput, refused.fetcher);
  assert.ok(!other.ok && other.error.stage === "domain");

  const writeRefused = mockDynadot({
    toolError: { tool: "set_domain_records", text: `INVALID: ${mockCredential}` },
  });
  const write = await applyDynadotRecords(baseInput, writeRefused.fetcher);
  assert.ok(!write.ok && write.error.stage === "write");
});

test("HTTP failures carry only a fixed stage and status, never a body or the token", async () => {
  for (const [failStage, status] of [
    ["exchange", 400],
    ["initialize", 401],
    ["read", 429],
    ["write", 500],
  ] as const) {
    const mock = mockDynadot({ failStage, status });
    const outcome = await applyDynadotRecords(baseInput, mock.fetcher);
    assert.ok(!outcome.ok);
    assert.equal(outcome.error.stage, failStage);
    assert.equal(outcome.error.status, status);
    assert.equal(outcome.error.cause, undefined);
    assert.ok(!JSON.stringify(outcome).includes(mockCredential));
    assert.ok(!outcome.error.message.includes(mockCredential));
  }
});

test("the outcome never carries the access token on success either", async () => {
  const mock = mockDynadot();
  const outcome = await applyDynadotRecords(baseInput, mock.fetcher);
  assert.ok(!JSON.stringify(outcome).includes(mockCredential));
});

test("a token response that is not a bearer token stops before any MCP call", async () => {
  const fetcher: typeof fetch = async () =>
    Response.json({ access_token: mockCredential, token_type: "mac" });
  const outcome = await applyDynadotRecords(baseInput, fetcher);
  assert.ok(!outcome.ok && outcome.error.stage === "exchange");
});

test("an expired session stops before the write", async () => {
  const mock = mockDynadot();
  const outcome = await applyDynadotRecords(
    { ...baseInput, expiresAt: new Date(Date.now() - 1) },
    mock.fetcher,
  );
  assert.ok(!outcome.ok && outcome.error.stage === "write");
  assert.ok(!mock.tools.some((call) => call.name === "set_domain_records"));
});

test("an SSE reply is read only until our response arrives, even when the stream stays open", async () => {
  const mock = mockDynadot();
  let cancelled = 0;
  const fetcher: typeof fetch = async (url, init) => {
    const response = await mock.fetcher(url, init);
    if (!(response.headers.get("content-type") ?? "").includes("text/event-stream"))
      return response;
    const body = await response.text();
    const encode = (chunk: string) => new TextEncoder().encode(chunk);
    // MOCK server that never closes: a keep-alive comment, then the reply
    // split across two chunks, then silence.
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encode(": ping\n\n"));
        controller.enqueue(encode(body.slice(0, 10)));
        controller.enqueue(encode(body.slice(10)));
      },
      cancel() {
        cancelled += 1;
      },
    });
    return new Response(stream, { headers: response.headers });
  };
  assert.deepEqual(await applyDynadotRecords(baseInput, fetcher), { ok: true });
  assert.equal(mock.tools.length, 2);
  // initialize + two tool calls, each released once its reply arrived.
  assert.equal(cancelled, 3);
});
