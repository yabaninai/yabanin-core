import { afterEach, describe, expect, it, vi } from "vitest";
import { Client, type ChatOptions } from "../src/client.js";

// N16-P04-T03 — request-body pass-through parity with the Go SDK's
// ChatRequest.Extra (sdks/go/compat_extensions_request_test.go, itself
// N07-P01-T04). The Node SDK exposes the same extra_body semantics as
// Client.chat options.extraBody: extension keys merge into the body top
// level verbatim, typed fields still serialize, an explicit extension key
// overrides a same-named typed field, and a request without extraBody is
// byte-identical to the previous hard-coded {messages, model} body.
//
// Response-side parity needs no opt-in: the untyped return of resp.json()
// already preserves unknown top-level keys (the loose counterpart of
// ChatResponse.Extra); pinned below so a future typed response decoder
// does not silently drop extensions.

const JSON_RAWJSON = (JSON as { rawJSON?: (s: string) => unknown }).rawJSON;
const hasRawJSON = typeof JSON_RAWJSON === "function";

function stubFetch(body: unknown) {
  const fetchMock = vi.fn(async (_url: string, init?: RequestInit) => ({
    ok: true,
    status: 200,
    statusText: "OK",
    json: async () => body,
  }));
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("Node SDK extraBody pass-through (Go Extra parity)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("merges extension keys into the body top level; typed fields still serialize; extraBody itself never appears", async () => {
    const fetchMock = stubFetch({ id: "x" });
    const client = new Client({ baseUrl: "http://gw.test", apiKey: "k" });
    const opts: ChatOptions = {
      extraBody: {
        x_request_ext: { retries: 9007199254740993, tag: "ext" },
        reasoning_effort: "low",
      },
    };
    await client.chat([{ role: "user", content: "hi" }], "gpt-4o-mini", opts);

    expect(fetchMock.mock.calls.length).toBe(1);
    const wire = JSON.parse(fetchMock.mock.calls[0][1].body as string) as Record<string, unknown>;
    expect(wire.x_request_ext).toEqual({ retries: 9007199254740993, tag: "ext" });
    expect(wire.reasoning_effort).toBe("low");
    expect(wire.model).toBe("gpt-4o-mini");
    expect(wire.messages).toEqual([{ role: "user", content: "hi" }]);
    expect("extraBody" in wire).toBe(false);
  });

  it("an explicit extension key overrides the same-named typed field (extra_body precedence)", async () => {
    const fetchMock = stubFetch({ id: "x" });
    const client = new Client({ baseUrl: "http://gw.test", apiKey: "k" });
    await client.chat([{ role: "user", content: "hi" }], "typed-model", {
      extraBody: { model: "ext-model" },
    });

    const wire = JSON.parse(fetchMock.mock.calls[0][1].body as string) as Record<string, unknown>;
    expect(wire.model).toBe("ext-model");
  });

  it("without extraBody the wire body is unchanged from the previous {messages, model} shape", async () => {
    const fetchMock = stubFetch({ id: "x" });
    const client = new Client({ baseUrl: "http://gw.test", apiKey: "k" });
    await client.chat([{ role: "user", content: "hi" }]);
    await client.chat([{ role: "user", content: "hi" }], "m");

    expect(fetchMock.mock.calls[0][1].body).toBe('{"messages":[{"role":"user","content":"hi"}]}');
    expect(fetchMock.mock.calls[1][1].body).toBe(
      '{"messages":[{"role":"user","content":"hi"}],"model":"m"}',
    );
  });

  it("keeps the bearer auth and content-type headers with extensions present", async () => {
    const fetchMock = stubFetch({ id: "x" });
    const client = new Client({ baseUrl: "http://gw.test", apiKey: "secret-key" });
    await client.chat([{ role: "user", content: "hi" }], "m", {
      extraBody: { x_request_ext: 1 },
    });

    const headers = fetchMock.mock.calls[0][1].headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer secret-key");
    expect(headers["Content-Type"]).toBe("application/json");
  });

  it.runIf(hasRawJSON)("serializes JSON.rawJSON extension values byte-exactly (2^53 window, RawMessage parity)", async () => {
    const fetchMock = stubFetch({ id: "x" });
    const client = new Client({ baseUrl: "http://gw.test", apiKey: "k" });
    await client.chat([{ role: "user", content: "hi" }], "m", {
      extraBody: {
        // JSON.rawJSON takes a primitive JSON fragment only; nesting it
        // inside a plain object mirrors the Go test's extension shape.
        x_request_ext: { retries: JSON_RAWJSON!("9007199254740993"), tag: "ext" },
      },
    });

    const rawWire = fetchMock.mock.calls[0][1].body as string;
    expect(rawWire).toContain('"x_request_ext":{"retries":9007199254740993,"tag":"ext"}');
    // After a JSON.parse round-trip the literal is already lossy (the
    // parsed number's string form is 9007199254740992) — the exactness
    // guarantee is on the wire bytes asserted above, exactly the property
    // Go pins on json.RawMessage.
    const wire = JSON.parse(rawWire) as { x_request_ext?: { retries: number } };
    expect(String(wire.x_request_ext?.retries)).not.toBe("9007199254740993");
  });

  it("response-side pass-through: unknown top-level provider fields ride the untyped return (ChatResponse.Extra counterpart)", async () => {
    stubFetch({ id: "resp1", model: "m", choices: [], x_provider_ext: { tier: "gold", rank: 9007199254740993 } });
    const client = new Client({ baseUrl: "http://gw.test", apiKey: "k" });
    const resp = (await client.chat([{ role: "user", content: "hi" }], "m")) as Record<string, unknown>;

    expect(resp.x_provider_ext).toEqual({ tier: "gold", rank: 9007199254740993 });
  });
});
