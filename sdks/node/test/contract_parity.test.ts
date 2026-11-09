import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "../src/client.js";
import { LineageHelper } from "../src/lineage.js";

// Contract parity: the SDK error surface against contracts/api-contract.json.
// The contract file is the canonical fixture source for every SDK; when the
// envelope or the schema_version changes, these tests and the gateway
// contract tests fail together (see docs/api/CONTRACT.md).
const CONTRACT_PATH = fileURLToPath(new URL("../../../contracts/api-contract.json", import.meta.url));

function fixtures() {
  const contract = JSON.parse(readFileSync(CONTRACT_PATH, "utf8"));
  expect(contract.schema_version, "schema_version changed — update every parity test with the bump").toBe(1);
  return contract.fixtures;
}

describe("Node SDK contract parity", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("chat surfaces the canonical error envelope message and status", async () => {
    const fx = fixtures().error_401;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string, _init?: RequestInit) => ({
        ok: false,
        status: 401,
        statusText: "Unauthorized",
        text: async () => JSON.stringify(fx),
      })),
    );
    const client = new Client({ baseUrl: "http://gw.test", apiKey: "k" });

    // The envelope body is carried verbatim in the error text — SDKs do not
    // rewrap errors (contracts/api-contract.json error_envelope.http).
    await expect(client.chat([{ role: "user", content: "hi" }], "m")).rejects.toThrow(
      fx.error.message,
    );
    await expect(client.chat([{ role: "user", content: "hi" }], "m")).rejects.toThrow(/401/);
  });

  it("spend surfaces the canonical error envelope code", async () => {
    const fx = fixtures().error_upstream;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string, _init?: RequestInit) => ({
        ok: false,
        status: 503,
        statusText: "Service Unavailable",
        text: async () => JSON.stringify(fx),
      })),
    );
    const client = new Client({ baseUrl: "http://gw.test", adminUrl: "http://admin.test", apiKey: "k" });

    await expect(client.spend()).rejects.toThrow(fx.error.code);
    await expect(client.spend()).rejects.toThrow(/503/);
  });

  it("lineage.get surfaces the canonical error envelope message", async () => {
    const fx = fixtures().error_401;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string, _init?: RequestInit) => ({
        ok: false,
        status: 401,
        statusText: "Unauthorized",
        text: async () => JSON.stringify(fx),
      })),
    );
    const helper = new LineageHelper({ adminUrl: "http://admin.test", apiKey: "k" });

    await expect(helper.get("r1")).rejects.toThrow(fx.error.message);
  });
});
