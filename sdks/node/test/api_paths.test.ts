import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "../src/client.js";
import { LineageHelper } from "../src/lineage.js";

describe("Node SDK http paths", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("chat throws on 401", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string, _init?: RequestInit) => ({
        ok: false,
        status: 401,
        statusText: "Unauthorized",
        text: async () => "nope",
      })),
    );
    const client = new Client({ baseUrl: "http://gw.test", apiKey: "k" });

    await expect(client.chat([{ role: "user", content: "hi" }], "m")).rejects.toThrow("401");
  });

  it("spend hits /api/analytics/savings", async () => {
    const fetchMock = vi.fn(async (_url: string, _init?: RequestInit) => ({
      ok: true,
      json: async () => ({}),
    }));
    vi.stubGlobal("fetch", fetchMock);
    const client = new Client({ baseUrl: "http://gw.test", adminUrl: "http://admin.test", apiKey: "k" });

    await client.spend();

    expect(fetchMock.mock.calls[0]?.[0]).toContain("http://admin.test/api/analytics/savings");
  });

  it("lineage.get hits /api/lineage/{id}", async () => {
    const fetchMock = vi.fn(async (_url: string, _init?: RequestInit) => ({
      ok: true,
      json: async () => ({}),
    }));
    vi.stubGlobal("fetch", fetchMock);
    const helper = new LineageHelper({ adminUrl: "http://admin.test", apiKey: "k" });

    await helper.get("r1");

    expect(fetchMock.mock.calls[0]?.[0]).toBe("http://admin.test/api/lineage/r1");
  });

  it("spend(30) sends the days=30 query parameter", async () => {
    const fetchMock = vi.fn(async (_url: string, _init?: RequestInit) => ({
      ok: true,
      json: async () => ({}),
    }));
    vi.stubGlobal("fetch", fetchMock);
    const client = new Client({ baseUrl: "http://gw.test", adminUrl: "http://admin.test", apiKey: "k" });

    await client.spend(30);

    expect(fetchMock.mock.calls[0]?.[0]).toBe("http://admin.test/api/analytics/savings?days=30");
  });

  it("lineage.verify POSTs /api/lineage/{id}/verify", async () => {
    const fetchMock = vi.fn(async (_url: string, _init?: RequestInit) => ({
      ok: true,
      json: async () => ({ verified: true }),
    }));
    vi.stubGlobal("fetch", fetchMock);
    const helper = new LineageHelper({ adminUrl: "http://admin.test", apiKey: "k" });

    await helper.verify("r1");

    expect(fetchMock.mock.calls[0]?.[0]).toBe("http://admin.test/api/lineage/r1/verify");
    expect(fetchMock.mock.calls[0]?.[1]?.method).toBe("POST");
  });
});
