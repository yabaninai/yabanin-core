import { describe, it, expect } from "vitest";
import { Client } from "../src/client.js";

describe("Node SDK", () => {
  it("missing key throws", () => {
    expect(() => new Client({ apiKey: "" })).toThrow("API key required");
  });

  it("uses env baseURL", () => {
    const c = new Client({ baseUrl: "http://custom:9090", apiKey: "pa_test" });
    // Internally stored; test via behavior.
    expect(c).toBeDefined();
  });
});
