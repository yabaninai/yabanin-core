import assert from "node:assert/strict";
import test from "node:test";
import { createBridge, isLoopbackHost } from "./server.ts";
import { fakeRunner } from "./runners.ts";

test("refuses non-loopback bind", () => {
  assert.equal(isLoopbackHost("0.0.0.0"), false);
  assert.equal(isLoopbackHost("127.0.0.1"), true);
  assert.throws(() =>
    createBridge({
      host: "0.0.0.0",
      port: 0,
      launchRoot: process.cwd(),
      runners: { codex: fakeRunner("codex"), cursor: fakeRunner("cursor") },
    }),
  );
});
