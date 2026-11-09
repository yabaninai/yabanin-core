import assert from "node:assert/strict";
import test from "node:test";
import {
  buildCursorCliArgs,
  classifyCursorCliError,
  cursorChildEnv,
  cursorStatusLooksLoggedIn,
  parseCursorPrintJson,
} from "./runners.ts";

test("cursor CLI args never pass an API key", () => {
  const analyze = buildCursorCliArgs("analyze", "/tmp/ws", "review auth");
  const implement = buildCursorCliArgs("implement", "/tmp/ws", "fix the bug");
  for (const args of [analyze, implement]) {
    assert.equal(args.includes("--api-key"), false);
    assert.equal(args.some((a) => a.startsWith("--api-key=")), false);
    assert.equal(args.includes("-p"), true);
    assert.equal(args.includes("--sandbox"), true);
    assert.equal(args.includes("enabled"), true);
    assert.equal(args.includes("--trust"), true);
  }
  assert.equal(analyze.includes("--mode"), true);
  assert.equal(analyze.includes("plan"), true);
  assert.equal(analyze.includes("--force"), false);
  assert.equal(implement.includes("--force"), true);
  assert.equal(implement.includes("--mode"), false);
});

test("cursor child env drops CURSOR_API_KEY so CLI uses subscription login", () => {
  const env = cursorChildEnv({ PATH: "/usr/bin", CURSOR_API_KEY: "cursor_should_not_leak", HOME: "/tmp" });
  assert.equal("CURSOR_API_KEY" in env, false);
  assert.match(String(env.PATH), /\.local\/bin/);
});

test("cursor status parser accepts CLI subscription login", () => {
  assert.equal(cursorStatusLooksLoggedIn("✓ Logged in as user@example.com"), true);
  assert.equal(cursorStatusLooksLoggedIn("Not authenticated"), false);
  assert.equal(cursorStatusLooksLoggedIn("logged out"), false);
  assert.equal(cursorStatusLooksLoggedIn("not logged in"), false);
});

test("cursor print JSON summary is extracted without secrets fields", () => {
  const stdout = [
    "noise",
    JSON.stringify({ type: "result", subtype: "success", is_error: false, result: "review ok" }),
  ].join("\n");
  assert.equal(parseCursorPrintJson(stdout), "review ok");
});

test("cursor CLI auth and quota map to stable errors", () => {
  assert.deepEqual(classifyCursorCliError("Not authenticated. Run agent login", 1), {
    error: "provider_not_authorized",
    startup: true,
  });
  assert.deepEqual(classifyCursorCliError("quota exceeded 429", 1), {
    error: "quota_exhausted",
    startup: false,
  });
});
