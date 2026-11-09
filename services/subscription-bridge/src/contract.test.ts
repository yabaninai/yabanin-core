import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createBridge } from "./server.ts";
import { fakeRunner } from "./runners.ts";

async function withBridge(fn: (url: string, root: string) => Promise<void>): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), "yabanin-bridge-"));
  const bridge = createBridge({
    host: "127.0.0.1",
    port: 0,
    launchRoot: root,
    runners: { codex: fakeRunner("codex"), cursor: fakeRunner("cursor") },
  });
  const { url } = await bridge.listen();
  try {
    await fn(url, root);
  } finally {
    await bridge.close();
    await rm(root, { recursive: true, force: true });
  }
}

test("healthz is ok", async () => {
  await withBridge(async (url) => {
    const res = await fetch(`${url}/healthz`);
    assert.equal(res.status, 200);
  });
});

test("success analyze does not write", async () => {
  await withBridge(async (url, root) => {
    const res = await fetch(`${url}/v1/delegate`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ provider: "codex", task: "review", mode: "analyze", workspace: root }),
    });
    const body = (await res.json()) as { status: string; changed_files: string[] };
    assert.equal(body.status, "ok");
    assert.equal(body.changed_files.length, 0);
  });
});

test("implement WRITE_FILE writes inside workspace", async () => {
  await withBridge(async (url, root) => {
    const res = await fetch(`${url}/v1/delegate`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        provider: "cursor",
        task: "WRITE_FILE please",
        mode: "implement",
        workspace: root,
      }),
    });
    const body = (await res.json()) as { status: string; changed_files: string[] };
    assert.equal(body.status, "ok");
    assert.equal(body.changed_files.length, 1);
    const text = await readFile(body.changed_files[0], "utf8");
    assert.match(text, /fake implement/);
  });
});

test("quota maps to quota_exhausted", async () => {
  await withBridge(async (url) => {
    const res = await fetch(`${url}/v1/delegate`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ provider: "codex", task: "QUOTA", mode: "analyze" }),
    });
    const body = (await res.json()) as { error: string };
    assert.equal(body.error, "quota_exhausted");
  });
});

test("auth maps to provider_not_authorized", async () => {
  await withBridge(async (url) => {
    const res = await fetch(`${url}/v1/delegate`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ provider: "cursor", task: "AUTH fail", mode: "analyze" }),
    });
    const body = (await res.json()) as { error: string };
    assert.equal(body.error, "provider_not_authorized");
  });
});

test("cancel aborts a hanging run", async () => {
  await withBridge(async (url, root) => {
    const runId = "run-cancel-1";
    const hung = fetch(`${url}/v1/delegate`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        provider: "codex",
        task: "HANG",
        mode: "analyze",
        workspace: root,
        run_id: runId,
        timeout_ms: 5000,
      }),
    });
    await new Promise((r) => setTimeout(r, 40));
    const cancel = await fetch(`${url}/v1/cancel`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ run_id: runId }),
    });
    assert.equal(cancel.status, 200);
    const body = (await (await hung).json()) as { error: string };
    assert.equal(body.error, "canceled");
  });
});

test("rejects workspace escape", async () => {
  await withBridge(async (url) => {
    const res = await fetch(`${url}/v1/delegate`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        provider: "codex",
        task: "x",
        mode: "analyze",
        workspace: "/etc",
      }),
    });
    const body = (await res.json()) as { error: string };
    assert.equal(body.error, "workspace_escape");
  });
});

test("full-access mode is rejected", async () => {
  await withBridge(async (url) => {
    const res = await fetch(`${url}/v1/delegate`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ provider: "codex", task: "x", mode: "danger-full-access" }),
    });
    const body = (await res.json()) as { error: string };
    assert.equal(body.error, "unsupported_mode");
  });
});
