import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { realpathSync } from "node:fs";
import { isAbsolute, resolve, sep } from "node:path";
import { randomUUID } from "node:crypto";
import type { DelegateRequest, DelegateResult, Runner } from "./types.ts";

const WRITE_LIMIT = 1;
const ANALYZE_LIMIT = 2;
const BODY_LIMIT = 1 << 20;

export type BridgeOptions = {
  host: string;
  port: number;
  runners: Record<"codex" | "cursor", Runner>;
  launchRoot: string;
};

type RunRecord = {
  controller: AbortController;
};

export function isLoopbackHost(host: string): boolean {
  return host === "127.0.0.1" || host === "localhost" || host === "::1";
}

export function confinePath(root: string, candidate: string): string | null {
  let resolvedRoot: string;
  try {
    resolvedRoot = realpathSync(root);
  } catch {
    resolvedRoot = resolve(root);
  }
  const abs = isAbsolute(candidate) ? resolve(candidate) : resolve(resolvedRoot, candidate);
  let resolved = abs;
  try {
    resolved = realpathSync(abs);
  } catch {
    resolved = abs;
  }
  if (resolved === resolvedRoot) return resolved;
  if (resolved.startsWith(resolvedRoot + sep)) return resolved;
  return null;
}

export function createBridge(opts: BridgeOptions) {
  if (!isLoopbackHost(opts.host)) {
    throw new Error("bridge must bind loopback");
  }
  const runs = new Map<string, RunRecord>();
  let writeActive = 0;
  let analyzeActive = 0;

  const server = createServer((req, res) => {
    void handle(req, res);
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      const host = String(req.headers.host ?? "").split(":")[0];
      if (host && !isLoopbackHost(host) && host !== "") {
        json(res, 403, { status: "error", error: "loopback_only" });
        return;
      }
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      if (req.method === "GET" && url.pathname === "/healthz") {
        json(res, 200, { status: "ok" });
        return;
      }
      if (req.method === "GET" && url.pathname === "/readyz") {
        const codex = await opts.runners.codex.available();
        const cursor = await opts.runners.cursor.available();
        json(res, 200, { status: "ok", providers: { codex, cursor } });
        return;
      }
      if (req.method === "GET" && url.pathname === "/v1/status") {
        json(res, 200, {
          status: "ok",
          providers: {
            codex: { available: await opts.runners.codex.available() },
            cursor: { available: await opts.runners.cursor.available() },
          },
        });
        return;
      }
      if (req.method === "POST" && url.pathname === "/v1/cancel") {
        const body = await readJSON(req);
        const id = String(body.run_id ?? "");
        const rec = runs.get(id);
        if (rec) rec.controller.abort();
        json(res, 200, { status: "ok" });
        return;
      }
      if (req.method === "POST" && url.pathname === "/v1/delegate") {
        const body = await readJSON(req);
        const out = await delegate(body);
        const code = out.status === "ok" ? 200 : 409;
        json(res, code, out);
        return;
      }
      json(res, 404, { status: "error", error: "not_found" });
    } catch (err) {
      const msg = err instanceof Error ? err.message : "error";
      const code = msg.includes("timeout") ? 504 : 500;
      json(res, code, { status: "error", error: sanitize(msg) });
    }
  }

  async function delegate(body: Record<string, unknown>): Promise<DelegateResult> {
    const provider = body.provider === "cursor" ? "cursor" : body.provider === "codex" ? "codex" : "";
    if (!provider) {
      return { status: "error", executor: "", summary: "", changed_files: [], error: "provider_required" };
    }
    const mode = body.mode === "implement" ? "implement" : "analyze";
    if (body.mode && body.mode !== "analyze" && body.mode !== "implement") {
      return { status: "error", executor: provider, summary: "", changed_files: [], error: "unsupported_mode" };
    }
    const task = String(body.task ?? "").trim();
    if (!task) {
      return { status: "error", executor: provider, summary: "", changed_files: [], error: "task_required" };
    }
    const ws = confinePath(opts.launchRoot, String(body.workspace ?? opts.launchRoot));
    if (!ws) {
      return { status: "error", executor: provider, summary: "", changed_files: [], error: "workspace_escape" };
    }
    if (mode === "implement") {
      if (writeActive >= WRITE_LIMIT) {
        return { status: "error", executor: provider, summary: "", changed_files: [], error: "concurrency_limit" };
      }
      writeActive += 1;
    } else {
      if (analyzeActive >= ANALYZE_LIMIT) {
        return { status: "error", executor: provider, summary: "", changed_files: [], error: "concurrency_limit" };
      }
      analyzeActive += 1;
    }
    const runId = String(body.run_id ?? "").trim() || randomUUID();
    const controller = new AbortController();
    runs.set(runId, { controller });
    const timeoutMs = Number(body.timeout_ms) > 0 ? Number(body.timeout_ms) : 14 * 60 * 1000;
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const started = Date.now();
    try {
      const req: DelegateRequest = { provider, task, mode, workspace: ws, timeout_ms: timeoutMs };
      const result = await opts.runners[provider].run(req, controller.signal);
      result.executor = provider;
      if (result.changed_files?.length) {
        result.changed_files = result.changed_files.filter((p) => confinePath(ws, p));
      }
      logDone(provider, Date.now() - started, result.status, result.changed_files?.length ?? 0);
      return result;
    } catch (err) {
      const startup = Boolean((err as { startup?: boolean }).startup);
      const msg = err instanceof Error ? err.message : "executor_error";
      logDone(provider, Date.now() - started, "error", 0);
      return {
        status: "error",
        executor: provider,
        summary: "",
        changed_files: [],
        error: startup ? "provider_not_authorized" : sanitize(msg),
      };
    } finally {
      clearTimeout(timer);
      runs.delete(runId);
      if (mode === "implement") writeActive -= 1;
      else analyzeActive -= 1;
    }
  }

  return {
    server,
    listen(): Promise<{ url: string }> {
      return new Promise((resolveListen, reject) => {
        server.listen(opts.port, opts.host, () => {
          const addr = server.address();
          if (!addr || typeof addr === "string") {
            reject(new Error("listen failed"));
            return;
          }
          resolveListen({ url: `http://${opts.host}:${addr.port}` });
        });
      });
    },
    close(): Promise<void> {
      for (const rec of runs.values()) rec.controller.abort();
      return new Promise((resolveClose, reject) => {
        server.close((err) => (err ? reject(err) : resolveClose()));
      });
    },
  };
}

function json(res: ServerResponse, code: number, body: unknown): void {
  res.writeHead(code, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

async function readJSON(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let n = 0;
  for await (const chunk of req) {
    n += (chunk as Buffer).length;
    if (n > BODY_LIMIT) {
      throw new Error("payload too large");
    }
    chunks.push(chunk as Buffer);
  }
  if (chunks.length === 0) return {};
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
}

function sanitize(msg: string): string {
  const lower = msg.toLowerCase();
  if (lower.includes("quota") || lower.includes("429")) return "quota_exhausted";
  if (lower.includes("401") || lower.includes("403") || lower.includes("unauthorized")) return "provider_not_authorized";
  if (lower.includes("cancel") || lower.includes("abort")) return "canceled";
  if (lower.includes("timeout")) return "timeout";
  return "executor_error";
}

function logDone(provider: string, durationMs: number, status: string, changed: number): void {
  console.log(
    JSON.stringify({
      msg: "delegation finished",
      provider,
      duration_ms: durationMs,
      status,
      changed_files: changed,
    }),
  );
}
