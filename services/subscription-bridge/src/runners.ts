import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Runner } from "./types.ts";

export function envTruthy(v: string | undefined): boolean {
  if (!v) return false;
  switch (v.toLowerCase().trim()) {
    case "1":
    case "true":
    case "yes":
    case "on":
      return true;
    default:
      return false;
  }
}

export function useFakeRunners(): boolean {
  if (envTruthy(process.env.YABANIN_BRIDGE_FAKE)) return true;
  const raw = process.env.YABANIN_BRIDGE_FAKE;
  if (raw !== undefined && ["0", "false", "no", "off"].includes(raw.toLowerCase().trim())) {
    return false;
  }
  return false;
}

export function fakeRunner(name: "codex" | "cursor"): Runner {
  return {
    name,
    async available() {
      return true;
    },
    async run(req, signal) {
      if (signal.aborted) {
        return { status: "error", executor: name, summary: "", changed_files: [], error: "canceled" };
      }
      const task = req.task ?? "";
      if (task.includes("QUOTA")) {
        return { status: "error", executor: name, summary: "", changed_files: [], error: "quota_exhausted" };
      }
      if (task.includes("AUTH")) {
        return { status: "error", executor: name, summary: "", changed_files: [], error: "provider_not_authorized" };
      }
      if (task.includes("HANG")) {
        await new Promise<void>((resolve, reject) => {
          const onAbort = () => {
            signal.removeEventListener("abort", onAbort);
            reject(Object.assign(new Error("canceled"), { name: "AbortError" }));
          };
          signal.addEventListener("abort", onAbort);
        });
      }
      const files: string[] = [];
      let wrote = false;
      if (req.mode === "implement" && task.includes("WRITE_FILE")) {
        const { writeFile } = await import("node:fs/promises");
        const target = join(req.workspace, "yabanin-delegate-fake.txt");
        await writeFile(target, "fake implement\n", { encoding: "utf8", mode: 0o600 });
        files.push(target);
        wrote = true;
      }
      return {
        status: "ok",
        executor: name,
        summary: `fake ${name} ${req.mode} completed`,
        changed_files: files,
        validation: "skipped",
        wrote,
      };
    },
  };
}

export function codexLoggedIn(): boolean {
  if (process.env.CODEX_API_KEY) return true;
  return existsSync(join(homedir(), ".codex", "auth.json"));
}

export async function realCodexRunner(): Promise<Runner> {
  return {
    name: "codex",
    async available() {
      return codexLoggedIn();
    },
    async run(req, signal) {
      const mod = (await import("@openai/codex-sdk")) as { Codex: new (opts?: object) => CodexClient };
      const Codex = mod.Codex;
      const sandboxMode = req.mode === "analyze" ? "read-only" : "workspace-write";
      const client = new Codex();
      const thread = client.startThread({
        workingDirectory: req.workspace,
        skipGitRepoCheck: true,
        sandboxMode,
        approvalPolicy: "never",
        networkAccessEnabled: false,
      });
      const turn = await thread.run(req.task, { signal });
      const changed = extractCodexFiles(turn);
      return {
        status: "ok",
        executor: "codex",
        summary: boundText(String(turn?.finalResponse ?? ""), 4000),
        changed_files: changed,
        wrote: changed.length > 0,
        diff_summary: changed.length ? `${changed.length} files` : "",
      };
    },
  };
}

type CodexClient = {
  startThread: (opts: Record<string, unknown>) => {
    run: (task: string, opts: { signal?: AbortSignal }) => Promise<{ finalResponse?: string; items?: unknown[] }>;
  };
};

function extractCodexFiles(turn: { items?: unknown[] } | null | undefined): string[] {
  const items = turn?.items ?? [];
  const files = new Set<string>();
  for (const item of items) {
    const rec = item as { type?: string; path?: string; changes?: { path?: string }[] };
    if (typeof rec.path === "string") files.add(rec.path);
    for (const ch of rec.changes ?? []) {
      if (typeof ch.path === "string") files.add(ch.path);
    }
  }
  return [...files];
}

export function cursorChildEnv(base: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const env = { ...base };
  delete env.CURSOR_API_KEY;
  const extra = [join(homedir(), ".local/bin"), join(homedir(), ".cursor/bin")];
  const parts = String(env.PATH ?? "")
    .split(":")
    .filter((p) => p && !extra.includes(p));
  env.PATH = [...extra, ...parts].join(":");
  return env;
}

export function cursorStatusLooksLoggedIn(text: string): boolean {
  const t = text.toLowerCase();
  if (t.includes("not authenticated") || t.includes("not logged in") || t.includes("logged out")) return false;
  return t.includes("logged in as");
}

export function findCursorAgent(): string {
  const override = process.env.YABANIN_CURSOR_AGENT?.trim();
  if (override && existsSync(override)) return override;
  for (const p of [join(homedir(), ".local/bin/agent"), join(homedir(), ".cursor/bin/agent")]) {
    if (existsSync(p)) return p;
  }
  return "agent";
}

export function buildCursorCliArgs(mode: "analyze" | "implement", workspace: string, task: string): string[] {
  const args = ["-p", "--sandbox", "enabled", "--trust", "--workspace", workspace, "--output-format", "json"];
  if (mode === "analyze") {
    args.push("--mode", "plan");
  } else {
    args.push("--force");
  }
  const model = process.env.CURSOR_MODEL?.trim();
  if (model) args.push("--model", model);
  const prompt =
    mode === "analyze"
      ? `Read-only review. Do not create, edit, or delete files.\n\n${task}`
      : task;
  args.push(prompt);
  return args;
}

export function parseCursorPrintJson(stdout: string): string {
  const lines = stdout.trim().split(/\r?\n/).filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i];
    if (!line.startsWith("{")) continue;
    try {
      const obj = JSON.parse(line) as { result?: unknown };
      if (obj && Object.prototype.hasOwnProperty.call(obj, "result")) {
        return boundText(String(obj.result ?? ""), 4000);
      }
    } catch {
      continue;
    }
  }
  return boundText(stdout.trim(), 4000);
}

export function classifyCursorCliError(stderr: string, code: number | null): { error: string; startup: boolean } {
  const t = stderr.toLowerCase();
  if (t.includes("not authenticated") || t.includes("unauthorized") || t.includes("401") || t.includes("403")) {
    return { error: "provider_not_authorized", startup: true };
  }
  if (t.includes("quota") || t.includes("429")) {
    return { error: "quota_exhausted", startup: false };
  }
  if (code === 130 || t.includes("abort") || t.includes("cancel")) {
    return { error: "canceled", startup: false };
  }
  return { error: "executor_error", startup: false };
}

export async function cursorCliLoggedIn(): Promise<boolean> {
  const bin = findCursorAgent();
  try {
    const out = await spawnCaptured(bin, ["status"], { env: cursorChildEnv(), timeoutMs: 8000 });
    if (out.error?.code === "ENOENT") return false;
    return cursorStatusLooksLoggedIn(`${out.stdout}\n${out.stderr}`);
  } catch {
    return false;
  }
}

export async function realCursorRunner(): Promise<Runner> {
  return {
    name: "cursor",
    async available() {
      return cursorCliLoggedIn();
    },
    async run(req, signal) {
      const bin = findCursorAgent();
      const args = buildCursorCliArgs(req.mode, req.workspace, req.task);
      if (args.some((a) => a === "--api-key" || a.startsWith("--api-key="))) {
        const err = new Error("provider_not_authorized");
        (err as { startup?: boolean }).startup = true;
        throw err;
      }
      const out = await spawnCaptured(bin, args, {
        cwd: req.workspace,
        env: cursorChildEnv(),
        signal,
      });
      if (out.error?.code === "ENOENT") {
        const err = new Error("provider_not_authorized");
        (err as { startup?: boolean }).startup = true;
        throw err;
      }
      if (signal.aborted || out.signal === "SIGTERM" || out.signal === "SIGKILL") {
        return { status: "error", executor: "cursor", summary: "", changed_files: [], error: "canceled" };
      }
      if (out.code !== 0) {
        const classified = classifyCursorCliError(out.stderr, out.code);
        const err = new Error(classified.error);
        (err as { startup?: boolean }).startup = classified.startup;
        throw err;
      }
      return {
        status: "ok",
        executor: "cursor",
        summary: parseCursorPrintJson(out.stdout),
        changed_files: [],
        wrote: req.mode === "implement",
      };
    },
  };
}

type SpawnResult = {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  error?: NodeJS.ErrnoException;
};

function spawnCaptured(
  cmd: string,
  args: string[],
  opts: { cwd?: string; env: NodeJS.ProcessEnv; signal?: AbortSignal; timeoutMs?: number },
): Promise<SpawnResult> {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, {
      cwd: opts.cwd,
      env: opts.env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout?.setEncoding("utf8");
    child.stderr?.setEncoding("utf8");
    child.stdout?.on("data", (d: string) => {
      stdout += d;
    });
    child.stderr?.on("data", (d: string) => {
      stderr += d;
    });
    const onAbort = () => {
      child.kill("SIGTERM");
    };
    if (opts.signal) {
      if (opts.signal.aborted) onAbort();
      else opts.signal.addEventListener("abort", onAbort, { once: true });
    }
    let timer: ReturnType<typeof setTimeout> | undefined;
    if (opts.timeoutMs && opts.timeoutMs > 0) {
      timer = setTimeout(() => child.kill("SIGTERM"), opts.timeoutMs);
    }
    child.on("error", (error: NodeJS.ErrnoException) => {
      if (timer) clearTimeout(timer);
      opts.signal?.removeEventListener("abort", onAbort);
      resolve({ code: null, signal: null, stdout, stderr, error });
    });
    child.on("close", (code, signal) => {
      if (timer) clearTimeout(timer);
      opts.signal?.removeEventListener("abort", onAbort);
      resolve({ code, signal, stdout, stderr });
    });
  });
}

function boundText(s: string, n: number): string {
  if (s.length <= n) return s;
  return s.slice(0, n);
}

export async function buildRunners(): Promise<Record<"codex" | "cursor", Runner>> {
  if (useFakeRunners()) {
    return { codex: fakeRunner("codex"), cursor: fakeRunner("cursor") };
  }
  return {
    codex: await realCodexRunner(),
    cursor: await realCursorRunner(),
  };
}
