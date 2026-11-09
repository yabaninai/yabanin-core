export type Mode = "analyze" | "implement";

export type DelegateRequest = {
  provider: "codex" | "cursor";
  task: string;
  mode: Mode;
  workspace: string;
  timeout_ms?: number;
};

export type DelegateResult = {
  status: string;
  executor: string;
  summary: string;
  changed_files: string[];
  validation?: string;
  diff_summary?: string;
  error?: string;
  wrote?: boolean;
  run_id?: string;
};

export type Runner = {
  name: "codex" | "cursor";
  available: () => Promise<boolean>;
  run: (req: DelegateRequest, signal: AbortSignal) => Promise<DelegateResult>;
};
