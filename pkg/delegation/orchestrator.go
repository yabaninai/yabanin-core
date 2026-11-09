// Package delegation orchestrates optional Codex/Cursor agent runs for OpenCode.
// It is imported only by the MCP partner bridge, never by the gateway hot path
// (pkg/gateway chat/stream). When YABANIN_DELEGATION_ENABLED is unset, MCP does not
// construct an Orchestrator or open any network clients.
package delegation

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Mode is the sandbox posture for a delegated run.
type Mode string

// ModeAnalyze is read-only. ModeImplement allows workspace writes without
// full or destructive access.
const (
	ModeAnalyze   Mode = "analyze"
	ModeImplement Mode = "implement"
)

// ProviderName selects a subscription-backed agent.
type ProviderName string

// ProviderAuto picks Codex then Cursor. ProviderCodex and ProviderCursor pin
// a single official agent.
const (
	ProviderAuto   ProviderName = "auto"
	ProviderCodex  ProviderName = "codex"
	ProviderCursor ProviderName = "cursor"
)

// Request is a trusted delegation request. Workspace is filled by the
// orchestrator from process context, never from an untrusted remote path.
type Request struct {
	Task      string
	Mode      Mode
	Provider  ProviderName
	Workspace string
	Timeout   time.Duration
}

// Result is the OpenCode-facing summary of a delegated run.
type Result struct {
	Status       string   `json:"status"`
	Executor     string   `json:"executor"`
	Summary      string   `json:"summary"`
	ChangedFiles []string `json:"changed_files"`
	Validation   string   `json:"validation,omitempty"`
	DiffSummary  string   `json:"diff_summary,omitempty"`
	SelectReason string   `json:"select_reason,omitempty"`
	Error        string   `json:"error,omitempty"`
	Wrote        bool     `json:"wrote,omitempty"`
}

func (r Result) wroteFiles() bool {
	return r.Wrote || len(r.ChangedFiles) > 0
}

// Executor runs one provider. Implementations must not log credentials or the
// full task prompt.
type Executor interface {
	Name() string
	Available(context.Context) bool
	Run(ctx context.Context, req Request) (Result, error)
}

// Health tracks provider quota/auth cooldowns.
type Health struct {
	mu        sync.Mutex
	cooldown  map[ProviderName]time.Time
	lastError map[ProviderName]string
}

// NewHealth returns empty health state.
func NewHealth() *Health {
	return &Health{
		cooldown:  make(map[ProviderName]time.Time),
		lastError: make(map[ProviderName]string),
	}
}

func sanitizeError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "quota") || strings.Contains(msg, "429"):
		return "quota_exhausted"
	case strings.Contains(msg, "401") || strings.Contains(msg, "403") || strings.Contains(msg, "unauthorized"):
		return "provider_not_authorized"
	case strings.Contains(msg, "cancel"):
		return "canceled"
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline"):
		return "timeout"
	case strings.Contains(msg, "unavailable") || strings.Contains(msg, "cooldown"):
		return "provider_unavailable"
	default:
		return "executor_error"
	}
}

func cooldownFor(err error) time.Duration {
	if sanitizeError(err) == "quota_exhausted" {
		return 2 * time.Minute
	}
	if sanitizeError(err) == "provider_not_authorized" {
		return 5 * time.Minute
	}
	return 30 * time.Second
}

// MarkFailure starts a cooldown so auto-select can skip the provider.
func (h *Health) MarkFailure(p ProviderName, err error, d time.Duration) {
	if h == nil || p == "" {
		return
	}
	if d <= 0 {
		d = cooldownFor(err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cooldown[p] = time.Now().Add(d)
	if code := sanitizeError(err); code != "" {
		h.lastError[p] = code
	}
}

// Healthy reports whether p is off cooldown.
func (h *Health) Healthy(p ProviderName) bool {
	if h == nil {
		return true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	until, ok := h.cooldown[p]
	if !ok {
		return true
	}
	return time.Now().After(until)
}

// Orchestrator selects an executor and runs it against a trusted workspace.
type Orchestrator struct {
	workspace string
	executors map[ProviderName]Executor
	health    *Health
	mu        sync.Mutex
	sticky    ProviderName
	writeMu   sync.Mutex
}

// NewOrchestrator binds executors to a trusted launch-root workspace.
func NewOrchestrator(workspace string, execs ...Executor) *Orchestrator {
	confined, err := ConfineWorkspace(workspace)
	if err != nil {
		confined = ""
	}
	m := make(map[ProviderName]Executor, len(execs))
	for _, e := range execs {
		if e != nil {
			m[ProviderName(e.Name())] = e
		}
	}
	return &Orchestrator{
		workspace: confined,
		executors: m,
		health:    NewHealth(),
	}
}

// Delegate validates the request, selects an executor, and runs it.
func (o *Orchestrator) Delegate(ctx context.Context, req Request) (Result, error) {
	if o == nil {
		return Result{Status: "disabled", Error: "delegation orchestrator is not configured"}, nil
	}
	req.Task = strings.TrimSpace(req.Task)
	if req.Task == "" {
		return Result{}, fmt.Errorf("task is required")
	}
	if req.Mode == "" {
		req.Mode = ModeAnalyze
	}
	if req.Mode != ModeAnalyze && req.Mode != ModeImplement {
		return Result{}, fmt.Errorf("mode must be analyze or implement")
	}
	if req.Provider == "" {
		req.Provider = ProviderAuto
	}
	if o.workspace == "" {
		return Result{Status: "error", Error: "workspace_unconfigured"}, fmt.Errorf("workspace is not configured")
	}
	req.Workspace = o.workspace

	if req.Mode == ModeImplement {
		o.writeMu.Lock()
		defer o.writeMu.Unlock()
	}

	start := time.Now()
	out, err := o.dispatch(ctx, req)
	out.ChangedFiles = filterChangedFiles(o.workspace, out.ChangedFiles)
	logDelegation(out, time.Since(start), err)
	return out, err
}

func (o *Orchestrator) dispatch(ctx context.Context, req Request) (Result, error) {
	if req.Provider != ProviderAuto {
		exec, reason, err := o.selectExecutor(ctx, req.Provider)
		if err != nil {
			return Result{Status: "error", Error: err.Error(), SelectReason: reason}, err
		}
		return o.runExecutor(ctx, exec, reason, req)
	}

	if pinned := o.pinned(); pinned != "" {
		if exec, ok := o.executors[pinned]; ok && exec != nil && o.health.Healthy(pinned) && exec.Available(ctx) {
			return o.runExecutor(ctx, exec, "pinned:"+string(pinned), req)
		}
	}

	order := []ProviderName{ProviderCodex, ProviderCursor}
	var last Result
	var lastErr error
	tried := 0
	for _, p := range order {
		e, ok := o.executors[p]
		if !ok || e == nil || !o.health.Healthy(p) || !e.Available(ctx) {
			continue
		}
		tried++
		reason := "auto:" + string(p)
		if tried > 1 {
			reason = "failover:" + string(p)
		}
		out, err := o.runExecutor(ctx, e, reason, req)
		if err == nil {
			return out, nil
		}
		last, lastErr = out, err
		if out.wroteFiles() {
			return out, err
		}
	}
	if lastErr != nil {
		return last, lastErr
	}
	return Result{Status: "error", Error: "no healthy subscription executor is available", SelectReason: "no_healthy_executor"}, fmt.Errorf("no healthy subscription executor is available")
}

func (o *Orchestrator) runExecutor(ctx context.Context, exec Executor, reason string, req Request) (Result, error) {
	req.Provider = ProviderName(exec.Name())
	out, runErr := exec.Run(ctx, req)
	out.Executor = exec.Name()
	out.SelectReason = reason
	if runErr != nil {
		o.health.MarkFailure(req.Provider, runErr, 0)
		if out.Status == "" {
			out.Status = "error"
		}
		if out.Error == "" {
			out.Error = sanitizeError(runErr)
		} else {
			out.Error = sanitizeError(fmt.Errorf("%s", out.Error))
		}
		return out, runErr
	}
	// TP-17: a nil Go error means the transport call succeeded — the run
	// itself is successful only on an explicit ok status. Empty, unknown or
	// error statuses are a failed delegation (cooldown + honest error)
	// instead of being rewritten to ok, and auto failover may continue.
	if out.Status != "ok" {
		shown := out.Status
		if shown == "" {
			out.Status = "error"
			shown = "(empty)"
		}
		err := fmt.Errorf("executor %q returned result status %q", exec.Name(), shown)
		o.health.MarkFailure(req.Provider, err, 0)
		if out.Error == "" {
			out.Error = "invalid_result_status"
		}
		return out, err
	}
	if req.Mode == ModeImplement && out.wroteFiles() {
		o.setPinned(req.Provider)
	}
	return out, nil
}

func (o *Orchestrator) pinned() ProviderName {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.sticky
}

func (o *Orchestrator) setPinned(p ProviderName) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sticky = p
}

func (o *Orchestrator) selectExecutor(ctx context.Context, want ProviderName) (Executor, string, error) {
	e, ok := o.executors[want]
	if !ok || e == nil {
		return nil, "provider_unavailable", fmt.Errorf("executor %q is not configured", want)
	}
	if !o.health.Healthy(want) {
		return nil, "provider_cooldown", fmt.Errorf("executor %q is in cooldown", want)
	}
	if !e.Available(ctx) {
		return nil, "provider_unavailable", fmt.Errorf("executor %q is not available", want)
	}
	return e, "explicit:" + string(want), nil
}

func logDelegation(out Result, d time.Duration, err error) {
	status := out.Status
	if status == "" && err != nil {
		status = "error"
	}
	slog.Info("delegation finished",
		"provider", out.Executor,
		"duration_ms", d.Milliseconds(),
		"status", status,
		"changed_files", len(out.ChangedFiles),
		"select_reason", out.SelectReason,
	)
}
