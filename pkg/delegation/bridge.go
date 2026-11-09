package delegation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const bridgeBodyLimit = 1 << 20

// refuseRedirects is the redirect policy for every bridge request. The
// loopback sidecar contract has no legitimate redirect, and following one
// would re-send the request — including the task payload (307/308 replay
// the POST body) — to an arbitrary endpoint. Refusing here guarantees the
// destination receives zero payloads (TP-19).
func refuseRedirects(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("bridge: redirect to %s refused (loopback contract)", req.URL.Redacted())
}

// BridgeExecutor calls the local subscription-bridge sidecar. The URL must be
// loopback HTTP or a unix socket URL (unix:///path/to.sock).
type BridgeExecutor struct {
	name   string
	base   string
	client *http.Client
}

// NewBridgeExecutor returns a named executor pointing at a loopback bridge.
func NewBridgeExecutor(name, baseURL string) *BridgeExecutor {
	raw := strings.TrimSpace(baseURL)
	b := &BridgeExecutor{name: name}
	if strings.HasPrefix(raw, "unix://") {
		sock := strings.TrimPrefix(raw, "unix://")
		b.base = "http://127.0.0.1"
		b.client = &http.Client{
			Timeout:       15 * time.Minute,
			CheckRedirect: refuseRedirects,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", sock)
				},
			},
		}
		return b
	}
	b.base = strings.TrimRight(raw, "/")
	b.client = &http.Client{Timeout: 15 * time.Minute, CheckRedirect: refuseRedirects}
	return b
}

// Name implements Executor.
func (b *BridgeExecutor) Name() string { return b.name }

// Available reports whether the loopback sidecar answers /healthz.
func (b *BridgeExecutor) Available(ctx context.Context) bool {
	if b == nil || b.base == "" || !isLoopbackBridge(b.base) {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.base+"/healthz", nil)
	if err != nil {
		return false
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode == http.StatusOK
}

// Run posts a delegate request to the sidecar and returns the typed result.
func (b *BridgeExecutor) Run(ctx context.Context, req Request) (Result, error) {
	if !isLoopbackBridge(b.base) {
		return Result{Status: "error"}, fmt.Errorf("bridge URL must be loopback")
	}
	payload, err := json.Marshal(map[string]any{
		"provider":  b.name,
		"task":      req.Task,
		"mode":      string(req.Mode),
		"workspace": req.Workspace,
	})
	if err != nil {
		return Result{Status: "error"}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, b.base+"/v1/delegate", bytes.NewReader(payload))
	if err != nil {
		return Result{Status: "error"}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := b.client.Do(httpReq)
	if err != nil {
		return Result{Status: "error", Error: "bridge_unavailable"}, fmt.Errorf("bridge_unavailable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, bridgeBodyLimit))
	if err != nil {
		return Result{Status: "error"}, err
	}
	var out Result
	if err := json.Unmarshal(body, &out); err != nil {
		return Result{Status: "error"}, fmt.Errorf("bridge returned invalid JSON")
	}
	// TP-19: any non-2xx status is explicit — the error result carries the
	// status; redirects additionally fail in CheckRedirect before a second
	// request is ever attempted.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if out.Status == "" || out.Status == "ok" {
			out.Status = "error"
		}
		if out.Error == "" {
			out.Error = fmt.Sprintf("bridge status %d", resp.StatusCode)
		}
		return out, fmt.Errorf("%s", out.Error)
	}
	return out, nil
}

func isLoopbackBridge(raw string) bool {
	if strings.HasPrefix(raw, "unix://") {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	host := u.Hostname()
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
