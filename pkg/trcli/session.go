package trcli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/cictx"
	"github.com/reireirei/yabanin/pkg/labels"
)

const (
	sessionDefaultTTL = 2 * time.Hour
	sessionMintWait   = 3 * time.Second
	sessionFinishWait = 3 * time.Second
	sessionCacheSlack = 10 * time.Minute
)

type sessionMintBody struct {
	Name       string            `json:"name"`
	TTL        int               `json:"ttl_seconds"`
	Labels     map[string]string `json:"labels"`
	Lock       bool              `json:"lock_labels"`
	MaxTokens  *int64            `json:"max_tokens,omitempty"`
	MaxCostUSD *float64          `json:"max_cost_usd,omitempty"`
}

type sessionMinted struct {
	ID        string     `json:"id"`
	Key       string     `json:"key"`
	ExpiresAt time.Time  `json:"expires_at"`
	Labels    labels.Set `json:"labels"`
}

type sessionHTTPError struct {
	Status int
	Body   string
}

func (e *sessionHTTPError) Error() string {
	return fmt.Sprintf("session key status %d", e.Status)
}

func sessionBase(gateway string) string {
	base := strings.TrimRight(strings.TrimSpace(gateway), "/")
	base = strings.TrimSuffix(base, "/v1")
	return base + "/v1/yabanin"
}

func mintSessionKey(ctx context.Context, gateway, parent string, body sessionMintBody) (sessionMinted, error) {
	ctx, cancel := context.WithTimeout(ctx, sessionMintWait)
	defer cancel()
	raw, err := json.Marshal(body)
	if err != nil {
		return sessionMinted{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sessionBase(gateway)+"/session-keys", bytes.NewReader(raw)) //nolint:gosec // G704: URL is the configured gateway, not a user redirect
	if err != nil {
		return sessionMinted{}, err
	}
	req.Header.Set("Authorization", "Bearer "+parent)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G704: URL is the configured gateway, not a user redirect
	if err != nil {
		return sessionMinted{}, err
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusCreated {
		return sessionMinted{}, &sessionHTTPError{Status: resp.StatusCode, Body: string(payload)}
	}
	var out struct {
		ID        string            `json:"id"`
		Key       string            `json:"key"`
		ExpiresAt string            `json:"expires_at"`
		Labels    map[string]string `json:"labels"`
	}
	if err := json.Unmarshal(payload, &out); err != nil {
		return sessionMinted{}, err
	}
	expires, err := time.Parse(time.RFC3339, out.ExpiresAt)
	if err != nil {
		return sessionMinted{}, err
	}
	return sessionMinted{ID: out.ID, Key: out.Key, ExpiresAt: expires.UTC(), Labels: out.Labels}, nil
}

func finishSessionKey(ctx context.Context, gateway, parent, id, status string, exitCode int, duration time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, sessionFinishWait)
	defer cancel()
	raw, err := json.Marshal(map[string]any{
		"status": status, "exit_code": exitCode, "duration_ms": duration.Milliseconds(),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sessionBase(gateway)+"/session-keys/"+id+"/finish", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+parent)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &sessionHTTPError{Status: resp.StatusCode, Body: string(payload)}
	}
	return nil
}

func sessionTTLSeconds(flag string, profile *cictx.Profile) (int, error) {
	if strings.TrimSpace(flag) != "" {
		return parseTTLSeconds(flag)
	}
	if profile != nil && profile.Session.TTL != "" {
		return parseTTLSeconds(profile.Session.TTL)
	}
	if os.Getenv("GITLAB_CI") == "true" {
		if raw := os.Getenv("CI_JOB_TIMEOUT"); raw != "" {
			n, err := strconv.Atoi(raw)
			if err == nil && n > 0 {
				ttl := n + 600
				if ttl > 43200 {
					ttl = 43200
				}
				return ttl, nil
			}
		}
	}
	return int(sessionDefaultTTL / time.Second), nil
}

func parseTTLSeconds(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if n, err := strconv.Atoi(raw); err == nil {
		return n, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("session ttl: %w", err)
	}
	return int(d / time.Second), nil
}

func sessionName(set labels.Set) string {
	name := strings.Join([]string{set["ci.system"], set["ci.pipeline"], set["ci.job"]}, ":")
	name = strings.Trim(name, ":")
	if name == "" {
		name = "ci"
	}
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}

func finishStatus(err error) (string, int) {
	var child *ChildExit
	if err == nil {
		return "success", 0
	}
	if errorsAsChild(err, &child) {
		if child.Signaled {
			return "canceled", child.Code
		}
		if child.Code == 0 {
			return "success", 0
		}
		return "failed", child.Code
	}
	return "failed", 1
}

func errorsAsChild(err error, target **ChildExit) bool {
	if err == nil {
		return false
	}
	child, ok := err.(*ChildExit)
	if !ok {
		return false
	}
	*target = child
	return true
}

type cachedSession struct {
	ID        string            `json:"id"`
	Key       string            `json:"key"`
	ExpiresAt time.Time         `json:"expires_at"`
	Labels    map[string]string `json:"labels"`
}

func sessionCachePath(home, tool, gateway string, set labels.Set) (string, error) {
	sum := sha256.Sum256([]byte(tool + "|" + gateway + "|" + labels.Encode(set)))
	dir := filepath.Join(home, ".yabanin", "sessions")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, hex.EncodeToString(sum[:])+".json"), nil
}

func readSessionCache(path string, now time.Time) (cachedSession, bool) {
	body, err := os.ReadFile(path) //nolint:gosec // G304: path is under the user session cache
	if err != nil {
		return cachedSession{}, false
	}
	var cached cachedSession
	if err := json.Unmarshal(body, &cached); err != nil || cached.Key == "" {
		return cachedSession{}, false
	}
	if cached.ExpiresAt.Sub(now) <= sessionCacheSlack {
		return cachedSession{}, false
	}
	return cached, true
}

func writeSessionCache(path string, cached cachedSession) error {
	body, err := json.Marshal(cached)
	if err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o600)
}

func sweepSessionCache(home string, now time.Time) {
	dir := filepath.Join(home, ".yabanin", "sessions")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	checked := 0
	for _, entry := range entries {
		if checked >= 100 {
			return
		}
		checked++
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		body, err := os.ReadFile(path) //nolint:gosec // G304: path is a session cache file
		if err != nil {
			continue
		}
		var cached cachedSession
		if err := json.Unmarshal(body, &cached); err != nil || !cached.ExpiresAt.After(now) {
			_ = os.Remove(path)
		}
	}
}
