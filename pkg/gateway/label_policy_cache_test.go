package cli

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/labels"
)

func TestOrgLabelPolicies_VisibleWithinRedisTTL(t *testing.T) {
	clock := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	policyA := []byte(`{"allowed_keys":["*"],"on_missing":"allow"}`)
	policyB := []byte(`{"allowed_keys":["*"],"on_missing":"reject","required_keys":["issue"]}`)
	current := policyA
	kv := &memLabelKV{now: now}
	p := &orgLabelPolicies{
		mem: map[string]labelMemEntry{},
		now: now,
		kv:  kv,
		db: labelDBFunc(func(context.Context, string) ([]byte, bool, error) {
			return current, true, nil
		}),
		log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	}
	ctx := context.Background()
	if p.get(ctx, "org-1").OnMissing() != "allow" {
		t.Fatal("initial policy")
	}
	current = policyB
	clock = clock.Add(31 * time.Second)
	if p.get(ctx, "org-1").OnMissing() != "allow" {
		t.Fatal("redis should still serve the previous policy")
	}
	clock = clock.Add(30 * time.Second)
	if p.get(ctx, "org-1").OnMissing() != "reject" {
		t.Fatal("policy should refresh once the redis ttl elapses")
	}
}

func TestOrgLabelPolicies_DBErrorUsesDefault(t *testing.T) {
	var buf bytes.Buffer
	clock := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	p := &orgLabelPolicies{
		mem: map[string]labelMemEntry{},
		now: func() time.Time { return clock },
		db: labelDBFunc(func(context.Context, string) ([]byte, bool, error) {
			return nil, false, errors.New("db down")
		}),
		log: slog.New(slog.NewTextHandler(&buf, nil)),
	}
	if p.get(context.Background(), "org-1") != defaultLabelPolicy {
		t.Fatal("expected default")
	}
	clock = clock.Add(31 * time.Second)
	_ = p.get(context.Background(), "org-1")
	if stringsCount(buf.String(), "label policy unavailable") != 1 {
		t.Fatalf("warns: %s", buf.String())
	}
}

func TestLabelsMiddleware_MissingRequired(t *testing.T) {
	compiled, err := labels.Policy{AllowedKeys: []string{"*"}, OnMissing: "reject", RequiredKeys: []string{"issue"}}.Compile()
	if err != nil {
		t.Fatal(err)
	}
	gw := &gateway{labelPolicy: func(context.Context, string) *labels.Compiled { return compiled }}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", nil)
	gw.labelsMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler should not run")
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !bytes.Contains(rec.Body.Bytes(), []byte("missing_required_labels")) {
		t.Fatalf("%d %s", rec.Code, rec.Body.Bytes())
	}
}

type labelDBFunc func(context.Context, string) ([]byte, bool, error)

func (f labelDBFunc) Load(ctx context.Context, orgID string) ([]byte, bool, error) {
	return f(ctx, orgID)
}

type memLabelKV struct {
	items map[string]memLabelItem
	now   func() time.Time
}

type memLabelItem struct {
	value string
	until time.Time
}

func (m *memLabelKV) Get(_ context.Context, key string) (string, error) {
	item, ok := m.items[key]
	if !ok || !m.now().Before(item.until) {
		return "", errLabelMiss
	}
	return item.value, nil
}

func (m *memLabelKV) Set(_ context.Context, key, value string, ttl time.Duration) error {
	if m.items == nil {
		m.items = map[string]memLabelItem{}
	}
	m.items[key] = memLabelItem{value: value, until: m.now().Add(ttl)}
	return nil
}

func stringsCount(s, sub string) int {
	n := 0
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			n++
		}
	}
	return n
}
