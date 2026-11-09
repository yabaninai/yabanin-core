package jitaccess

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Hermetic unit tests: defaults, digest binding algebra and the fail-closed
// posture. The Postgres-backed acceptance flows live in access_int_test.go.

func TestJIT_Defaults(t *testing.T) {
	m := NewManager(nil)
	if m.ttl != ApprovedTTL {
		t.Errorf("approved TTL default: got %v, want %v", m.ttl, ApprovedTTL)
	}
	if m.ttl != time.Hour {
		t.Errorf("D6: approved TTL must be 1h, got %v", m.ttl)
	}
	if m.pendingTTL != 24*time.Hour {
		t.Errorf("D6: pending auto-expire must be 24h, got %v", m.pendingTTL)
	}
	if PendingTTL != 24*time.Hour || ApprovedTTL != time.Hour {
		t.Errorf("D6 policy constants drifted: pending %v, approved %v", PendingTTL, ApprovedTTL)
	}
	if m.rootCheck == nil {
		t.Error("NewManager must wire a root check")
	}
}

func TestJIT_RequestDigestIsStableAndSensitive(t *testing.T) {
	a := requestDigest("admin-1", "root", "break-glass", "2026-10-13T10:00:00Z")
	b := requestDigest("admin-1", "root", "break-glass", "2026-10-13T10:00:00Z")
	if a != b {
		t.Fatal("digest must be deterministic for identical content")
	}
	// Any changed argument (the replay negative) must produce a different
	// digest.
	cases := [][]string{
		{"admin-2", "root", "break-glass", "2026-10-13T10:00:00Z"},    // requester changed
		{"admin-1", "finance", "break-glass", "2026-10-13T10:00:00Z"}, // role changed
		{"admin-1", "root", "other reason", "2026-10-13T10:00:00Z"},   // reason changed
		{"admin-1", "root", "break-glass", "2026-10-13T11:00:00Z"},    // version changed
	}
	for i, c := range cases {
		if got := requestDigest(c[0], c[1], c[2], c[3]); got == a {
			t.Errorf("case %d: digest collided with the original", i)
		}
	}
	if len(a) != 64 {
		t.Errorf("digest must be hex sha256 (64 chars), got %d", len(a))
	}
}

func TestJIT_BindsFeedDigest(t *testing.T) {
	r := &JITRecord{
		AdminID:   "admin-1",
		Role:      "root",
		Reason:    "break-glass",
		CreatedAt: time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC),
	}
	b := bindsFor(r)
	if b.Org != "admin-1" || b.Entity != "root" {
		t.Errorf("binds mapping wrong: %+v", b)
	}
	if b.EntityVersion != "2026-10-13T10:00:00Z" {
		t.Errorf("EntityVersion must pin the creation stamp, got %q", b.EntityVersion)
	}
	if b.ParamsDigest == "" {
		t.Fatal("ParamsDigest must be set")
	}
	// bindsFor must be stable across re-derivation (what the decision path
	// re-computes equals what the reviewer saw).
	if bindsFor(r) != b {
		t.Error("binds re-derivation diverged")
	}
}

func TestJIT_FailClosedWithoutPool(t *testing.T) {
	m := NewManager(nil)
	ctx := context.Background()
	saw := ApprovalBinds{ParamsDigest: "x"}
	if _, err := m.Request(ctx, "a", "r", "why"); !errors.Is(err, ErrNoPool) {
		t.Errorf("Request without pool: got %v, want ErrNoPool", err)
	}
	if _, err := m.Approve(ctx, "id", "ap", saw); !errors.Is(err, ErrNoPool) {
		t.Errorf("Approve without pool: got %v, want ErrNoPool", err)
	}
	if _, err := m.Deny(ctx, "id", "ap", saw); !errors.Is(err, ErrNoPool) {
		t.Errorf("Deny without pool: got %v, want ErrNoPool", err)
	}
	if _, err := m.Get(ctx, "id"); !errors.Is(err, ErrNoPool) {
		t.Errorf("Get without pool: got %v, want ErrNoPool", err)
	}
	if _, err := m.ExpirePast(ctx); !errors.Is(err, ErrNoPool) {
		t.Errorf("ExpirePast without pool: got %v, want ErrNoPool", err)
	}
	if _, err := m.PendingRequests(ctx); !errors.Is(err, ErrNoPool) {
		t.Errorf("PendingRequests without pool: got %v, want ErrNoPool", err)
	}
	if m.IsActive(ctx, "a", "r") {
		t.Error("D7: IsActive must answer false (fail closed) without a pool")
	}
}

func TestJIT_FailClosedWithoutRootCheck(t *testing.T) {
	// A lazy, never-connected pool keeps the manager past the pool guard;
	// the missing root checker must stop the decision before any fetch.
	pool, err := pgxpool.New(context.Background(), "postgres://127.0.0.1:1/unused")
	if err != nil {
		t.Fatalf("lazy pool: %v", err)
	}
	defer pool.Close()
	m := NewManager(pool)
	m.WithRootCheck(nil) // explicit fail-closed configuration
	if _, err := m.Approve(context.Background(), "id", "approver", ApprovalBinds{}); !errors.Is(err, ErrApproverNotRoot) {
		t.Errorf("decision without root checker must fail closed, got %v", err)
	}
}

func TestJIT_PostgresRootCheckNilPoolFailsClosed(t *testing.T) {
	rc := PostgresRootCheck(nil)
	ok, err := rc(context.Background(), "someone")
	if ok || !errors.Is(err, ErrNoPool) {
		t.Errorf("nil-pool root check: got (%v, %v), want (false, ErrNoPool)", ok, err)
	}
}

func TestJIT_StatusTaxonomy(t *testing.T) {
	// D2: the canonical vocabulary. Values are storage-visible; changing
	// them silently would corrupt existing rows.
	for got, want := range map[string]string{
		StatusPending:  "pending",
		StatusApproved: "approved",
		StatusDenied:   "denied",
		StatusExpired:  "expired",
	} {
		if got != want {
			t.Errorf("status constant drifted: got %q, want %q", got, want)
		}
	}
}
