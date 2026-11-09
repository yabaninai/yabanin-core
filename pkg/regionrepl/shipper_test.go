package regionrepl

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestShipper_Success(t *testing.T) {
	var got []RollupRow
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p struct {
			Rows []RollupRow `json:"rows"`
		}
		_ = json.NewDecoder(r.Body).Decode(&p)
		got = p.Rows
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	s := NewShipper(srv.URL, "sg")
	rows := []RollupRow{{Region: "sg", Day: "2026-01-01", ModelUsed: "smart", RequestCount: 5}}
	if err := s.Ship(context.Background(), rows); err != nil {
		t.Fatalf("Ship: %v", err)
	}
	if len(got) != 1 || got[0].RequestCount != 5 {
		t.Errorf("unexpected ingest: %+v", got)
	}
}

func TestShipper_RetryTransientError(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = io.Copy(io.Discard, r.Body)
		if calls < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	s := NewShipper(srv.URL, "sg")
	if err := s.Ship(context.Background(), []RollupRow{{Region: "sg", Day: "2026-01-01"}}); err != nil {
		t.Fatalf("expected eventual success, got: %v", err)
	}
	if calls != 3 {
		t.Errorf("expected 3 attempts, got %d", calls)
	}
}

func TestShipper_EmptyRows_Noop(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer srv.Close()
	s := NewShipper(srv.URL, "sg")
	if err := s.Ship(context.Background(), nil); err != nil {
		t.Fatalf("Ship(nil): %v", err)
	}
	if called {
		t.Error("expected no HTTP call for empty rows")
	}
}

func TestShipper_AllAttemptsFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	s := NewShipper(srv.URL, "sg")
	err := s.Ship(context.Background(), []RollupRow{{Region: "sg", Day: "2026-01-01"}})
	if err == nil {
		t.Fatal("expected error after 3 failures")
	}
}

func TestHashOrg_StableAndTruncated(t *testing.T) {
	a := hashOrg("org-1")
	b := hashOrg("org-1")
	c := hashOrg("org-2")
	if a != b {
		t.Error("hash not deterministic")
	}
	if a == c {
		t.Error("different orgs hashed same")
	}
	if len(a) != 8 {
		t.Errorf("expected 8-char prefix, got %d", len(a))
	}
}

func TestHashOrg_Empty(t *testing.T) {
	if hashOrg("") != "" {
		t.Error("expected empty hash for empty org")
	}
}
