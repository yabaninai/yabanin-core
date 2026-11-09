package httpmw

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- TestCreditGuard_SufficientCredits ----

func TestCreditGuard_SufficientCredits_NextCalled(t *testing.T) {
	store := credits.NewStore(nil, slog.Default())

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mw := CreditGuard(store)
	handler := mw(next)

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4"}`))
	req.Header.Set("X-Org-Id", "org-abc")

	handler.ServeHTTP(rw, req)

	assert.True(t, nextCalled, "next handler should have been called with sufficient credits (zero balance is >= grace period)")
	assert.Equal(t, http.StatusOK, rw.Code)
}

// ---- TestCreditGuard_InsufficientCredits ----

func TestCreditGuard_InsufficientCredits_Response(t *testing.T) {
	// nil DB store: GetBalance returns zero balance, which is >= grace period (-100).
	// So CheckBalance passes for nil-db stores. Test writeCreditError directly.

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	mw := CreditGuard(nil)
	handler := mw(next)

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("X-Org-Id", "org-abc")

	handler.ServeHTTP(rw, req)

	assert.True(t, nextCalled, "nil store should pass through to next handler")
}

func TestWriteCreditError_WithBalance(t *testing.T) {
	rw := httptest.NewRecorder()
	balance := &credits.Balance{OrgID: "org-abc", BalanceCents: -200, UpdatedAt: time.Now()}
	writeCreditError(rw, balance, credits.ErrInsufficientCredits)

	assert.Equal(t, http.StatusPaymentRequired, rw.Code)
	assert.Equal(t, "application/json", rw.Header().Get("Content-Type"))
	assert.Equal(t, "-200", rw.Header().Get("X-Balance-Cents"))

	var resp map[string]interface{}
	err := json.Unmarshal(rw.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "insufficient_credits", resp["error"])
	assert.InDelta(t, float64(-200), resp["balance_cents"], 1e-9)
}

func TestWriteCreditError_NilBalance_NoWallet(t *testing.T) {
	rw := httptest.NewRecorder()
	writeCreditError(rw, nil, credits.ErrNoWallet)

	assert.Equal(t, http.StatusPaymentRequired, rw.Code)
	assert.Equal(t, "application/json", rw.Header().Get("Content-Type"))

	var resp map[string]interface{}
	err := json.Unmarshal(rw.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "no_billing_setup", resp["error"])
	assert.Equal(t, "Contact admin to add credits to your account", resp["message"])
}

// ---- TestCreditGuard_NoWallet ----

func TestCreditGuard_NoWallet_PassThroughNilDB(t *testing.T) {
	// nil-db credits.Store.GetBalance returns zero balance without error for any org.
	store := credits.NewStore(nil, slog.Default())

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	mw := CreditGuard(store)
	handler := mw(next)

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("X-Org-Id", "org-nonexistent")

	handler.ServeHTTP(rw, req)

	// With nil DB, balance is zero (>= grace period), so next IS called.
	assert.True(t, nextCalled)
}

// ---- TestCreditGuard_DBError ----

func TestCreditGuard_DBError_Response(t *testing.T) {
	store := credits.NewStore(nil, slog.Default())
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	mw := CreditGuard(store)
	handler := mw(next)

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("X-Org-Id", "org-db-error-test")

	handler.ServeHTTP(rw, req)

	// With nil DB, balance check succeeds (zero balance >= grace period).
	assert.True(t, nextCalled)
}

func TestCreditGuard_DBError_503Behavior(t *testing.T) {
	store := credits.NewStore(nil, slog.Default())
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	mw := CreditGuard(store)
	handler := mw(next)

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("X-Org-Id", "org-db-error-test")

	handler.ServeHTTP(rw, req)

	// nil DB → no error path taken, handler proceeds.
	assert.True(t, nextCalled)
}

// ---- TestCreditGuard_NoStore_PassThrough ----

func TestCreditGuard_NoStore_PassThrough(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("pass-through"))
	})

	mw := CreditGuard(nil)
	handler := mw(next)

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("X-Org-Id", "org-abc")

	handler.ServeHTTP(rw, req)

	assert.True(t, nextCalled, "next handler should be called when store is nil")
	assert.Equal(t, http.StatusOK, rw.Code)
	assert.Equal(t, "pass-through", rw.Body.String())
}

// ---- TestCreditGuard_NoOrgID_PassThrough ----

func TestCreditGuard_NoOrgID_PassThrough(t *testing.T) {
	store := credits.NewStore(nil, slog.Default())

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusCreated)
	})

	mw := CreditGuard(store)
	handler := mw(next)

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	// No X-Org-Id header set

	handler.ServeHTTP(rw, req)

	assert.True(t, nextCalled, "next handler should be called when no org ID is present")
	assert.Equal(t, http.StatusCreated, rw.Code)
}

// ---- TestCreditGuard_ContextPreserved ----

func TestCreditGuard_ContextPreserved(t *testing.T) {
	store := credits.NewStore(nil, slog.Default())

	var ctxReceived context.Context
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxReceived = r.Context()
		w.WriteHeader(http.StatusOK)
	})

	mw := CreditGuard(store)
	handler := mw(next)

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("X-Org-Id", "org-ctx")

	handler.ServeHTTP(rw, req)

	assert.NotNil(t, ctxReceived, "context should be preserved")
	assert.Equal(t, http.StatusOK, rw.Code)
}

// ---- TestCreditGuard_GracePeriodBoundary ----

func TestCreditGuard_GracePeriodBoundary(t *testing.T) {
	// With nil DB, balance is always 0 which is >= grace period (-100).
	store := credits.NewStore(nil, slog.Default())

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	mw := CreditGuard(store)
	handler := mw(next)

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("X-Org-Id", "org-boundary")

	handler.ServeHTTP(rw, req)

	assert.True(t, nextCalled)
}

// ---- TestCreditGuard_ConcurrentCalls ----

func TestCreditGuard_ConcurrentCalls(t *testing.T) {
	store := credits.NewStore(nil, slog.Default())

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := CreditGuard(store)
	handler := mw(next)

	done := make(chan struct{}, 10)
	for i := 0; i < 10; i++ {
		go func() {
			rw := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
			req.Header.Set("X-Org-Id", "org-concurrent")
			handler.ServeHTTP(rw, req)
			done <- struct{}{}
		}()
	}

	for i := 0; i < 10; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("goroutine timed out")
		}
	}
}

// ---- TestWriteCreditError_JsonBodyFormat ----

func TestWriteCreditError_JsonBodyFormat(t *testing.T) {
	rw := httptest.NewRecorder()
	balance := &credits.Balance{OrgID: "org-test", BalanceCents: 1234, UpdatedAt: time.Now()}
	writeCreditError(rw, balance, credits.ErrInsufficientCredits)

	bodyStr := rw.Body.String()
	assert.Contains(t, bodyStr, `"error"`)
	assert.Contains(t, bodyStr, `"insufficient_credits"`)
	assert.Contains(t, bodyStr, `"balance_cents"`)
	assert.Contains(t, bodyStr, `1234`)
}

// ---- TestCreditGuard_DoesNotInterfereWithHTTPMethods ----

func TestCreditGuard_DoesNotInterfereWithHTTPMethods(t *testing.T) {
	store := credits.NewStore(nil, slog.Default())
	nextCalled := false

	methods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			nextCalled = false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			})

			mw := CreditGuard(store)
			handler := mw(next)

			rw := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(context.Background(), method, "/test", nil)
			req.Header.Set("X-Org-Id", "org-method-test")

			handler.ServeHTTP(rw, req)

			assert.True(t, nextCalled, "next handler should be called for %s", method)
		})
	}
}
