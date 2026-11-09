package handlers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

// withRootCtx sets the admin session context values (the way
// adminauth.ChiAuthMiddleware does) so OrgScopeMiddleware can read the root
// flag. isRoot=false yields the same context shape as a real non-root
// session.
func withRootCtx(r *http.Request, isRoot bool) *http.Request {
	ctx := r.Context()
	ctx = context.WithValue(ctx, adminauth.ContextKeyUserID{}, "test-user")
	ctx = context.WithValue(ctx, adminauth.ContextKeyEmail{}, "t@x.test")
	ctx = context.WithValue(ctx, adminauth.ContextKeyIsRoot{}, isRoot)
	return r.WithContext(ctx)
}

// S01 org dimension, white-box via the exported OrgScopeMiddleware.
//
// OrgScopeMiddleware is the gate that will protect org-scoped mutations for
// future non-root admin roles. Every org-scoped route is root-only today
// (MustBeRoot 403s non-root first), so the middleware's non-root branch
// cannot be reached end-to-end through SetupRouter yet — pin the contract
// here by driving the middleware directly.
func TestS01_OrgScopeMiddleware(t *testing.T) {
	probe := func(method, path string, headers map[string]string, isRoot bool) (scope string, status int, ran bool) {
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ran = true
			scope = handlers.OrgScopeFromRequest(r)
			w.WriteHeader(http.StatusOK)
		})
		req := httptest.NewRequestWithContext(t.Context(), method, path, nil)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		req = withRootCtx(req, isRoot)
		w := httptest.NewRecorder()
		handlers.OrgScopeMiddleware(next).ServeHTTP(w, req)
		return scope, w.Code, ran
	}

	t.Run("non-root: matching scope passes, context carries the org", func(t *testing.T) {
		scope, _, ran := probe(http.MethodPut, "/api/organizations/org-a",
			map[string]string{handlers.OrgHeader: "org-a"}, false)
		if !ran {
			t.Fatal("expected the handler to run for a matching scope")
		}
		if scope != "org-a" {
			t.Errorf("scope = %q, want org-a", scope)
		}
	})

	t.Run("non-root: foreign scope is 403", func(t *testing.T) {
		_, status, ran := probe(http.MethodPut, "/api/organizations/org-a",
			map[string]string{handlers.OrgHeader: "org-b"}, false)
		if ran {
			t.Fatal("expected the handler NOT to run for a foreign scope")
		}
		if status != http.StatusForbidden {
			t.Errorf("status = %d, want 403", status)
		}
	})

	t.Run("non-root: missing scope header is 400", func(t *testing.T) {
		_, status, ran := probe(http.MethodPut, "/api/organizations/org-a", nil, false)
		if ran {
			t.Fatal("expected the handler NOT to run without a scope header")
		}
		if status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("root: missing header still passes (operator)", func(t *testing.T) {
		_, _, ran := probe(http.MethodPut, "/api/organizations/org-a", nil, true)
		if !ran {
			t.Fatal("expected the handler to run for root without a scope header")
		}
	})

	t.Run("root: mismatched header still passes (operator)", func(t *testing.T) {
		_, _, ran := probe(http.MethodPut, "/api/organizations/org-a",
			map[string]string{handlers.OrgHeader: "org-b"}, true)
		if !ran {
			t.Fatal("expected the handler to run for root with a mismatched header")
		}
	})

	t.Run("non-org-scoped route passes untouched", func(t *testing.T) {
		_, _, ran := probe(http.MethodGet, "/api/teams", nil, false)
		if !ran {
			t.Fatal("expected a non-org-scoped route to pass through")
		}
	})

	t.Run("GET on an org-scoped route passes (read-only)", func(t *testing.T) {
		// Reads are not scope-gated: the role dimension (MustBeRoot) covers
		// them. A future org-scoped read can require the header without
		// breaking the mutation contract.
		_, _, ran := probe(http.MethodGet, "/api/organizations/org-a", nil, false)
		if !ran {
			t.Fatal("expected a GET on an org route to pass through")
		}
	})
}
