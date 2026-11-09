package mcpagg

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// N05-P06-T02 / FIX-21 teeth: migration 0020 moved the ACTION dimension of
// the grant check from "every enabled row authorizes both" to the per-grant
// allowed_actions column. These tests pin the column-backed behavior: the
// seam grantAllowsAction consults the column, empty = deny-all (fail-closed,
// unlike the tool dimension where empty means unrestricted), the Go encoder
// rejects unknown/duplicate actions before the DB CHECK does, and the proxy
// call sites (tools/call and tools/list) both honor the narrowing with the
// pre-existing not_found indistinguishability posture.

func TestGrantAllowsActionColumnBacked(t *testing.T) {
	enabled := func(actions []string) *Grant {
		return &Grant{ID: "g", OrgID: "o", AgentID: "a", ServerName: "s",
			AllowedActions: actions, Enabled: true}
	}
	cases := []struct {
		name    string
		grant   *Grant
		action  string
		allowed bool
	}{
		{"column default authorizes both", enabled([]string{GrantActionInvoke, GrantActionList}), GrantActionInvoke, true},
		{"column default authorizes list", enabled([]string{GrantActionInvoke, GrantActionList}), GrantActionList, true},
		{"invoke-only denies list", enabled([]string{GrantActionInvoke}), GrantActionList, false},
		{"invoke-only allows invoke", enabled([]string{GrantActionInvoke}), GrantActionInvoke, true},
		{"list-only denies invoke", enabled([]string{GrantActionList}), GrantActionInvoke, false},
		{"empty list denies invoke", enabled([]string{}), GrantActionInvoke, false},
		{"empty list denies list", enabled([]string{}), GrantActionList, false},
		{"nil actions deny", enabled(nil), GrantActionInvoke, false},
		{"nil grant denies", nil, GrantActionInvoke, false},
		{"disabled grant denies", func() *Grant {
			g := enabled([]string{GrantActionInvoke, GrantActionList})
			g.Enabled = false
			return g
		}(), GrantActionInvoke, false},
		{"unknown action refused even when grant is wide", enabled([]string{GrantActionInvoke, GrantActionList}), "admin", false},
		{"unknown action refused on empty grant", enabled([]string{}), "", false},
	}
	for _, tc := range cases {
		if got := grantAllowsAction(tc.grant, tc.action); got != tc.allowed {
			t.Errorf("%s: grantAllowsAction = %v, want %v", tc.name, got, tc.allowed)
		}
	}
}

func TestEncodeActionsValidatesVocabulary(t *testing.T) {
	cases := []struct {
		name    string
		actions []string
		want    string // exact JSON encoding; empty means error expected
	}{
		{"both", []string{GrantActionInvoke, GrantActionList}, `["invoke","list"]`},
		{"invoke only", []string{GrantActionInvoke}, `["invoke"]`},
		{"empty is explicit deny-all", []string{}, `[]`},
		{"unknown refused", []string{GrantActionInvoke, "admin"}, ""},
		{"duplicate refused", []string{GrantActionInvoke, GrantActionInvoke}, ""},
		{"over-vocabulary refused", []string{GrantActionInvoke, GrantActionList, GrantActionInvoke}, ""},
	}
	for _, tc := range cases {
		got, err := encodeActions(tc.actions)
		if tc.want == "" {
			if err == nil {
				t.Errorf("%s: expected refusal, got %s", tc.name, string(got))
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected error: %v", tc.name, err)
			continue
		}
		if string(got) != tc.want {
			t.Errorf("%s: encoded %s, want %s", tc.name, string(got), tc.want)
		}
	}
}

// grantActionsStore is a store whose grant row carries the given actions
// (chain seam mirrors the same grant, tools unrestricted).
func grantActionsStore(upURL string, actions []string) *Store {
	grant := &Grant{ID: "gr-act", OrgID: "org-1", AgentID: "ag-1",
		ServerName: "knowledge", AllowedActions: actions, Enabled: true}
	db := &mcpMockDB{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if isChainQuery(sql) {
				return chainRowFor(grant)
			}
			if isGrantQuery(sql) {
				return &grantRow{g: grant}
			}
			return &serverRow{srv: testServer(upURL)}
		},
	}
	return NewStore(db)
}

// TestProxy_InvokeHonorsActionColumn — tools/call on an invoke-only grant
// passes; the same grant refuses tools/list (list not authorized) with the
// not_found posture and WITHOUT reaching the upstream.
func TestProxy_InvokeHonorsActionColumn(t *testing.T) {
	up := newUpstreamMCP(t, "json", "")
	p := NewProxy(grantActionsStore(up.URL, []string{GrantActionInvoke}), testConfig(), loopbackAllow(t), nil, nil)

	msg, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{"q":"x"}`)})
	if err != nil {
		t.Fatalf("invoke on invoke-only grant must pass: %v", err)
	}
	if msg == nil {
		t.Fatal("invoke must return the upstream message")
	}

	_, err = p.ListServerTools(context.Background(), "org-1", Identity{AgentID: "ag-1"}, "knowledge")
	if err == nil {
		t.Fatal("tools/list on an invoke-only grant must be refused")
	}
	var invErr *InvokeError
	if !errors.As(err, &invErr) || invErr.Code != ErrCodeNotFound {
		t.Fatalf("list refusal must keep the not_found indistinguishability, got %v", err)
	}
	if !strings.Contains(err.Error(), "not available for this org") {
		t.Fatalf("refusal must not reveal the action dimension, got %q", err.Error())
	}
}

// TestProxy_InvokeDeniesEmptyActions — an explicitly empty action list
// denies tools/call (fail-closed action dimension): the grant stays
// subject-valid but authorizes nothing.
func TestProxy_InvokeDeniesEmptyActions(t *testing.T) {
	up := newUpstreamMCP(t, "json", "")
	p := NewProxy(grantActionsStore(up.URL, []string{}), testConfig(), loopbackAllow(t), nil, nil)

	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{"q":"x"}`)})
	if err == nil {
		t.Fatal("empty action list must deny tools/call")
	}
	var invErr *InvokeError
	if !errors.As(err, &invErr) || invErr.Code != ErrCodeNotFound {
		t.Fatalf("empty-actions denial must keep the not_found posture, got %v", err)
	}
}

// TestProxy_ListHonorsListOnlyGrant — a list-only grant serves tools/list
// and refuses tools/call.
func TestProxy_ListHonorsListOnlyGrant(t *testing.T) {
	up, lastMethod := newToolsListUpstream(t, http.StatusOK)
	grant := &Grant{ID: "gr-act", OrgID: "org-1", AgentID: "ag-1",
		ServerName: "catalogsrv", AllowedActions: []string{GrantActionList}, Enabled: true}
	db := &mcpMockDB{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if isChainQuery(sql) {
				return chainRowFor(grant)
			}
			if isGrantQuery(sql) {
				return &grantRow{g: grant}
			}
			return &serverRow{srv: func() *Server {
				s := testServer(up.URL)
				s.Name = "catalogsrv"
				return s
			}()}
		},
	}
	p := NewProxy(NewStore(db), testConfig(), loopbackAllow(t), nil, nil)

	tools, err := p.ListServerTools(context.Background(), "org-1", Identity{AgentID: "ag-1"}, "catalogsrv")
	if err != nil {
		t.Fatalf("tools/list on a list-only grant must pass: %v", err)
	}
	if lastMethod.load() != "tools/list" || len(tools) == 0 {
		t.Fatalf("catalog must come from the upstream: method=%q tools=%d", lastMethod.load(), len(tools))
	}

	_, err = p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "catalogsrv", Tool: "search", Params: json.RawMessage(`{"q":"x"}`)})
	if err == nil {
		t.Fatal("tools/call on a list-only grant must be refused")
	}
	var invErr *InvokeError
	if !errors.As(err, &invErr) || invErr.Code != ErrCodeNotFound {
		t.Fatalf("invoke refusal must keep the not_found posture, got %v", err)
	}
}
