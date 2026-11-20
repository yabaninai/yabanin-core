package loopexec

// DUALFORM-ORACLE-01 chat leg (auth/SSE correction packet, case 10): the
// chat/agent-loop form (BuiltinExecutor.Execute → toolexec.ExecuteGuarded,
// no gateway pre-check) is pinned by a COUNTABLE SIDE EFFECT rather than
// error text. The protected effect is the sink hit: the allowed call
// executes exactly once and returns the payload; after the admin flip to
// deny the refusal lands within the documented engine bound (5s TTL), and
// once effective the sink count is FROZEN — repeated refused attempts
// never egress again. The frozen count is the refusal oracle, and the
// refusal is typed (ErrNotPermitted wrapping a guard refusal), never a
// payload. During the TTL propagation window attempts may still egress;
// that window is the accepted bound contract (RP8), not a defect this
// case introduces.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/reireirei/yabanin/pkg/toolexec"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// chatWebFetchCall builds the (config, call) pair for web_fetch on org.
func chatWebFetchCall(org, url string) (Config, Call) {
	cfg := validConfig()
	cfg.Scope.OrgID = org
	cfg.AllowedTools = []string{"yabanin:" + toolexec.ToolWebFetch}
	call := builtinCall(toolexec.ToolWebFetch, json.RawMessage(`{"url":"`+url+`"}`))
	call.Scope = cfg.Scope
	return cfg, call
}

func awaitChatToolRefusal(t *testing.T, execute func() error, hits *atomic.Int32) int32 {
	t.Helper()
	expected := hits.Load()
	deadline := time.Now().Add(revChatBound)
	for {
		before := hits.Load()
		if before != expected {
			t.Fatalf("chat propagation: attempt boundary drift (sink hits %d, want %d)", before, expected)
		}
		err := execute()
		if err == nil {
			// Still-allowed propagation attempts each egress exactly once;
			// the deadline is checked before another attempt can run.
			expected++
			if n := hits.Load(); n != expected {
				t.Fatalf("chat propagation: allowed attempt egressed %d times (sink hits %d→%d)", n-before, before, n)
			}
			if time.Now().After(deadline) {
				t.Fatal("chat path still allowed at bound (commit+7s)")
			}
		} else {
			if !errors.Is(err, ErrNotPermitted) {
				t.Fatalf("chat refusal must be a typed permission error, got %v", err)
			}
			if n := hits.Load(); n != before {
				t.Fatalf("chat refusal: refused attempt egressed (sink hits %d→%d)", before, n)
			}
			return expected
		}
		time.Sleep(revChatPollEvery)
	}
}

func assertChatToolRefusalHold(t *testing.T, execute func() error, hits *atomic.Int32, expected int32) {
	t.Helper()
	holdEnd := time.Now().Add(revChatForever)
	for time.Now().Before(holdEnd) {
		before := hits.Load()
		if err := execute(); !errors.Is(err, ErrNotPermitted) {
			t.Fatalf("chat hold: call no longer refused: err=%v", err)
		}
		if n := hits.Load(); n != before {
			t.Fatalf("chat hold: refused attempt egressed (sink hits %d→%d)", before, n)
		}
		time.Sleep(revChatPollEvery)
	}
	if n := hits.Load(); n != expected {
		t.Fatalf("chat hold: whole-run bound broken (sink hits %d, want %d)", n, expected)
	}
}

func TestDualformOracle_02_ChatFormCountableSideEffect(t *testing.T) {
	if testing.Short() {
		t.Skip("disposable stands are skipped in -short mode")
	}
	pool := testdb.Postgres(t)
	ctx := context.Background()

	var hits atomic.Int32
	sinkBody := `{"text":"chat payload"}`
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, sinkBody)
	}))
	t.Cleanup(sink.Close)

	store := toolpolicy.NewStore(pool)
	engine := toolpolicy.NewEngine(store, 5*time.Second)
	exec := newGuardedChatExecutor(t, engine)
	org := mustChatOrg(t, pool, fmt.Sprintf("dualform-chat-%d", time.Now().UnixNano()))
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM tool_policies WHERE org_id = $1::uuid`, org)
		_, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id = $1::uuid`, org)
	})
	mustChatRows(t, ctx, store, org, chatRow{name: "df-chat-allow", tool: toolexec.ToolWebFetch,
		action: toolpolicy.ActionAllow, priority: 50})
	cfg, call := chatWebFetchCall(org, sink.URL+"/doc")

	res, err := exec.Execute(ctx, cfg, call)
	if err != nil {
		t.Fatalf("chat allow: refused (err=%v)", err)
	}
	if !containsPayload(res.Payload, sinkBody) {
		t.Fatalf("chat allow: payload %s does not carry the sink body", res.Payload)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("chat allow: expected exactly one sink hit, got %d", n)
	}

	deny := toolpolicy.ActionDeny
	if _, err := store.Update(ctx, org, "df-chat-allow", toolpolicy.UpdateParams{Action: &deny}); err != nil {
		t.Fatalf("chat flip: update: %v", err)
	}
	execute := func() error {
		_, err := exec.Execute(ctx, cfg, call)
		return err
	}
	expected := awaitChatToolRefusal(t, execute, &hits)
	assertChatToolRefusalHold(t, execute, &hits, expected)
}

// containsPayload reports whether the web_fetch result envelope carries the
// sink body verbatim in its content field.
func containsPayload(payload []byte, sinkBody string) bool {
	var env struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal(payload, &env); err != nil {
		return false
	}
	return env.Content == sinkBody
}
