package loopexec

// RP8-CHAT — pre-registered before implementation (task
// task/auth-policy-revocation-repro, base 786885f).
//
// FROZEN INVARIANT: the chat/agent-loop builtin path (BuiltinExecutor.Execute
// → toolexec.ExecuteGuarded, builtin.go — NO gateway pre-check) enforces the
// org tool policy under BOTH builtin addresses — the bare effective name
// ("time_now") and the qualified name ("yabanin:time_now"). After an admin
// flips a row in EITHER form to deny, the chat path must refuse within
// BOUND = 5s engine TTL + 2s grace (= 7s) and keep refusing; a cross-form
// allow row never un-denies; within ONE form the engine ranking (priority)
// is unchanged.
//
// FROZEN CASES:
//
//	RP8-HARNESS   real Postgres rows, real toolpolicy engine (5s TTL, the
//	              gateway wiring shape), guarded executor, real adapter
//	RP8-CHAT-PRE  allow row yabanin:time_now → Execute succeeds with payload
//	RP8-CHAT-FLIP store.Update action=deny (the admin PATCH store path)
//	RP8-CHAT-BOUND  first refusal ≤ commit + 7s
//	RP8-CHAT-FOREVER still refusing ≥ 2s later, no successful execution
//	RP8-CHAT-BARE fresh org, bare "time_now" deny row from cold: refusal
//	              ≤ commit + 7s, then holds — bare rows DO address the path
//	RP8-CHAT-MIX-BA  bare deny (p50) + prefixed ALLOW (p10): refused
//	RP8-CHAT-MIX-AB  prefixed deny (p50) + bare ALLOW (p10): refused
//	RP8-CHAT-PRIORITY prefixed ALLOW (p10) + prefixed deny (p50) — one form:
//	              ALLOWED (within-form ranking preserved)
//
// time_now performs no egress: the protected effect under test is the
// execution itself (payload present vs refusal), documented here as the
// oracle. Rows are written via the real toolpolicy Store (the same class the
// admin handlers drive; the admin HTTP path is covered end-to-end by the
// gateway reproducer in pkg/gateway).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/reireirei/yabanin/pkg/toolexec"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

const (
	revChatBound     = 7 * time.Second // 5s engine TTL + 2s grace
	revChatForever   = 2 * time.Second // post-refusal hold
	revChatPollEvery = 250 * time.Millisecond
)

// mustChatOrg inserts a real org row and returns its UUID.
func mustChatOrg(t *testing.T, pool *pgxpool.Pool, slug string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`, slug).Scan(&id); err != nil {
		t.Fatalf("org row %s: %v", slug, err)
	}
	return id
}

// chatRow is one frozen-form policy row for the dual-address cases.
type chatRow struct {
	name, tool, action string
	priority           int
}

// mustChatRows writes the rows via the real toolpolicy Store.
func mustChatRows(t *testing.T, ctx context.Context, store *toolpolicy.Store, org string, rows ...chatRow) {
	t.Helper()
	for _, r := range rows {
		if _, err := store.Create(ctx, toolpolicy.CreateParams{
			OrgID: org, Name: r.name, Subject: "*",
			Server: "*", Tool: r.tool, Action: r.action,
			Priority: r.priority, Enabled: true,
		}); err != nil {
			t.Fatalf("chat row %s/%s: %v", org, r.name, err)
		}
	}
}

// chatTimeNowCall returns the (config, call) pair executing time_now for org.
func chatTimeNowCall(org string) (Config, Call) {
	cfg := validConfig()
	cfg.Scope.OrgID = org
	call := builtinCall("time_now", nil)
	call.Scope = cfg.Scope
	return cfg, call
}

// chatDenyCase runs one deny-family case: seed the rows on a fresh org,
// require the first refusal within the bound, then require the hold.
func chatDenyCase(t *testing.T, ctx context.Context, store *toolpolicy.Store, exec *BuiltinExecutor, label, org string, rows ...chatRow) {
	t.Helper()
	mustChatRows(t, ctx, store, org, rows...)
	cfg, call := chatTimeNowCall(org)
	chatFirstRefusalWithin(t, ctx, exec, cfg, call, time.Now())
	chatHoldsRefusal(t, ctx, exec, cfg, call)
}

func TestToolPolicyRevocationChat(t *testing.T) {
	if testing.Short() {
		t.Skip("disposable stands are skipped in -short mode (fast loop stays Dockerless)")
	}
	pool := testdb.Postgres(t)
	ctx := context.Background()

	// RP8-HARNESS: the gateway wiring shape over the real database.
	store := toolpolicy.NewStore(pool)
	engine := toolpolicy.NewEngine(store, 5*time.Second)
	exec := newGuardedChatExecutor(t, engine)
	orgs := make([]string, 0, 6)
	for i := 0; i < 6; i++ {
		orgs = append(orgs, mustChatOrg(t, pool, fmt.Sprintf("repro-chat-%d-%s", i, fmt.Sprint(time.Now().UnixNano()))))
	}
	t.Cleanup(func() {
		for _, org := range orgs {
			_, _ = pool.Exec(ctx, `DELETE FROM tool_policies WHERE org_id = $1::uuid`, org)
			_, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id = $1::uuid`, org)
		}
	})

	// RP8-CHAT-PRE: qualified-key allow row → execution succeeds.
	mustChatRows(t, ctx, store, orgs[0], chatRow{name: "repro-chat-time", tool: "yabanin:time_now", action: toolpolicy.ActionAllow, priority: 50})
	cfgA, callA := chatTimeNowCall(orgs[0])
	res, err := exec.Execute(ctx, cfgA, callA)
	if err != nil || len(res.Payload) == 0 {
		t.Fatalf("RP8-CHAT-PRE: chat execution refused (err=%v payload=%s)", err, res.Payload)
	}

	// RP8-CHAT-FLIP: the admin PATCH store path.
	deny := toolpolicy.ActionDeny
	if _, err := store.Update(ctx, orgs[0], "repro-chat-time",
		toolpolicy.UpdateParams{Action: &deny}); err != nil {
		t.Fatalf("RP8-CHAT-FLIP: update: %v", err)
	}

	// RP8-CHAT-BOUND + RP8-CHAT-FOREVER: first refusal within the bound,
	// then the refusal holds.
	chatFirstRefusalWithin(t, ctx, exec, cfgA, callA, time.Now())
	chatHoldsRefusal(t, ctx, exec, cfgA, callA)

	// Deny family on fresh orgs (cold engine caches): the bare row DOES
	// address the path, and cross-form allows never un-deny.
	denyCases := []struct {
		label string
		org   string
		rows  []chatRow
	}{
		{"RP8-CHAT-BARE", orgs[1], []chatRow{{name: "repro-chat-bare", tool: "time_now", action: toolpolicy.ActionDeny, priority: 50}}},
		{"RP8-CHAT-MIX-BA", orgs[2], []chatRow{
			{name: "mix-ba-bare", tool: "time_now", action: toolpolicy.ActionDeny, priority: 50},
			{name: "mix-ba-allow", tool: "yabanin:time_now", action: toolpolicy.ActionAllow, priority: 10}}},
		{"RP8-CHAT-MIX-AB", orgs[3], []chatRow{
			{name: "mix-ab-prefixed", tool: "yabanin:time_now", action: toolpolicy.ActionDeny, priority: 50},
			{name: "mix-ab-allow", tool: "time_now", action: toolpolicy.ActionAllow, priority: 10}}},
	}
	for _, tc := range denyCases {
		chatDenyCase(t, ctx, store, exec, tc.label, tc.org, tc.rows...)
	}

	chatPriorityAndControl(t, ctx, store, exec, orgs[4], orgs[5])
}

// chatPriorityAndControl is RP8-CHAT-PRIORITY plus the no-policy negative
// control: within ONE form the ranking is untouched (prefixed allow p10
// beats prefixed deny p50 → the call runs), and an org with NO rows keeps
// executing (implicit allow).
func chatPriorityAndControl(t *testing.T, ctx context.Context, store *toolpolicy.Store, exec *BuiltinExecutor, prOrg, noPolicyOrg string) {
	t.Helper()
	mustChatRows(t, ctx, store, prOrg,
		chatRow{name: "pr-allow", tool: "yabanin:time_now", action: toolpolicy.ActionAllow, priority: 10},
		chatRow{name: "pr-deny", tool: "yabanin:time_now", action: toolpolicy.ActionDeny, priority: 50})
	cfgP, callP := chatTimeNowCall(prOrg)
	if res, err := exec.Execute(ctx, cfgP, callP); err != nil || len(res.Payload) == 0 {
		t.Fatalf("RP8-CHAT-PRIORITY: allow p10 must beat deny p50 within one form (err=%v)", err)
	}
	cfgN, callN := chatTimeNowCall(noPolicyOrg)
	if res, err := exec.Execute(ctx, cfgN, callN); err != nil || len(res.Payload) == 0 {
		t.Fatalf("no-policy org must keep executing (err=%v)", err)
	}
}

// chatFirstRefusalWithin is RP8-CHAT-BOUND: the first refusal must land
// within BOUND of the deny commit (5s engine TTL + 2s grace).
func chatFirstRefusalWithin(t *testing.T, ctx context.Context, exec *BuiltinExecutor, cfg Config, call Call, commit time.Time) {
	t.Helper()
	deadline := commit.Add(revChatBound)
	for {
		_, err := exec.Execute(ctx, cfg, call)
		if chatRefused(t, err) {
			t.Logf("RP8-CHAT-BOUND: first refused %v after commit", time.Since(commit).Round(time.Millisecond))
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("RP8-CHAT-BOUND: chat path still allowed at bound (commit+7s)")
		}
		time.Sleep(revChatPollEvery)
	}
}

// chatHoldsRefusal is RP8-CHAT-FOREVER: the refusal holds for the whole
// window and no successful execution sneaks through.
func chatHoldsRefusal(t *testing.T, ctx context.Context, exec *BuiltinExecutor, cfg Config, call Call) {
	t.Helper()
	foreverEnd := time.Now().Add(revChatForever)
	for time.Now().Before(foreverEnd) {
		if _, err := exec.Execute(ctx, cfg, call); !chatRefused(t, err) {
			t.Fatal("RP8-CHAT-FOREVER: chat path allowed again after propagation")
		}
		time.Sleep(revChatPollEvery)
	}
}

// newGuardedChatExecutor mirrors the deployment wiring: the guarded
// toolexec executor behind the loopexec adapter. time_now performs no
// egress, so no URL guard is needed.
func newGuardedChatExecutor(t *testing.T, engine *toolpolicy.Engine) *BuiltinExecutor {
	t.Helper()
	x := toolexec.NewExecutor(toolexec.NewDefaultConfig(), nil, nil).WithToolGuard(engine)
	b, err := NewBuiltinExecutor(x)
	if err != nil {
		t.Fatalf("RP8-HARNESS: NewBuiltinExecutor: %v", err)
	}
	return b
}

// chatRefused reports whether err is a policy refusal on the chat path
// (ErrNotPermitted wrapping toolexec tool_blocked). Anything else fails the
// test — it is not a policy outcome.
func chatRefused(t *testing.T, err error) bool {
	t.Helper()
	if err == nil {
		return false
	}
	if !errors.Is(err, ErrNotPermitted) {
		t.Fatalf("chat path unexpected error (not a policy outcome): %v", err)
	}
	return strings.Contains(err.Error(), "tool_blocked")
}
