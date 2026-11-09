package cli

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubReq builds a POST request (httptest.NewRequestWithContext) for handler
// helpers under test.
func stubReq() *http.Request {
	return httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", nil)
}

func fixedBudgetNow() time.Time {
	return time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
}

func TestTokenBudget_CheckOff(t *testing.T) {
	// Cap 0 = off: always ok, no warn.
	b := NewTokenBudget(0, 0, 24*time.Hour)
	b.now = fixedBudgetNow
	assert.False(t, b.Check(TaskBudgetScope, "", "task-1").Exceeded)
	assert.False(t, b.Check(SessionBudgetScope, "", "sess-1").Warn)
}

func TestTokenBudget_CheckAndRecord(t *testing.T) {
	const cap int64 = 1000
	b := NewTokenBudget(cap, 0, 24*time.Hour)
	b.now = fixedBudgetNow

	assert.False(t, b.Check(TaskBudgetScope, "", "t").Exceeded)

	// Below 80%: ok, no warn.
	b.Record(TaskBudgetScope, "", "t", 500)
	res := b.Check(TaskBudgetScope, "", "t")
	assert.False(t, res.Exceeded)
	assert.False(t, res.Warn)

	// At/above 80% (>=800): warn, not exceeded.
	b.Record(TaskBudgetScope, "", "t", 300) // total 800
	res = b.Check(TaskBudgetScope, "", "t")
	assert.False(t, res.Exceeded)
	assert.True(t, res.Warn)

	// At cap: exceeded.
	b.Record(TaskBudgetScope, "", "t", 200) // total 1000
	res = b.Check(TaskBudgetScope, "", "t")
	assert.True(t, res.Exceeded)
}

func TestTokenBudget_ScopesIndependent(t *testing.T) {
	b := NewTokenBudget(1000, 1000, 24*time.Hour)
	b.now = fixedBudgetNow
	b.Record(TaskBudgetScope, "", "x", 1000)
	// Task exceeded, session untouched.
	assert.True(t, b.Check(TaskBudgetScope, "", "x").Exceeded)
	assert.False(t, b.Check(SessionBudgetScope, "", "x").Exceeded)
}

func TestTokenBudget_TTLExpiry(t *testing.T) {
	b := NewTokenBudget(100, 0, time.Minute)
	t0 := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	b.now = func() time.Time { return t0 }
	b.Record(TaskBudgetScope, "", "t", 100)
	assert.True(t, b.Check(TaskBudgetScope, "", "t").Exceeded)

	// Advance past the TTL: the budget resets.
	t1 := t0.Add(2 * time.Minute)
	b.now = func() time.Time { return t1 }
	assert.False(t, b.Check(TaskBudgetScope, "", "t").Exceeded)
}

func TestTokenBudget_Eviction(t *testing.T) {
	b := NewTokenBudget(1000, 0, 24*time.Hour)
	b.now = fixedBudgetNow
	b.maxPer = 10

	// Fill 10 entries with staggered lastSeen so the oldest half is known.
	base := fixedBudgetNow()
	for i := 0; i < 10; i++ {
		// Record directly with a controlled lastSeen by manipulating now.
		b.now = func() time.Time { return base.Add(time.Duration(i) * time.Minute) }
		b.Record(TaskBudgetScope, "", fmt.Sprintf("e%d", i), 1)
	}
	require.Len(t, b.task, 10)

	// Adding one more triggers eviction of the oldest half (5 entries).
	b.now = func() time.Time { return base.Add(20 * time.Minute) }
	b.Record(TaskBudgetScope, "", "new", 1)
	assert.LessOrEqual(t, len(b.task), 10)
}

// --- gateway helpers (check/record) ---

func TestCheckTokenBudget_Disabled(t *testing.T) {
	gw := &gateway{tokenBudget: nil}
	w := httptest.NewRecorder()
	assert.True(t, gw.checkTokenBudget(w, stubReq(), "", "t", "s"))
	assert.Empty(t, w.Result().Header.Get("X-Yabanin-Budget-Warning"))
}

func TestCheckTokenBudget_Exceeded429(t *testing.T) {
	b := NewTokenBudget(100, 100, 24*time.Hour)
	b.now = fixedBudgetNow
	b.Record(TaskBudgetScope, "", "t", 100)
	gw := &gateway{tokenBudget: b}

	w := httptest.NewRecorder()
	req := stubReq()
	ok := gw.checkTokenBudget(w, req, "", "t", "s")
	assert.False(t, ok)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

func TestCheckTokenBudget_WarnHeader(t *testing.T) {
	const cap int64 = 100
	b := NewTokenBudget(cap, 0, 24*time.Hour)
	b.now = fixedBudgetNow
	b.Record(TaskBudgetScope, "", "t", 85) // 85% >= 80%
	gw := &gateway{tokenBudget: b}

	w := httptest.NewRecorder()
	ok := gw.checkTokenBudget(w, stubReq(), "", "t", "")
	assert.True(t, ok)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, w.Header().Get("X-Yabanin-Budget-Warning"))
}

func TestCheckTokenBudget_UntaggedSkipsTask(t *testing.T) {
	// No task id and no session id with only a task cap set: nothing to check.
	b := NewTokenBudget(100, 0, 24*time.Hour)
	b.now = fixedBudgetNow
	b.Record(TaskBudgetScope, "", "t", 100)
	gw := &gateway{tokenBudget: b}

	w := httptest.NewRecorder()
	ok := gw.checkTokenBudget(w, stubReq(), "", "", "")
	assert.True(t, ok)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRecordTokenBudgetSpend(t *testing.T) {
	b := NewTokenBudget(1000, 1000, 24*time.Hour)
	b.now = fixedBudgetNow
	gw := &gateway{tokenBudget: b}
	gw.recordTokenBudgetSpend("", "t", "s", 50)
	assert.Equal(t, int64(50), b.task[budgetKey{org: "", id: "t"}].tokens)
	assert.Equal(t, int64(50), b.session[budgetKey{org: "", id: "s"}].tokens)
}

func TestRecordTokenBudgetSpend_Disabled(t *testing.T) {
	gw := &gateway{tokenBudget: nil}
	// Must not panic.
	gw.recordTokenBudgetSpend("", "t", "s", 50)
}

// NEXT-02 (F02): task/session budget counters must be namespaced by the
// authenticated org. Two orgs using the same client-visible task or session
// ID are independent budgets — org A exhausting "deploy" must not 429 org B.
// The red versions of these tests ran against the un-namespaced maps and
// failed exactly as the finding describes.
func TestTokenBudget_TenantNamespacing(t *testing.T) {
	b := NewTokenBudget(1000, 0, time.Hour)

	// Org A exhausts the task budget for id "deploy".
	b.Record(TaskBudgetScope, "org-a", "deploy", 1000)
	if res := b.Check(TaskBudgetScope, "org-a", "deploy"); !res.Exceeded {
		t.Fatal("org-a deploy must be exceeded after recording the full cap")
	}
	// Org B with the SAME client id is a different namespace: still ok.
	if res := b.Check(TaskBudgetScope, "org-b", "deploy"); res.Exceeded {
		t.Fatal("org-b deploy must be independent of org-a's exhaustion")
	}
	// And it accumulates separately (800/1000 ≥ the 80% warn line).
	b.Record(TaskBudgetScope, "org-b", "deploy", 800)
	if res := b.Check(TaskBudgetScope, "org-b", "deploy"); res.Exceeded || !res.Warn {
		t.Fatalf("org-b at 80%% cap: want warn without exceed, got %+v", res)
	}
	// Session scope is namespaced identically.
	sb := NewTokenBudget(0, 100, time.Hour)
	sb.Record(SessionBudgetScope, "org-a", "sess-1", 100)
	if res := sb.Check(SessionBudgetScope, "org-a", "sess-1"); !res.Exceeded {
		t.Fatal("org-a sess-1 must be exceeded")
	}
	if res := sb.Check(SessionBudgetScope, "org-b", "sess-1"); res.Exceeded {
		t.Fatal("org-b sess-1 must be independent")
	}
}

// The empty-org namespace is shared (legacy behavior for auth modes without
// an org) but never collides with named orgs.
func TestTokenBudget_EmptyOrgNamespace(t *testing.T) {
	b := NewTokenBudget(100, 0, time.Hour)
	b.Record(TaskBudgetScope, "", "t", 100)
	if res := b.Check(TaskBudgetScope, "", "t"); !res.Exceeded {
		t.Fatal("empty-org namespace must still enforce its own budget")
	}
	if res := b.Check(TaskBudgetScope, "org-a", "t"); res.Exceeded {
		t.Fatal("empty-org exhaustion must not leak into named orgs")
	}
}

// Structural keys, not concatenation: org/id pairs that would collide under
// "org+\":\"+id" formatting stay distinct.
func TestTokenBudget_KeyIsStructural(t *testing.T) {
	b := NewTokenBudget(10, 0, time.Hour)
	b.Record(TaskBudgetScope, "org", "a:b", 10) // would collide with ("org:a","b")
	if res := b.Check(TaskBudgetScope, "org:a", "b"); res.Exceeded {
		t.Fatal("structural key must not collide across org/id splits")
	}
	if res := b.Check(TaskBudgetScope, "org", "a:b"); !res.Exceeded {
		t.Fatal("the exact recorded pair must be exceeded")
	}
}

// The gateway-level helpers must thread the authenticated org through: the
// stream and chat surfaces update the same scoped accounting contract.
func TestCheckTokenBudget_ScopedByOrg(t *testing.T) {
	gw := &gateway{tokenBudget: NewTokenBudget(1000, 0, time.Hour)}
	gw.tokenBudget.Record(TaskBudgetScope, "org-a", "deploy", 1000)

	// Org B passes with the SAME task id; org A gets the 429.
	rwB := httptest.NewRecorder()
	if !gw.checkTokenBudget(rwB, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", nil), "org-b", "deploy", "") {
		t.Fatal("org-b must pass with the same task id")
	}
	rwA := httptest.NewRecorder()
	if gw.checkTokenBudget(rwA, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", nil), "org-a", "deploy", "") {
		t.Fatal("org-a must be 429'd")
	}
	if rwA.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", rwA.Code)
	}
}
