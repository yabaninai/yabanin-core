package cli

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/reireirei/yabanin/pkg/labels"
	"github.com/stretchr/testify/require"
)

// Critical-go wave 3 facts: the small writer/helper facts — the batch line
// recorder, guard hit rendering, MCP creds version parsing, PKCE S256, the
// session budget event keys and the label middleware helpers.
func TestWriterSmallFacts(t *testing.T) {
	for i := range uint8(13) {
		if i < 7 {
			writerSmallEarlyCase(t, int(i))
			continue
		}
		writerSmallLateCase(t, int(i))
	}
}

// writerSmallEarlyCase covers cases 0-6.
func writerSmallEarlyCase(t *testing.T, index int) {
	t.Helper()
	switch index {
	case 0:
		// batchLineRecorder mirrors net/http: the first Write implies 200,
		// an explicit WriteHeader wins, Flush is a no-op, Header stays the
		// same map.
		rec := newBatchLineRecorder()
		require.NotNil(t, rec.Header())
		require.Equal(t, 0, rec.code)
		rec.Header().Set("X-Test", "1")
		n, err := rec.Write([]byte(`{"ok":true}`))
		require.NoError(t, err)
		require.Equal(t, 11, n)
		require.Equal(t, http.StatusOK, rec.code)
		require.Equal(t, `{"ok":true}`, rec.body.String())
		rec.WriteHeader(http.StatusCreated)
		require.Equal(t, http.StatusCreated, rec.code)
		rec.Flush()
		require.Equal(t, http.StatusCreated, rec.code)
		require.Equal(t, "1", rec.Header().Get("X-Test"))
	case 1:
		// joinStrings skips the separator for empty and single inputs.
		require.Empty(t, joinStrings(nil, ", "))
		require.Equal(t, "a", joinStrings([]string{"a"}, ", "))
		require.Equal(t, "a, b", joinStrings([]string{"a", "b"}, ", "))
	case 2:
		// categoryList renders each hit as category:outcome.
		require.Empty(t, categoryList(nil))
		got := categoryList([]guardhooks.Hit{
			{Category: guardhooks.CatSecret, Outcome: guardhooks.Outcome("log")},
			{Category: guardhooks.Category("x"), Outcome: guardhooks.Outcome("y")},
		})
		require.Equal(t, "secret:log, x:y", got)
	case 3:
		// hasDetectorFailure reports only the detector-failure category.
		require.False(t, hasDetectorFailure(nil))
		require.False(t, hasDetectorFailure([]guardhooks.Hit{{Category: guardhooks.CatSecret}}))
		require.True(t, hasDetectorFailure([]guardhooks.Hit{
			{Category: guardhooks.CatSecret},
			{Category: guardhooks.CatDetectorFailure},
		}))
	case 4:
		// MCP creds versions parse as integers and round-trip.
		v, err := parseVersion("7")
		require.NoError(t, err)
		require.Equal(t, int64(7), v)
		_, err = parseVersion("abc")
		require.Error(t, err)
		require.Contains(t, err.Error(), `parse mcp creds version "abc"`)
		require.Equal(t, "7", formatVersion(7))
		require.Equal(t, "0", formatVersion(0))
		require.Equal(t, "-3", formatVersion(-3))
	case 5:
		// PKCE: the verifier is 43 unreserved base64url chars and unique per
		// call; the S256 challenge follows RFC 7636 Appendix B.
		v1, err := newPKCEVerifier()
		require.NoError(t, err)
		require.Len(t, v1, 43)
		_, err = base64.RawURLEncoding.DecodeString(v1)
		require.NoError(t, err)
		v2, err := newPKCEVerifier()
		require.NoError(t, err)
		require.NotEqual(t, v1, v2)
		const rfcVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		require.Equal(t, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", pkceChallengeS256(rfcVerifier))
	case 6:
		// Budget event attribution reads the request principal; the session
		// ledger keys have a fixed namespace.
		require.Empty(t, eventKeyID(context.Background()))
		require.Empty(t, eventSessionID(context.Background()))
		ctx := withPrincipal(context.Background(), principal{APIKeyID: "key1", SessionKeyID: "sess1"})
		require.Equal(t, "key1", eventKeyID(ctx))
		require.Equal(t, "sess1", eventSessionID(ctx))
		require.Equal(t, "yb:skey:sess1:tok", sessionTokenKey("sess1"))
		require.Equal(t, "yb:skey:sess1:ucost", sessionCostKey("sess1"))
	default:
		t.Fatalf("unknown early writer-small case %d", index)
	}
}

// writerSmallLateCase covers cases 7-12.
func writerSmallLateCase(t *testing.T, index int) {
	t.Helper()
	switch index {
	case 7:
		// noteBudgetWarning: nil writers are safe, the first value wins the
		// header, repeats are idempotent, distinct values append.
		require.NotPanics(t, func() { noteBudgetWarning(nil, "a") })
		w := httptest.NewRecorder()
		noteBudgetWarning(w, "approaching")
		require.Equal(t, "approaching", w.Header().Get("X-Yabanin-Budget-Warning"))
		noteBudgetWarning(w, "approaching")
		require.Equal(t, "approaching", w.Header().Get("X-Yabanin-Budget-Warning"))
		noteBudgetWarning(w, "exceeded")
		require.Equal(t, "approaching; exceeded", w.Header().Get("X-Yabanin-Budget-Warning"))
	case 8:
		// labelSecret reports only secret-category scan hits.
		syntheticKey := "sk-" + strings.Repeat("0", 24)
		require.True(t, labelSecret("token "+syntheticKey+" embedded"))
		require.False(t, labelSecret("plain operator text"))
	case 9:
		// stripLabelHeaders removes the aggregate and per-key label headers,
		// everything else survives.
		h := http.Header{}
		h.Set(labels.HeaderName, "a=b")
		h.Set(labels.PerKeyPrefix+"Team", "t")
		h.Set("X-Org-Id", "org1")
		stripLabelHeaders(h)
		require.NotContains(t, h, labels.HeaderName)
		require.NotContains(t, h, labels.PerKeyPrefix+"Team")
		require.Equal(t, "org1", h.Get("X-Org-Id"))
	case 10:
		// repoLabelOK bounds and whitelists the repo label characters.
		require.False(t, repoLabelOK(""))
		require.True(t, repoLabelOK("org/repo_name-v2@host:port"))
		require.False(t, repoLabelOK("bad space"))
		require.False(t, repoLabelOK("ünïcode"))
		require.False(t, repoLabelOK(stringsRepear(201)))
	case 11:
		// droppedKeys dedups in first-seen order and skips empty keys;
		// formatDropped bounds the header with an explicit suffix.
		require.Empty(t, droppedKeys(nil))
		got := droppedKeys([]labels.Dropped{
			{Key: "b", Reason: "policy"},
			{Key: "", Reason: "policy"},
			{Key: "a", Reason: "policy"},
			{Key: "b", Reason: "policy"},
		})
		require.Equal(t, "b,a", got)
		require.Empty(t, formatDropped(nil))
		require.Equal(t, "a:policy", formatDropped([]labels.Dropped{{Key: "a", Reason: "policy"}}))
		require.Equal(t, "…", formatDropped([]labels.Dropped{{Key: stringsRepear(600), Reason: "policy"}}))
	case 12:
		// bridgeLabels resolves the task tag priority header > label > gateway
		// config, and mirrors the repo label in whichever direction is missing.
		r := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
		res := &labels.Result{Labels: labels.Set{}}
		r.Header.Set("X-Yabanin-Task", "task-h")
		bridgeLabels(&gateway{}, r, res)
		require.Equal(t, "task-h", res.Labels["task"])
		r2 := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
		res2 := &labels.Result{Labels: labels.Set{"task": "task-l"}}
		bridgeLabels(&gateway{}, r2, res2)
		require.Equal(t, "task-l", r2.Header.Get("X-Yabanin-Task"))
		r3 := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
		res3 := &labels.Result{Labels: labels.Set{}}
		bridgeLabels(&gateway{taskTag: "task-g"}, r3, res3)
		require.Equal(t, "task-g", res3.Labels["task"])
		r4 := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
		res4 := &labels.Result{Labels: labels.Set{"git.repo": "org/repo"}}
		bridgeLabels(&gateway{}, r4, res4)
		require.Equal(t, "org/repo", r4.Header.Get("X-Yabanin-Repo"))
		r5 := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
		r5.Header.Set("X-Yabanin-Repo", "org/from-header")
		res5 := &labels.Result{Labels: labels.Set{}}
		bridgeLabels(&gateway{}, r5, res5)
		require.Equal(t, "org/from-header", res5.Labels["git.repo"])
		r6 := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
		r6.Header.Set("X-Yabanin-Repo", "bad space")
		res6 := &labels.Result{Labels: labels.Set{}}
		bridgeLabels(&gateway{}, r6, res6)
		require.NotContains(t, res6.Labels, "git.repo")
	default:
		t.Fatalf("unknown late writer-small case %d", index)
	}
}

// stringsRepear builds an n-byte filler for bound checks.
func stringsRepear(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}
