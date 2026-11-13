//go:build integration

package handlers

// CV-02 request-journey browser acceptance stand.
//
// Boots the REAL admin router (dbRBACRouter wiring) over the REAL
// disposable migrated Postgres (testdb.Postgres), seeds two tenants, two
// session-cookie users and five request rows whose journey facts span every
// documented state (served-with-decision, pre-upstream termination with
// NULL counters, legacy NULL counters, recorded zeros, and a foreign-tenant
// marker row), serves the REAL built dashboard artifact (web/dashboard/dist)
// at the SAME origin as the API, writes a fixture whose row values are the
// raw request_logs columns read back by direct SQL (the independent store
// oracle for the browser suite), and runs the Playwright suite
// (web/dashboard/e2e-journey) as a subprocess. The Go test fails when the
// browser suite fails.
//
// Run (repo root):
//
//	cd web/dashboard && npm ci && npm run build
//	go test -tags integration -run TestCV02RequestJourneyBrowserAcceptance \
//	  ./services/admin/handlers/ -count=1 -timeout 15m
//
// CV02_DIST_DIR overrides the artifact location (defaults to
// <repo>/web/dashboard/dist). Docker must be reachable for testdb.Postgres.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/require"
)

// cv02Oracle is the raw request_logs column set the browser suite asserts
// against — marshalled straight into the fixture JSON. Pointers keep SQL
// NULL distinguishable from recorded zeros (the AC-UNK/AC-ZERO contract).
type cv02Oracle struct {
	Method               string   `json:"method"`
	ModelRequested       string   `json:"model_requested"`
	ModelUsed            string   `json:"model_used"`
	StatusCode           int      `json:"status_code"`
	DurationMs           int      `json:"duration_ms"`
	TokensIn             int      `json:"tokens_in"`
	TokensOut            int      `json:"tokens_out"`
	AttemptCount         *int     `json:"attempt_count"`
	RetryCount           *int     `json:"retry_count"`
	FirstTokenMs         *int     `json:"first_token_ms"`
	RoutingDecision      *string  `json:"routing_decision"`
	ClassifierClass      *string  `json:"classifier_class"`
	ClassifierConfidence *float32 `json:"classifier_confidence"`
	ClassifierSource     *string  `json:"classifier_source"`
	CacheHitType         *string  `json:"cache_hit_type"`
	UpstreamURL          *string  `json:"upstream_url"`
	Error                *string  `json:"error"`
	AnswerStatus         *string  `json:"answer_status"`
	AnswerContent        *string  `json:"answer_content"`
}

type cv02OrgRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cv02FixtureRow struct {
	Org       string     `json:"org"`
	RequestID string     `json:"request_id"`
	Oracle    cv02Oracle `json:"oracle"`
}

type cv02Fixture struct {
	RunID         string `json:"run_id"`
	SessionCookie string `json:"session_cookie"`
	Orgs          struct {
		A cv02OrgRef `json:"a"`
		B cv02OrgRef `json:"b"`
	} `json:"orgs"`
	Users struct {
		AOnly struct {
			Cookie string `json:"cookie"`
		} `json:"a_only"`
		Both struct {
			Cookie string `json:"cookie"`
		} `json:"both"`
	} `json:"users"`
	Rows struct {
		Served  cv02FixtureRow `json:"served"`
		Blocked cv02FixtureRow `json:"blocked"`
		Legacy  cv02FixtureRow `json:"legacy"`
		Zero    cv02FixtureRow `json:"zero"`
		TenantB cv02FixtureRow `json:"tenantb"`
	} `json:"rows"`
}

// cv02Seed is the explicit insert payload for one request_logs row; nil
// pointers write SQL NULL (unknown), so the seeded corpus itself encodes
// the unknown-vs-zero distinction the suite pins.
type cv02Seed struct {
	ModelRequested string
	ModelUsed      string
	StatusCode     int
	DurationMs     int
	TokensIn       int
	TokensOut      int
	AttemptCount   *int
	RetryCount     *int
	FirstTokenMs   *int
	Routing        *string
	ClfClass       *string
	ClfConfidence  *float32
	ClfSource      *string
	CacheHit       *string
	UpstreamURL    *string
	Error          *string
	Response       *string
	// OwnerUserID marks the row as a human console user's OWN attributed
	// request (user_id, agent_id NULL, api_key_id NULL) — the one durable
	// path besides grants that exposes payload columns (error, response).
	OwnerUserID *string
	// CreatedAgo backdates created_at: the dashboard's reporting window ends
	// at the page-boot minute, so rows stamped "now" can fall outside it.
	CreatedAgo time.Duration
}

func cv02IntPtr(v int) *int             { return &v }
func cv02StrPtr(v string) *string       { return &v }
func cv02Float32Ptr(v float32) *float32 { return &v }

// cv02RepoRoot walks up from the test's working directory (the package
// dir) to the module root; CV02_REPO_ROOT overrides for exotic layouts.
func cv02RepoRoot(t *testing.T) string {
	t.Helper()
	if v := os.Getenv("CV02_REPO_ROOT"); v != "" {
		return v
	}
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("cv02: go.mod not found walking up from the package directory")
		}
		dir = parent
	}
}

// cv02StaticSite serves the built dashboard artifact. The app is a hash
// router: only "/" and the hashed asset paths exist, so extension-less
// paths fall back to the shell instead of a 404.
func cv02StaticSite(dist string) http.Handler {
	fs := http.FileServer(http.Dir(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if filepath.Ext(r.URL.Path) == "" {
			r.URL.Path = "/"
		}
		fs.ServeHTTP(w, r)
	})
}

// cv02InsertRow writes one seeded request_logs row; nil pointers become
// SQL NULL, so the corpus itself encodes unknown-vs-zero.
func cv02InsertRow(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID, requestID string, s cv02Seed) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		INSERT INTO request_logs
			(org_id, request_id, method, model_requested, model_used, upstream_url,
			 status_code, duration_ms, tokens_in, tokens_out, error, response, prompt_hash,
			 cache_hit_type, classifier_class, classifier_confidence, classifier_source,
			 tier_used, ab_group, task_id, routing_decision,
			 first_token_ms, attempt_count, retry_count, home_region, user_id, created_at)
		VALUES ($1, $2, 'POST', $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, 'sha256:cv02',
			$12, $13, $14, $15, 'standard', 'b', 'task-cv02', $16, $17, $18, $19, 'e2e', $20, $21)`,
		orgID, requestID, s.ModelRequested, s.ModelUsed, s.UpstreamURL,
		s.StatusCode, s.DurationMs, s.TokensIn, s.TokensOut, s.Error, s.Response,
		s.CacheHit, s.ClfClass, s.ClfConfidence, s.ClfSource,
		s.Routing, s.FirstTokenMs, s.AttemptCount, s.RetryCount, s.OwnerUserID,
		time.Now().UTC().Add(-s.CreatedAgo))
	require.NoError(t, err, "cv02: seed %s", requestID)
}

// cv02ReadOracle reads the raw journey columns back by direct SQL — the
// independent store oracle the browser suite asserts against (never the
// store's own detail projection).
func cv02ReadOracle(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID, requestID string) cv02Oracle {
	t.Helper()
	var o cv02Oracle
	err := pool.QueryRow(ctx, `
		SELECT method, model_requested, model_used, status_code, duration_ms,
			tokens_in, tokens_out, attempt_count, retry_count, first_token_ms,
			routing_decision, classifier_class, classifier_confidence, classifier_source,
			cache_hit_type, upstream_url, error, response->>'status', response->>'content'
		FROM request_logs WHERE org_id = $1 AND request_id = $2`, orgID, requestID).
		Scan(&o.Method, &o.ModelRequested, &o.ModelUsed, &o.StatusCode, &o.DurationMs,
			&o.TokensIn, &o.TokensOut, &o.AttemptCount, &o.RetryCount, &o.FirstTokenMs,
			&o.RoutingDecision, &o.ClassifierClass, &o.ClassifierConfidence, &o.ClassifierSource,
			&o.CacheHitType, &o.UpstreamURL, &o.Error, &o.AnswerStatus, &o.AnswerContent)
	require.NoError(t, err, "cv02: oracle read for %s", requestID)
	return o
}

func TestCV02RequestJourneyBrowserAcceptance(t *testing.T) {
	repoRoot := cv02RepoRoot(t)
	dist := os.Getenv("CV02_DIST_DIR")
	if dist == "" {
		dist = filepath.Join(repoRoot, "web", "dashboard", "dist")
	}
	if _, err := os.Stat(filepath.Join(dist, "index.html")); err != nil {
		t.Skipf("cv02: dashboard artifact not built at %s — run `npm run build` in web/dashboard first", dist)
	}

	pool := testdb.Postgres(t)
	h, store := dbRBACRouter(t, pool)
	// The console route shape, not the portal one: dbRBACRouter enables the
	// developer portal, whose PUBLIC static /api/me (portal-session-gated)
	// would shadow the console mount — a portal /api/me 401 then trips the
	// dashboard's global 401 SessionGate at boot (router_console.go
	// documents exactly this precedence). CV-02 exercises the console
	// journey against the console route table.
	h.SetPortal(PortalOptions{Enabled: false})
	router := h.SetupRouter()
	ctx := context.Background()
	run := fmt.Sprintf("%d", time.Now().UnixNano())

	orgA, err := store.CreateOrganization(ctx, "CV02 Journey A "+run, "cv02-a-"+run)
	require.NoError(t, err)
	orgB, err := store.CreateOrganization(ctx, "CV02 Journey B "+run, "cv02-b-"+run)
	require.NoError(t, err)

	// userA: org-admin of A only. userAB: org-admin of both (tenant-switch
	// control). Session cookies are minted against the router's real secret
	// and revalidated through the store (TP-02), like production sessions.
	userA, err := store.CreateAdminUser(ctx,
		fmt.Sprintf("cv02-a-only-%s@sweep.test", run), "cv02 a only",
		"integration-hash-not-used-for-login", false)
	require.NoError(t, err)
	_, err = store.CreateOrgMembership(ctx, adminstore.OrgMembership{
		UserID: userA.ID, OrgID: orgA.ID, Role: adminstore.RoleOrgAdmin,
	})
	require.NoError(t, err)
	userAB, err := store.CreateAdminUser(ctx,
		fmt.Sprintf("cv02-both-%s@sweep.test", run), "cv02 both",
		"integration-hash-not-used-for-login", false)
	require.NoError(t, err)
	_, err = store.CreateOrgMembership(ctx, adminstore.OrgMembership{
		UserID: userAB.ID, OrgID: orgA.ID, Role: adminstore.RoleOrgAdmin,
	})
	require.NoError(t, err)
	_, err = store.CreateOrgMembership(ctx, adminstore.OrgMembership{
		UserID: userAB.ID, OrgID: orgB.ID, Role: adminstore.RoleOrgAdmin,
	})
	require.NoError(t, err)
	cookieA := sweepSessionCookie(t, "test-session-key", userA.ID)
	cookieAB := sweepSessionCookie(t, "test-session-key", userAB.ID)

	// Seeded corpus. served: every journey fact recorded, including a
	// reroute decision with rule ref + classifier columns and a FIX-20
	// complete response envelope. blocked: model_used === '' (pre-upstream
	// termination) with NULL counters. legacy: NULL counters, no decision,
	// no envelope. zero: recorded zeros (retry_count 0, empty error on a
	// failing status). tenantb: org-B marker row for the isolation probes.
	ruleID := "1b0e8a2c-3d4f-5a6b-7c8d-9e0f1a2b3c4d"
	rows := []struct {
		key   string
		orgID string
		id    string
		seed  cv02Seed
	}{
		{
			key: "served", orgID: orgA.ID, id: "req-cv02-served-" + run,
			seed: cv02Seed{
				ModelRequested: "cv02-gpt-x", ModelUsed: "cv02-gpt-x-fast",
				StatusCode: 200, DurationMs: 850, TokensIn: 120, TokensOut: 340,
				AttemptCount: cv02IntPtr(3), RetryCount: cv02IntPtr(2), FirstTokenMs: cv02IntPtr(210),
				Routing: cv02StrPtr(fmt.Sprintf(
					`{"source":"tier_router","from":"cv02-gpt-x","to":"cv02-gpt-x-fast","class":"medium","confidence":0.62,"threshold":0.6,"reason":"cost cap 429s","rule":{"id":%q,"version":"3"}}`, ruleID)),
				ClfClass: cv02StrPtr("medium"), ClfConfidence: cv02Float32Ptr(0.62), ClfSource: cv02StrPtr("budget"),
				CacheHit: cv02StrPtr("miss"), UpstreamURL: cv02StrPtr("https://upstream.cv02.test/v1"),
				Response: cv02StrPtr(`{"v":1,"kind":"model_response","status":"complete","model":"cv02-gpt-x-fast","content":"CV02 served answer ` + run + `","finish_reason":"stop","truncated":false}`),
				// Owned by userA: the own-row payload grant exposes error and
				// the parsed FIX-20 response view to the acting console user.
				OwnerUserID: &userA.ID,
				CreatedAgo:  1 * time.Minute,
			},
		},
		{
			key: "blocked", orgID: orgA.ID, id: "req-cv02-blocked-" + run,
			seed: cv02Seed{
				ModelRequested: "cv02-gpt-x", ModelUsed: "",
				StatusCode: 429, DurationMs: 0, TokensIn: 0, TokensOut: 0,
				Error:       cv02StrPtr("budget cap exceeded 429s"),
				OwnerUserID: &userA.ID,
				CreatedAgo:  2 * time.Minute,
			},
		},
		{
			key: "legacy", orgID: orgA.ID, id: "req-cv02-legacy-" + run,
			seed: cv02Seed{
				ModelRequested: "cv02-legacy-model", ModelUsed: "cv02-legacy-model",
				StatusCode: 200, DurationMs: 400, TokensIn: 10, TokensOut: 20,
				CreatedAgo: 3 * time.Minute,
			},
		},
		{
			key: "zero", orgID: orgA.ID, id: "req-cv02-zero-" + run,
			seed: cv02Seed{
				ModelRequested: "cv02-zero-model", ModelUsed: "cv02-zero-model",
				StatusCode: 502, DurationMs: 66, TokensIn: 5, TokensOut: 0,
				AttemptCount: cv02IntPtr(1), RetryCount: cv02IntPtr(0), FirstTokenMs: cv02IntPtr(12),
				Routing:    cv02StrPtr(`{"source":"passthrough","from":"cv02-zero-model"}`),
				Error:      cv02StrPtr(""),
				CreatedAgo: 4 * time.Minute,
			},
		},
		{
			key: "tenantb", orgID: orgB.ID, id: "req-cv02-tenantb-" + run,
			seed: cv02Seed{
				ModelRequested: "cv02-tenantb-model", ModelUsed: "cv02-tenantb-model",
				StatusCode: 200, DurationMs: 55, TokensIn: 7, TokensOut: 9,
				AttemptCount: cv02IntPtr(2), RetryCount: cv02IntPtr(1), FirstTokenMs: cv02IntPtr(33),
				Error:      cv02StrPtr("CV02-TENANT-B-SECRET-" + run),
				Response:   cv02StrPtr(`{"v":1,"kind":"model_response","status":"complete","model":"cv02-tenantb-model","content":"CV02-TENANT-B-ANSWER-` + run + `","truncated":false}`),
				CreatedAgo: 1 * time.Minute,
			},
		},
	}
	for _, r := range rows {
		cv02InsertRow(t, ctx, pool, r.orgID, r.id, r.seed)
	}

	// Serve the artifact and the API at ONE origin (cookie scope + same-origin
	// fetches are part of the contract under test).
	mux := http.NewServeMux()
	mux.Handle("/api/", router)
	mux.Handle("/auth/", router)
	mux.Handle("/", cv02StaticSite(dist))
	srv := httptest.NewUnstartedServer(mux)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)

	// Preflight: the minted sessions must authenticate against the served
	// origin with the SAME request shape the browser sends (fail fast with
	// a clear cause instead of ten opaque browser failures).
	for _, who := range []struct {
		name   string
		cookie *http.Cookie
	}{{"a_only", cookieA}, {"both", cookieAB}} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/version", nil)
		require.NoError(t, err)
		req.AddCookie(who.cookie)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode,
			"cv02 preflight %s: minted session must authenticate /api/version (body: %s)", who.name, cv02Tail(body, 300))
	}

	// Fixture: orgs, minted cookies, and the SQL read-back oracle per row.
	fixture := cv02Fixture{RunID: run, SessionCookie: cookieA.Name}
	fixture.Orgs.A = cv02OrgRef{ID: orgA.ID, Name: orgA.Name}
	fixture.Orgs.B = cv02OrgRef{ID: orgB.ID, Name: orgB.Name}
	fixture.Users.AOnly.Cookie = cookieA.Value
	fixture.Users.Both.Cookie = cookieAB.Value
	fixture.Rows.Served = cv02FixtureRow{Org: "a", RequestID: "req-cv02-served-" + run, Oracle: cv02ReadOracle(t, ctx, pool, orgA.ID, "req-cv02-served-"+run)}
	fixture.Rows.Blocked = cv02FixtureRow{Org: "a", RequestID: "req-cv02-blocked-" + run, Oracle: cv02ReadOracle(t, ctx, pool, orgA.ID, "req-cv02-blocked-"+run)}
	fixture.Rows.Legacy = cv02FixtureRow{Org: "a", RequestID: "req-cv02-legacy-" + run, Oracle: cv02ReadOracle(t, ctx, pool, orgA.ID, "req-cv02-legacy-"+run)}
	fixture.Rows.Zero = cv02FixtureRow{Org: "a", RequestID: "req-cv02-zero-" + run, Oracle: cv02ReadOracle(t, ctx, pool, orgA.ID, "req-cv02-zero-"+run)}
	fixture.Rows.TenantB = cv02FixtureRow{Org: "b", RequestID: "req-cv02-tenantb-" + run, Oracle: cv02ReadOracle(t, ctx, pool, orgB.ID, "req-cv02-tenantb-"+run)}

	fixturePath := filepath.Join(t.TempDir(), "cv02-fixture.json")
	raw, err := json.Marshal(fixture)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(fixturePath, raw, 0o600))

	artifacts := filepath.Join(repoRoot, "artifacts", "cv02-journey", run)
	require.NoError(t, os.MkdirAll(artifacts, 0o755))

	runCtx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "node",
		filepath.Join("node_modules", "@playwright", "test", "cli.js"),
		"test", "-c", "playwright.journey.config.ts")
	cmd.Dir = filepath.Join(repoRoot, "web", "dashboard")
	cmd.Env = append(os.Environ(),
		"CV02_BASE_URL="+srv.URL,
		"CV02_FIXTURE="+fixturePath,
		"CV02_ARTIFACTS="+artifacts,
	)
	out, err := cmd.CombinedOutput()
	logPath := filepath.Join(artifacts, "playwright.log")
	require.NoError(t, os.WriteFile(logPath, out, 0o644))
	t.Logf("cv02 playwright run %s: %d bytes of output at %s", run, len(out), logPath)
	if err != nil {
		t.Fatalf("cv02 browser acceptance suite FAILED (%v) — output tail:\n%s", err, cv02Tail(out, 6000))
	}
}

// cv02Tail returns the last n bytes of a byte slice for failure reporting.
func cv02Tail(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[len(b)-n:]
}
