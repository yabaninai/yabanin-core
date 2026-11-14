//go:build integration

package handlers

// CV-02 request-journey browser acceptance stand (MANDATORY quality command).
//
// Boots the REAL admin router (dbRBACRouter wiring) over the REAL
// disposable migrated Postgres (testdb.Postgres), seeds two tenants, two
// session-cookie users and five request rows whose journey facts span every
// documented state (served-with-decision, pre-upstream termination with
// NULL counters, legacy NULL counters, recorded zeros, and a foreign-tenant
// marker row), serves the REAL built dashboard artifact (web/dashboard/dist)
// at the SAME origin as the API, writes a fixture whose row values are the
// raw request_logs columns read back by direct SQL (the independent store
// oracle for the browser suite), and runs the REGISTERED npm command
// (test:journey) as a subprocess, enforcing its results.
//
// MANDATORY semantics (2026-11-14 audit repair): this command NEVER skips.
// The built dashboard is a hard prerequisite — a missing artifact fails the
// run immediately and a stale/unverified one fails the product verifier
// (scripts/quality/browser-build.sh, the same fingerprint contract the
// browser gate trusts). The registered preflight is `make _quality-journey`
// (build/verify dist, then run this command). The run also enforces the
// FROZEN case registry: every required case ID below must appear exactly
// once in the Playwright results with a passed verdict; a missing, skipped,
// duplicate or unknown case FAILS acceptance — a green run with a dropped
// case is not acceptance. The run receipt (stand-summary.json) binds the
// verdict to the dist fingerprint + content hash and the repo state.
//
// The AC-RACE case uses the stand barrier: while armed, requests under
// /api/organizations/<orgA>/requests are parked mid-flight and forwarded
// only on release, so a genuinely delayed old-tenant response arrives after
// the browser has switched tenants through the real org switcher. The
// /_cv02/barrier* control endpoints are stand test surface, not product API.
//
// MANDATORY command (repo root):
//
//	go test -tags integration -run TestCV02RequestJourneyBrowserAcceptance \
//	  ./services/admin/handlers/ -count=1 -timeout 15m
//
// Artifacts land in <repo>/artifacts/cv02-journey/<run>/ (CV02_JOURNEY_OUT
// overrides the artifacts root; the quality gate points it into its evidence
// dir). CV02_DIST_DIR overrides the artifact location for isolated negative
// controls; an override records its own fingerprint and hash without
// claiming default-path freshness. Docker must be reachable for
// testdb.Postgres.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/require"
)

// cv02RequiredJourneyCases is the FROZEN browser-acceptance case registry
// (frozen 2026-11-14, coordination rev 0c85ca3, from b121b30
// web/dashboard/e2e-journey/journey.spec.ts plus the AC-RACE repair case).
// Every listed case ID MUST appear in the Playwright results exactly once
// with a passed verdict; a missing, skipped, duplicate, unknown or unnamed
// case FAILS the acceptance. IDs 1-10 are the frozen ten (AC-NARROW's two
// 390px tests pinned as individually addressable IDs); AC-RACE is the
// delayed-old-tenant-response case added by the 2026-11-14 audit repair.
// Registry changes are deliberate acceptance-scope decisions, never silent.
var cv02RequiredJourneyCases = []string{
	"AC-RT",
	"AC-BLK",
	"AC-UNK",
	"AC-ZERO",
	"AC-STALE",
	"AC-IDOR",
	"AC-KB",
	"AC-NARROW-SERVED",
	"AC-NARROW-BLOCKED",
	"AC-PERF",
	"AC-RACE",
}

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

// cv02FixtureControl carries the stand barrier's control endpoints for the
// AC-RACE case (stand test surface, not product API).
type cv02FixtureControl struct {
	BarrierArm     string `json:"barrier_arm"`
	BarrierRelease string `json:"barrier_release"`
	BarrierState   string `json:"barrier_state"`
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
	Control cv02FixtureControl `json:"control"`
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

// cv02DistEvidence binds the acceptance run to the exact built dashboard it
// served: the recorded source fingerprint (freshness — verified with the
// product's own browser-build.sh on the default artifact path) and a
// content hash over everything under dist.
type cv02DistEvidence struct {
	Dir                string `json:"dir"`
	Fingerprint        string `json:"fingerprint,omitempty"`
	FingerprintCurrent bool   `json:"fingerprint_current"`
	ArtifactSHA256     string `json:"artifact_sha256"`
	Files              int    `json:"files"`
}

// cv02RequireDashboardArtifact enforces the MANDATORY prerequisite: the
// built dashboard must exist and be fresh for the current source. It FAILS
// the test — this command never skips: a mandatory acceptance that cannot
// run its prerequisite must be red, not quietly green. Existence is checked
// BEFORE the verifier because browser-build.sh builds on demand when dist
// is missing; on the default path it then runs verify-only and fails on a
// stale/unverified artifact. An explicit CV02_DIST_DIR override (isolated
// negative controls) records its own fingerprint + hash without claiming
// default-path freshness.
func cv02RequireDashboardArtifact(t *testing.T, repoRoot, dist string) cv02DistEvidence {
	t.Helper()
	if _, err := os.Stat(filepath.Join(dist, "index.html")); err != nil {
		t.Fatalf("cv02: MANDATORY prerequisite missing: no built dashboard at %s (%v).\n"+
			"  The browser acceptance serves the real artifact. Build it first:\n"+
			"    cd web/dashboard && npm ci && npm run build\n"+
			"  or run the registered preflight gate: make _quality-journey\n"+
			"  This command fails on missing prerequisites; it never skips.", dist, err)
	}
	ev := cv02DistEvidence{Dir: dist, Fingerprint: cv02RecordedFingerprint(dist)}
	if dist == filepath.Join(repoRoot, "web", "dashboard", "dist") {
		out, err := exec.Command("bash",
			filepath.Join(repoRoot, "scripts", "quality", "browser-build.sh"), "dashboard").CombinedOutput()
		if err != nil {
			t.Fatalf("cv02: MANDATORY prerequisite failed: the dashboard build at %s is stale or "+
				"unverified for the current source (browser-build.sh: %v):\n%s\n"+
				"  Rebuild it: cd web/dashboard && npm run build   (or: make _quality-journey)",
				dist, err, cv02Tail(out, 2000))
		}
		ev.FingerprintCurrent = true
	}
	sum, files, err := cv02TreeSHA256(dist)
	require.NoError(t, err, "cv02: hashing dist artifact at %s", dist)
	ev.ArtifactSHA256, ev.Files = sum, files
	return ev
}

// cv02RecordedFingerprint reads dist/.build-fingerprint ("" when absent).
func cv02RecordedFingerprint(dist string) string {
	raw, err := os.ReadFile(filepath.Join(dist, ".build-fingerprint"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// cv02TreeSHA256 hashes the artifact content: every file's relative path
// (sorted) and bytes, so two runs agree only on identical dist trees.
func cv02TreeSHA256(root string) (string, int, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, p := range paths {
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return "", 0, err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return "", 0, err
		}
		h.Write([]byte(rel))
		h.Write([]byte{0})
		h.Write(data)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), len(paths), nil
}

// cv02BarrierHoldLimit bounds how long a parked request may stay held: a
// failing AC-RACE run must report, not hang the stand.
const cv02BarrierHoldLimit = 45 * time.Second

// cv02Barrier is the AC-RACE stand hook. While ARMED it parks every API
// request scoped to the old tenant (orgPrefix) instead of answering, so a
// genuinely in-flight old-tenant response reaches the browser only when the
// stand releases it — in AC-RACE, after the real org switcher has already
// moved the session to tenant B. The control endpoints under /_cv02/barrier
// are stand test surface, NOT product API.
type cv02Barrier struct {
	mu        sync.Mutex
	orgPrefix string
	armed     bool
	held      int
	released  int
	waiters   []chan struct{}
}

func cv02NewBarrier(orgID string) *cv02Barrier {
	return &cv02Barrier{orgPrefix: "/api/organizations/" + orgID + "/requests"}
}

// Handler returns the outermost stand handler: the /_cv02/barrier* control
// endpoints, parked old-tenant API requests while armed, everything else
// forwarded to the real mux untouched.
func (b *cv02Barrier) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_cv02/barrier":
			io.WriteString(w, b.stateJSON())
		case "/_cv02/barrier/arm":
			b.setArmed(true)
			w.WriteHeader(http.StatusNoContent)
		case "/_cv02/barrier/release":
			b.Release()
			w.WriteHeader(http.StatusNoContent)
		default:
			if b.holdsPath(r.URL.Path) {
				b.holdRequest(w, r, next)
				return
			}
			next.ServeHTTP(w, r)
		}
	})
}

func (b *cv02Barrier) setArmed(v bool) {
	b.mu.Lock()
	b.armed = v
	b.mu.Unlock()
}

// holdsPath reports whether the request path is a parked old-tenant API
// call (list and stats share the /requests prefix).
func (b *cv02Barrier) holdsPath(path string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.armed && strings.HasPrefix(path, b.orgPrefix)
}

// holdRequest parks one old-tenant request until Release, the request dying
// with its context, or the bounded safety deadline — then forwards it to
// the real router, so it completes late exactly like a slow upstream.
func (b *cv02Barrier) holdRequest(w http.ResponseWriter, r *http.Request, next http.Handler) {
	ch := make(chan struct{})
	b.mu.Lock()
	b.held++
	b.waiters = append(b.waiters, ch)
	b.mu.Unlock()
	timer := time.NewTimer(cv02BarrierHoldLimit)
	defer timer.Stop()
	select {
	case <-ch:
	case <-r.Context().Done():
	case <-timer.C:
	}
	next.ServeHTTP(w, r)
}

// Release disarms the barrier and flushes every parked request. Safe to
// call multiple times (control endpoint + test cleanup) and after server
// close; parked-request flushes are counted in `released`.
func (b *cv02Barrier) Release() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.armed = false
	for _, ch := range b.waiters {
		close(ch)
	}
	b.released += len(b.waiters)
	b.waiters = nil
}

// counters snapshots the parking counters for the run receipt.
func (b *cv02Barrier) counters() (held, released int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.held, b.released
}

func (b *cv02Barrier) stateJSON() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out, err := json.Marshal(struct {
		Armed    bool `json:"armed"`
		Held     int  `json:"held"`
		Released int  `json:"released"`
	}{b.armed, b.held, b.released})
	if err != nil {
		return `{"armed":false}`
	}
	return string(out)
}

// cv02PWReport mirrors the Playwright --reporter=json document
// (probe-verified against @playwright/test 1.63): stats counters, an errors
// array and recursive suites. Verdicts are taken from
// tests[].results[].status (passed|failed|timedOut|skipped|interrupted).
type cv02PWReport struct {
	Stats  cv02PWStats   `json:"stats"`
	Errors []cv02PWError `json:"errors"`
	Suites []cv02PWSuite `json:"suites"`
}

type cv02PWStats struct {
	StartTime  string  `json:"startTime"`
	DurationMs float64 `json:"duration"`
	Expected   int     `json:"expected"`
	Unexpected int     `json:"unexpected"`
	Flaky      int     `json:"flaky"`
	Skipped    int     `json:"skipped"`
}

type cv02PWError struct {
	Message string `json:"message"`
}

type cv02PWSuite struct {
	Title  string        `json:"title"`
	Specs  []cv02PWSpec  `json:"specs"`
	Suites []cv02PWSuite `json:"suites"`
}

type cv02PWSpec struct {
	Title string       `json:"title"`
	File  string       `json:"file"`
	Tests []cv02PWTest `json:"tests"`
}

type cv02PWTest struct {
	ProjectName string         `json:"projectName"`
	Results     []cv02PWResult `json:"results"`
}

type cv02PWResult struct {
	Status string `json:"status"`
}

// cv02FlatSpec is one spec with its describe path, for failure messages.
type cv02FlatSpec struct {
	Suite string
	Spec  cv02PWSpec
}

// cv02FlattenSpecs walks the report's nested suites (file > describe) into
// a flat spec list.
func cv02FlattenSpecs(suites []cv02PWSuite, prefix string, out []cv02FlatSpec) []cv02FlatSpec {
	for _, s := range suites {
		path := s.Title
		if prefix != "" {
			path = prefix + " > " + s.Title
		}
		for _, spec := range s.Specs {
			out = append(out, cv02FlatSpec{Suite: path, Spec: spec})
		}
		out = cv02FlattenSpecs(s.Suites, path, out)
	}
	return out
}

// cv02CaseResult is the stand's verdict for one browser case.
type cv02CaseResult struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
}

// cv02CaseID extracts the frozen case ID from a spec title: the first
// whitespace-delimited token, which must match the AC-* registry shape.
func cv02CaseID(title string) string {
	token := strings.TrimSpace(strings.SplitN(title, " ", 2)[0])
	if !strings.HasPrefix(token, "AC-") {
		return ""
	}
	for _, r := range token {
		if !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
			return ""
		}
	}
	return token
}

// cv02SpecVerdict maps one spec's Playwright results to the stand's
// verdict. A case passes only when every recorded result passed; any
// skipped result is "skipped"; anything else non-passed is "failed"; a
// spec with no recorded results is "not-run".
func cv02SpecVerdict(spec cv02PWSpec) string {
	verdict := "passed"
	runs := 0
	for _, test := range spec.Tests {
		for _, res := range test.Results {
			runs++
			switch {
			case res.Status == "skipped":
				return "skipped"
			case res.Status != "passed":
				verdict = "failed"
			}
		}
	}
	if runs == 0 {
		return "not-run"
	}
	return verdict
}

// cv02EnforceCaseRegistry applies the FROZEN registry to the parsed
// results: every required ID exactly once and passed; no unknown, unnamed
// or duplicate case IDs. Any violation fails the mandatory acceptance.
// cv02CaseVerdicts enforces the frozen case registry over the flattened
// specs: every required case exactly once and passed. Problems are returned
// (not raised) so the caller can write the run receipt FIRST and fail
// afterwards — a failing run keeps its evidence.
func cv02CaseVerdicts(specs []cv02FlatSpec) (cases []cv02CaseResult, problems []string) {
	byID := make(map[string][]cv02FlatSpec)
	for _, fs := range specs {
		id := cv02CaseID(fs.Spec.Title)
		if id == "" {
			problems = append(problems, fmt.Sprintf("unnamed journey case %q — every spec title must "+
				"start with its frozen AC-* case ID", fs.Spec.Title))
			continue
		}
		byID[id] = append(byID[id], fs)
	}
	for _, id := range cv02RequiredJourneyCases {
		got := byID[id]
		switch {
		case len(got) == 0:
			cases = append(cases, cv02CaseResult{ID: id, Status: "missing"})
			problems = append(problems, fmt.Sprintf("required journey case %s is MISSING from the results — "+
				"the frozen registry (%d cases) requires every case to run and pass; a green run with a "+
				"dropped case is not acceptance", id, len(cv02RequiredJourneyCases)))
			continue
		case len(got) > 1:
			problems = append(problems, fmt.Sprintf("journey case %s appears %d times — exactly one spec "+
				"per case ID is allowed", id, len(got)))
			continue
		}
		status := cv02SpecVerdict(got[0].Spec)
		cases = append(cases, cv02CaseResult{ID: id, Title: got[0].Spec.Title, Status: status})
		if status != "passed" {
			problems = append(problems, fmt.Sprintf("required journey case %s did not pass (status %q, "+
				"suite %q) — skipped or failed cases are not acceptance; see playwright.out for details",
				id, status, got[0].Suite))
		}
		delete(byID, id)
	}
	if len(byID) > 0 {
		ids := make([]string, 0, len(byID))
		for id := range byID {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		problems = append(problems, fmt.Sprintf("unknown journey cases %v are not in the frozen registry — "+
			"extend the registry deliberately, never by silent addition", ids))
	}
	return cases, problems
}

// cv02ExtractJSONObject finds the Playwright JSON report inside captured
// command output (npm --silent normally emits the document alone, but a
// stray prefix line must not break parsing): the first '{' whose JSON value
// ends the output. Failing to find it is a plumbing failure, not a pass.
func cv02ExtractJSONObject(t *testing.T, out []byte) []byte {
	t.Helper()
	for i := 0; i < len(out); i++ {
		if out[i] != '{' {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(out[i:]))
		var doc json.RawMessage
		if dec.Decode(&doc) != nil {
			continue
		}
		if dec.Decode(&doc) != io.EOF {
			continue // trailing content — not the report document
		}
		return out[i:]
	}
	t.Fatalf("cv02: no Playwright JSON report found in the test:journey output (%d bytes) — "+
		"reporter plumbing broken, not a pass", len(out))
	return nil
}

// cv02RunPlaywright runs the REGISTERED npm command (test:journey) with the
// JSON reporter, saves raw output as evidence and returns the parsed report,
// the suite error (nil when green) and the raw output. A failed suite still
// yields its report — the caller writes the receipt before failing. Only
// broken reporter plumbing (no parsable JSON document) fails here.
func cv02RunPlaywright(t *testing.T, repoRoot, baseURL, fixturePath, artifacts string) (cv02PWReport, error, []byte) {
	t.Helper()
	runCtx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "npm", "run", "--silent", "test:journey", "--", "--reporter=json")
	cmd.Dir = filepath.Join(repoRoot, "web", "dashboard")
	cmd.Env = append(os.Environ(),
		"CV02_BASE_URL="+baseURL,
		"CV02_FIXTURE="+fixturePath,
		"CV02_ARTIFACTS="+artifacts,
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, os.WriteFile(filepath.Join(artifacts, "playwright.out"), out, 0o644))
	t.Logf("cv02 playwright run: %d bytes of output kept at %s/playwright.out", len(out), artifacts)
	var report cv02PWReport
	require.NoError(t, json.Unmarshal(cv02ExtractJSONObject(t, out), &report),
		"cv02: Playwright JSON report does not parse")
	return report, err, out
}

// cv02StandSummary is the run receipt: the verdict bound to the exact
// artifact served (fingerprint + content hash), the case-by-case registry
// outcome, the suite stats, the barrier evidence and the repo state.
type cv02StandSummary struct {
	RunID         string           `json:"run_id"`
	StartedUTC    string           `json:"started_utc"`
	GitHead       string           `json:"git_head,omitempty"`
	GitDirty      bool             `json:"git_dirty"`
	Dist          cv02DistEvidence `json:"dist"`
	RequiredCases []string         `json:"required_cases"`
	Cases         []cv02CaseResult `json:"cases"`
	Stats         cv02PWStats      `json:"stats"`
	Barrier       struct {
		Held     int `json:"held"`
		Released int `json:"released"`
	} `json:"barrier"`
}

// cv02WriteStandSummary writes the run receipt next to the artifacts.
func cv02WriteStandSummary(t *testing.T, artifacts string, s cv02StandSummary) string {
	t.Helper()
	s.GitHead, s.GitDirty = cv02GitState(t)
	raw, err := json.MarshalIndent(s, "", "  ")
	require.NoError(t, err)
	path := filepath.Join(artifacts, "stand-summary.json")
	require.NoError(t, os.WriteFile(path, append(raw, '\n'), 0o644))
	return path
}

// cv02GitState reports HEAD and dirtiness (best effort; "" when gitless).
func cv02GitState(t *testing.T) (string, bool) {
	t.Helper()
	head, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		t.Logf("cv02: git HEAD unavailable (%v)", err)
		return "", false
	}
	status, err := exec.Command("git", "status", "--porcelain").Output()
	if err != nil {
		return strings.TrimSpace(string(head)), true
	}
	return strings.TrimSpace(string(head)), len(status) > 0
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
	started := time.Now().UTC()
	repoRoot := cv02RepoRoot(t)
	dist := os.Getenv("CV02_DIST_DIR")
	if dist == "" {
		dist = filepath.Join(repoRoot, "web", "dashboard", "dist")
	}
	// MANDATORY prerequisite — fails on a missing or stale artifact,
	// never skips (2026-11-14 audit repair).
	distEv := cv02RequireDashboardArtifact(t, repoRoot, dist)

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
	// fetches are part of the contract under test). The barrier wraps the
	// whole mux as the outermost handler (AC-RACE parks old-tenant API
	// requests mid-flight; /_cv02/barrier* are its control endpoints).
	barrier := cv02NewBarrier(orgA.ID)
	mux := http.NewServeMux()
	mux.Handle("/api/", router)
	mux.Handle("/auth/", router)
	mux.Handle("/", cv02StaticSite(dist))
	srv := httptest.NewUnstartedServer(barrier.Handler(mux))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	// LIFO: registered after srv.Close, so parked requests are flushed
	// BEFORE the server closes (and never outlive the test).
	t.Cleanup(barrier.Release)

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

	// Fixture: orgs, minted cookies, the SQL read-back oracle per row, and
	// the barrier control endpoints for AC-RACE.
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
	fixture.Control = cv02FixtureControl{
		BarrierArm:     "/_cv02/barrier/arm",
		BarrierRelease: "/_cv02/barrier/release",
		BarrierState:   "/_cv02/barrier",
	}

	fixturePath := filepath.Join(t.TempDir(), "cv02-fixture.json")
	raw, err := json.Marshal(fixture)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(fixturePath, raw, 0o600))

	artifacts := os.Getenv("CV02_JOURNEY_OUT")
	if artifacts == "" {
		artifacts = filepath.Join(repoRoot, "artifacts", "cv02-journey", run)
	}
	require.NoError(t, os.MkdirAll(artifacts, 0o755))

	// Registered command + frozen-registry enforcement (audit repair):
	// a green run missing a required case is not acceptance.
	report, suiteErr, out := cv02RunPlaywright(t, repoRoot, srv.URL, fixturePath, artifacts)
	specs := cv02FlattenSpecs(report.Suites, "", nil)
	cases, problems := cv02CaseVerdicts(specs)
	for _, c := range cases {
		t.Logf("cv02 case %s: %s", c.ID, c.Status)
	}
	held, released := barrier.counters()
	summary := cv02StandSummary{
		RunID: run, StartedUTC: started.Format(time.RFC3339),
		Dist: distEv, RequiredCases: cv02RequiredJourneyCases,
		Cases: cases, Stats: report.Stats,
	}
	summary.Barrier.Held, summary.Barrier.Released = held, released
	t.Logf("cv02 stand receipt: %s", cv02WriteStandSummary(t, artifacts, summary))
	if len(problems) > 0 {
		for _, p := range problems {
			t.Errorf("cv02: %s", p)
		}
		t.Fatalf("cv02: frozen journey case registry violated by %d problem(s) — see above and %s",
			len(problems), filepath.Join(artifacts, "playwright.out"))
	}
	if suiteErr != nil {
		t.Fatalf("cv02 browser acceptance suite FAILED (%v) — output tail:\n%s",
			suiteErr, cv02Tail(out, 6000))
	}
}

// cv02Tail returns the last n bytes of a byte slice for failure reporting.
func cv02Tail(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[len(b)-n:]
}
