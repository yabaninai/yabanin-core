//go:build integration

package handlers

// CV-03 org-presentation browser acceptance stand (MANDATORY quality command).
//
// Boots the REAL admin router (dbRBACRouter wiring) over the REAL disposable
// migrated Postgres (testdb.Postgres), seeds the presentation corpus — one
// CHF/Europe-Zurich org deliberately created FIRST so the created_at DESC
// directory listing pushes it beyond page 1 (54 fillers occupy page 1), one
// JPY/Asia-Tokyo org owned by an ordinary operator member (the least
// privileged standard role the W-CRED wallet read allows), one
// EUR/Europe-Berlin org owned by a READER (analytics explorer is that
// role's presentation-bearing surface; its wallet read stays denied), a
// root operator, and wallet rows whose updated_at instants are fixed AND
// DISTINCT PER OR so a wrong-row read cannot pass a different formatter —
// serves the REAL built dashboard artifact (web/dashboard/dist) at the SAME
// origin as the API, writes a fixture whose expected values are raw SQL
// read-backs plus API probes (the independent store oracle for the browser
// suite), and runs the REGISTERED npm command (test:orgpresentation) as a
// subprocess, enforcing its results.
//
// This stand deliberately EXTENDS the CV-02 stand family instead of
// duplicating it: it reuses the same artifact/fingerprint, static-site,
// Playwright-report parsing and git-state helpers, and adds its own barrier
// (parks exactly the root-only single-org GET /api/organizations/{id} — the
// directory listing, wallet reads and analytics queries pass through), its
// own fixture shape and its own FROZEN case registry. The eleven CV-02
// journey cases and their checks are untouched.
//
// MANDATORY semantics (same contract as CV-02): this command NEVER skips; a
// missing built dashboard fails immediately and a stale one fails the
// browser-build.sh verifier; the registered preflight is
// `make _quality-orgpresentation`. The run enforces the FROZEN registry
// below (every required case exactly once and passed; missing, skipped,
// duplicate or unknown IDs FAIL acceptance). The receipt
// (stand-summary.json) binds the verdict to the dist fingerprint + content
// hash, the barrier evidence and the repo state.
//
// Artifact freshness is verified on EVERY path, including overrides: an
// isolated negative control sets CV03_DIST_DIR to a build of the pre-fix
// source AND CV03_CONTROL_REPO to that source tree — the stand then runs
// the SAME browser-build.sh verifier from the control tree, so the served
// artifact is provably current for the source it claims (a stale override
// fails exactly like a stale default). The control run records
// mode=control plus the control repo/note in the receipt; the pre-fix
// build must FAIL AC-OP-SHARE (the remounted view receives a resolved null
// from the dead mount's marker and stays on USD/UTC defaults) while the
// member and reader cases still pass.
//
// The AC-OP-SHARE case uses the stand barrier: while armed, the single-org
// GET for the page-2 target org is parked mid-flight and forwarded only on
// release, so the dashboard route can be unmounted and remounted while the
// lookup is genuinely outstanding — the remounted view must share that one
// in-flight request (exactly one GET) and, once released, render the
// authoritative CHF/Europe-Zurich presentation instead of USD/UTC defaults.
// The barrier counts honest per-request outcomes (parked/flushed/cancelled/
// timed_out): a parked request that dies with its context or times out is
// NEVER counted as released, so the stand's post-run assertion — exactly
// one parked, flushed via release, zero cancelled, zero timed out — proves
// the single GET genuinely stayed outstanding until release and was served
// through it; the spec's post-release render assertion proves the
// remounted view awaited exactly that response. The /_cv03/barrier*
// control endpoints are stand test surface, not product API.
//
// MANDATORY command (repo root):
//
//	go test -tags integration -run TestCV03OrgPresentationBrowserAcceptance \
//	  ./services/admin/handlers/ -count=1 -timeout 15m
//
// Artifacts land in <repo>/artifacts/cv03-org-presentation/<run/>
// (CV03_ORG_PRESENTATION_OUT overrides the artifacts root). Docker must be
// reachable for testdb.Postgres.

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
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/require"
)

// cv03RequiredCases is the FROZEN org-presentation browser-acceptance case
// registry. Every listed case ID MUST appear in the Playwright results
// exactly once with a passed verdict; a missing, skipped, duplicate or
// unknown case FAILS the acceptance. Registry changes are deliberate
// acceptance-scope decisions, never silent.
var cv03RequiredCases = []string{
	// AC-OP-MEMBER: an ordinary operator member's wallet renders their own
	// org's authoritative JPY/Asia-Tokyo presentation from /api/me alone —
	// non-USD money form, Tokyo-shifted stamp, AND the exact seeded amount
	// (a wrong-row read cannot pass: every org's cents/stamp pair is
	// distinct) — while firing ZERO root-only /api/organizations requests.
	"AC-OP-MEMBER",
	// AC-OP-SHARE: root remounts the wallet route while the page-2 org GET
	// is parked mid-flight; the remounted view shares the one in-flight
	// request (barrier outcome counters prove exactly one genuinely-parked,
	// release-flushed GET with zero cancellations) and, after release,
	// renders the authoritative CHF/Europe-Zurich presentation.
	"AC-OP-SHARE",
	// AC-OP-READER: a READER (no budgets.manage — wallet stays denied 403)
	// opens the analytics explorer, the reader-authorized surface that
	// renders metric values in the org's presentation currency: their own
	// EUR/Europe-Berlin presentation applies (non-USD money form on the
	// cost total) with ZERO root-only /api/organizations directory calls,
	// and the wallet read is still denied.
	"AC-OP-READER",
}

// The seeded wallet instants are fixed calendar constants (not relative
// now) so the rendered date/time is byte-stable across runs, and DISTINCT
// PER ORG so no wrong-row read can pass another org's formatter: the
// (cents, stamp) pairs are unique and every stamp renders differently
// under UTC, Europe/Zurich and Asia/Tokyo. November sits in CET (UTC+1),
// so Europe/Zurich shifts stamps by one hour and Asia/Tokyo by nine.
const (
	cv03TargetStamp = "2026-11-21 12:34:56+00" // Zurich 13:34, Tokyo 21:34
	cv03MemberStamp = "2026-11-21 09:05:00+00" // Tokyo 18:05, Zurich 10:05
	cv03ReaderStamp = "2026-11-20 08:15:00+00" // Berlin 09:15 (denied, never rendered)

	cv03TargetCents = int64(123)  // "1.23 USD" under CHF/JPY, "$1.23" only if defaulted
	cv03MemberCents = int64(4567) // "45.67 USD" under JPY
	cv03ReaderCents = int64(789)  // seeded but DENIED to the reader (403)

	// Reader-org analytics corpus: two request_logs rows whose
	// cost_in_usd/cost_status columns the cost_usd metric sums
	// (analytics_query_sql.go filters cost_status IN priced/cache_hit/
	// legacy). 12.50 + 3.25 = 15.75 — "15.75 USD" under EUR, "$15.75"
	// only if the presentation defaulted to USD.
	cv03ReaderCostA = 12.50
	cv03ReaderCostB = 3.25
)

// cv03FillerOrgs is the number of filler orgs created AFTER the target so
// the created_at DESC page-1 listing (page_size 50) cannot contain it; the
// stand preflight asserts the exclusion before the browser runs.
const cv03FillerOrgs = 54

// cv03Barrier parks exactly the root-only single-org GET while armed. The
// directory listing (/api/organizations, no id segment) and the org-scoped
// wallet/analytics reads pass through untouched; the /_cv03/barrier*
// control endpoints are stand test surface, NOT product API.
//
// Every registered waiter records EXACTLY ONE final outcome, decided under
// the barrier mutex by whichever side observes first — Release (using a
// cancellation-aware context check) or the parking goroutine (using its
// wake reason when Release never decided it):
//
//   - `parked` counts registrations, atomically with the armed check — a
//     request racing a Release is either parked-under-arm or forwarded,
//     never lost between the two;
//   - `flushed` counts only waiters whose request context was STILL ALIVE
//     at the moment Release observed them (release-before-cancel);
//   - `cancelled` counts waiters whose context was already dead when
//     Release observed them (cancel-before-release, including the case
//     where the parking goroutine has not yet been scheduled to notice)
//     or that woke from their own context while undecided;
//   - `timedOut` counts waiters that left the park by the bounded safety
//     deadline while still undecided.
//
// A request that died is therefore NEVER reported as released, and a
// request released before it died is never re-counted as cancelled: the
// first recorded outcome is final, so delayed scheduling cannot turn one
// outcome into the other.
type cv03Barrier struct {
	mu        sync.Mutex
	orgPath   string
	armed     bool
	parked    int
	flushed   int
	cancelled int
	timedOut  int
	waiters   map[*cv03Parked]struct{}
	// holdLimit bounds one park (production: cv02BarrierHoldLimit; the
	// deterministic interleave test shortens it to exercise the timeout
	// path without waiting).
	holdLimit time.Duration
}

// cv03Parked is one registered parking of a request. outcome is 0 while
// undecided, then exactly one of 1 (flushed), 2 (cancelled), 3 (timed
// out) — set once, under the barrier mutex, never overwritten.
type cv03Parked struct {
	release chan struct{}
	ctx     context.Context
	outcome int
}

func cv03NewBarrier(orgID string) *cv03Barrier {
	return &cv03Barrier{
		orgPath:   "/api/organizations/" + orgID,
		waiters:   make(map[*cv03Parked]struct{}),
		holdLimit: cv02BarrierHoldLimit,
	}
}

// Handler returns the outermost stand handler: the /_cv03/barrier* control
// endpoints, the parked single-org GET while armed, everything else
// forwarded to the real mux untouched.
func (b *cv03Barrier) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_cv03/barrier":
			io.WriteString(w, b.stateJSON())
		case "/_cv03/barrier/arm":
			b.setArmed(true)
			w.WriteHeader(http.StatusNoContent)
		case "/_cv03/barrier/release":
			b.Release()
			w.WriteHeader(http.StatusNoContent)
		default:
			if r.Method == http.MethodGet && r.URL.Path == b.orgPath {
				b.park(w, r, next)
				return
			}
			next.ServeHTTP(w, r)
		}
	})
}

func (b *cv03Barrier) setArmed(v bool) {
	b.mu.Lock()
	b.armed = v
	b.mu.Unlock()
}

// park registers and parks one single-org GET until Release, the request
// dying with its context, or the bounded safety deadline — then forwards
// it to the real router, so it completes late exactly like a slow upstream.
// Registration (the armed check, the parked count and the waiter entry) is
// ONE atomic critical section: a Release racing the arrival either sees
// armed and flushes this waiter, or disarms first and this request is
// forwarded immediately — it can never park under a released barrier.
func (b *cv03Barrier) park(w http.ResponseWriter, r *http.Request, next http.Handler) {
	// ctx powers Release's cancellation-aware observation; outcome is
	// the single-final-outcome slot (see the struct comment).
	p := &cv03Parked{release: make(chan struct{}), ctx: r.Context()}
	b.mu.Lock()
	if !b.armed {
		b.mu.Unlock()
		next.ServeHTTP(w, r)
		return
	}
	b.parked++
	b.waiters[p] = struct{}{}
	b.mu.Unlock()

	timer := time.NewTimer(b.holdLimit)
	defer timer.Stop()
	select {
	case <-p.release:
	case <-p.ctx.Done():
	case <-timer.C:
	}
	// Record the final outcome exactly once. If Release already decided
	// this waiter (release-before-cancel — its context observation found
	// the request alive, or dead, and recorded it), that decision is
	// final and must not be recounted here. Reaching this branch with the
	// release channel closed and outcome unset is impossible by
	// construction: Release records the outcome under this mutex before
	// closing the channel. Waking by context or deadline with the outcome
	// still undecided means Release never flushed this waiter.
	b.mu.Lock()
	if p.outcome == 0 {
		delete(b.waiters, p)
		select {
		case <-p.ctx.Done():
			b.cancelled++
			p.outcome = 2
		default:
			b.timedOut++
			p.outcome = 3
		}
	}
	b.mu.Unlock()
	next.ServeHTTP(w, r)
}

// Release disarms the barrier and flushes every still-parked request,
// deciding each waiter's outcome with a cancellation-aware observation:
// a waiter whose request context is already dead was cancelled BEFORE
// this release (even if its parking goroutine has not yet been scheduled
// to notice) and is counted cancelled, never flushed; a waiter whose
// context is alive is genuinely flushed. Safe to call multiple times
// (control endpoint + test cleanup) and after server close.
func (b *cv03Barrier) Release() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.armed = false
	for p := range b.waiters {
		if p.ctx.Err() != nil {
			b.cancelled++
			p.outcome = 2
		} else {
			b.flushed++
			p.outcome = 1
		}
		close(p.release)
		delete(b.waiters, p)
	}
}

// counters snapshots the honest outcome counters for the run receipt and
// the post-run assertion.
func (b *cv03Barrier) counters() (parked, flushed, cancelled, timedOut int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.parked, b.flushed, b.cancelled, b.timedOut
}

func (b *cv03Barrier) stateJSON() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out, err := json.Marshal(struct {
		Armed     bool `json:"armed"`
		Parked    int  `json:"parked"`
		Flushed   int  `json:"flushed"`
		Cancelled int  `json:"cancelled"`
		TimedOut  int  `json:"timed_out"`
	}{b.armed, b.parked, b.flushed, b.cancelled, b.timedOut})
	if err != nil {
		return `{"armed":false}`
	}
	return string(out)
}

// cv03SessionCookie mints a session against the router's real secret for
// an arbitrary store-seeded identity (TP-02 revalidation resolves the user
// through the store). sweepSessionCookie hardcodes IsRoot=false; the root
// acceptance identity needs the flag set.
func cv03SessionCookie(t *testing.T, secret, userID string, isRoot bool) *http.Cookie {
	t.Helper()
	cookie, err := adminauth.CreateAdminSessionCookie(adminauth.AdminSession{
		UserID:    userID,
		Email:     userID + "@cv03.test",
		IsRoot:    isRoot,
		SessionID: "cv03-" + userID,
		ExpiresAt: time.Now().Add(time.Hour),
	}, secret)
	require.NoError(t, err, "cv03: CreateAdminSessionCookie(%s)", userID)
	return cookie
}

// cv03OrgOracle is the raw organizations/org_credits column set the
// browser suite asserts against — read back by direct SQL after seeding
// (never the store's own projection), plus the wallet cents/stamp as the
// API serves them.
type cv03OrgOracle struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Currency     string    `json:"currency"`
	Timezone     string    `json:"timezone"`
	BalanceCents int64     `json:"balance_cents"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type cv03Fixture struct {
	RunID         string `json:"run_id"`
	SessionCookie string `json:"session_cookie"`
	Users         struct {
		Root struct {
			Cookie string `json:"cookie"`
		} `json:"root"`
		Member struct {
			Cookie string `json:"cookie"`
		} `json:"member"`
		Reader struct {
			Cookie string `json:"cookie"`
		} `json:"reader"`
	} `json:"users"`
	// Target: the root-only page-2+ org (CHF/Europe-Zurich). Member: the
	// operator's own JPY/Asia-Tokyo org, resolved from /api/me alone.
	// Reader: the reader's own EUR/Europe-Berlin org (wallet denied).
	Target cv03OrgOracle `json:"target"`
	Member cv03OrgOracle `json:"member"`
	Reader cv03OrgOracle `json:"reader"`
	// Analytics is the reader case's independent expectation: the query
	// window and the exact cost_usd total the seeded request_logs rows
	// must sum to (15.75). The spec re-derives its expected strings from
	// these values with its own Intl formatting.
	Analytics struct {
		From         string  `json:"from"`
		To           string  `json:"to"`
		Metrics      string  `json:"metrics"`
		ExpectedCost float64 `json:"expected_cost"`
	} `json:"analytics"`
	Control struct {
		BarrierArm     string `json:"barrier_arm"`
		BarrierRelease string `json:"barrier_release"`
		BarrierState   string `json:"barrier_state"`
	} `json:"control"`
}

// cv03ReadOrgOracle reads the presentation + wallet columns back by direct
// SQL — the independent store oracle the browser suite asserts against.
func cv03ReadOrgOracle(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID string) cv03OrgOracle {
	t.Helper()
	var o cv03OrgOracle
	err := pool.QueryRow(ctx, `
		SELECT o.id::text, o.name, o.currency, o.timezone,
		       COALESCE(oc.balance_cents, 0), COALESCE(oc.updated_at, '2000-01-01'::timestamptz)
		FROM organizations o LEFT JOIN org_credits oc ON oc.org_id = o.id::text
		WHERE o.id::text = $1`, orgID).
		Scan(&o.ID, &o.Name, &o.Currency, &o.Timezone, &o.BalanceCents, &o.UpdatedAt)
	require.NoError(t, err, "cv03: oracle read for org %s", orgID)
	return o
}

// cv03CaseVerdicts applies the frozen CV-03 registry to the parsed results,
// reusing the CV-02 verdict primitives (ID shape, spec verdict). Problems
// are returned, not raised, so the receipt is written before failing.
func cv03CaseVerdicts(specs []cv02FlatSpec) (cases []cv02CaseResult, problems []string) {
	byID := make(map[string][]cv02FlatSpec)
	for _, fs := range specs {
		id := cv02CaseID(fs.Spec.Title)
		if id == "" {
			problems = append(problems, fmt.Sprintf("unnamed org-presentation case %q — every spec title must "+
				"start with its frozen AC-* case ID", fs.Spec.Title))
			continue
		}
		byID[id] = append(byID[id], fs)
	}
	for _, id := range cv03RequiredCases {
		got := byID[id]
		switch {
		case len(got) == 0:
			cases = append(cases, cv02CaseResult{ID: id, Status: "missing"})
			problems = append(problems, fmt.Sprintf("required org-presentation case %s is MISSING from the "+
				"results — the frozen registry (%d cases) requires every case to run and pass; a green run "+
				"with a dropped case is not acceptance", id, len(cv03RequiredCases)))
			continue
		case len(got) > 1:
			problems = append(problems, fmt.Sprintf("org-presentation case %s appears %d times — exactly one "+
				"spec per case ID is allowed", id, len(got)))
			continue
		}
		status := cv02SpecVerdict(got[0].Spec)
		cases = append(cases, cv02CaseResult{ID: id, Title: got[0].Spec.Title, Status: status})
		if status != "passed" {
			problems = append(problems, fmt.Sprintf("required org-presentation case %s did not pass (status %q, "+
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
		problems = append(problems, fmt.Sprintf("unknown org-presentation cases %v are not in the frozen registry — "+
			"extend the registry deliberately, never by silent addition", ids))
	}
	return cases, problems
}

// cv03RunPlaywright runs the REGISTERED npm command (test:orgpresentation)
// with the JSON reporter, saves raw output as evidence and returns the
// parsed report, the suite error and the raw output. Only broken reporter
// plumbing fails here; a failed suite still yields its report so the
// receipt can be written first.
func cv03RunPlaywright(t *testing.T, repoRoot, baseURL, fixturePath, artifacts string) (cv02PWReport, error, []byte) {
	t.Helper()
	runCtx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "npm", "run", "--silent", "test:orgpresentation", "--", "--reporter=json")
	cmd.Dir = filepath.Join(repoRoot, "web", "dashboard")
	cmd.Env = append(os.Environ(),
		"CV03_BASE_URL="+baseURL,
		"CV03_FIXTURE="+fixturePath,
		"CV03_ARTIFACTS="+artifacts,
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, os.WriteFile(filepath.Join(artifacts, "playwright.out"), out, 0o644))
	t.Logf("cv03 playwright run: %d bytes of output kept at %s/playwright.out", len(out), artifacts)
	var report cv02PWReport
	require.NoError(t, json.Unmarshal(cv02ExtractJSONObject(t, out), &report),
		"cv03: Playwright JSON report does not parse")
	return report, err, out
}

// cv03StandSummary is the run receipt: the verdict bound to the exact
// artifact served (and, in control mode, the control tree it was verified
// against), the case-by-case registry outcome, the suite stats, the
// barrier outcome evidence and the repo state.
type cv03StandSummary struct {
	RunID      string `json:"run_id"`
	StartedUTC string `json:"started_utc"`
	Mode       string `json:"mode"` // "acceptance" | "control"
	// ControlRepo/ControlNote are set in control mode (CV03_DIST_DIR
	// override): the source tree whose browser-build.sh verified the
	// served artifact and why the isolated run exists.
	ControlRepo   string           `json:"control_repo,omitempty"`
	ControlNote   string           `json:"control_note,omitempty"`
	GitHead       string           `json:"git_head,omitempty"`
	GitDirty      bool             `json:"git_dirty"`
	Dist          cv02DistEvidence `json:"dist"`
	RequiredCases []string         `json:"required_cases"`
	Cases         []cv02CaseResult `json:"cases"`
	Stats         cv02PWStats      `json:"stats"`
	// GlobalErrors counts the Playwright JSON reporter's top-level
	// "errors" array (teardown/global failures) — specs can be green
	// while the run itself is not, so the receipt carries it and both
	// the stand and the gate require zero.
	GlobalErrors int `json:"global_errors"`
	Barrier      struct {
		Parked    int `json:"parked"`
		Flushed   int `json:"flushed"`
		Cancelled int `json:"cancelled"`
		TimedOut  int `json:"timed_out"`
	} `json:"barrier"`
}

func cv03WriteStandSummary(t *testing.T, artifacts string, s cv03StandSummary) string {
	t.Helper()
	s.GitHead, s.GitDirty = cv02GitState(t)
	raw, err := json.MarshalIndent(s, "", "  ")
	require.NoError(t, err)
	path := filepath.Join(artifacts, "stand-summary.json")
	require.NoError(t, os.WriteFile(path, append(raw, '\n'), 0o644))
	return path
}

func TestCV03OrgPresentationBrowserAcceptance(t *testing.T) {
	started := time.Now().UTC()
	repoRoot := cv02RepoRoot(t)

	// Artifact contract — freshness is verified on EVERY path. Default:
	// the current tree's dist through the CV-02 fingerprint gate. Override
	// (isolated negative controls): the dist must BE the control tree's
	// dist and is verified by the SAME browser-build.sh running from that
	// tree, so a stale override fails exactly like a stale default; the
	// control run also requires an explicit note naming its purpose.
	mode, controlRepo, controlNote := "acceptance", "", ""
	dist := os.Getenv("CV03_DIST_DIR")
	if dist == "" {
		dist = filepath.Join(repoRoot, "web", "dashboard", "dist")
	} else {
		controlRepo, controlNote = os.Getenv("CV03_CONTROL_REPO"), os.Getenv("CV03_CONTROL_NOTE")
		require.NotEmpty(t, controlRepo,
			"cv03: CV03_DIST_DIR overrides require CV03_CONTROL_REPO — the control source tree whose "+
				"browser-build.sh must verify the served artifact (a stale or unverifiable override is a "+
				"failed run, never a quiet pass)")
		require.NotEmpty(t, controlNote,
			"cv03: CV03_DIST_DIR overrides require CV03_CONTROL_NOTE naming the control's purpose "+
				"(e.g. 'negative control: pre-fix c466995 remount marker')")
		abs, err := filepath.Abs(controlRepo)
		require.NoError(t, err, "cv03: CV03_CONTROL_REPO path")
		controlRepo = abs
		require.Equal(t, filepath.Join(controlRepo, "web", "dashboard", "dist"), dist,
			"cv03: CV03_DIST_DIR must be exactly <CV03_CONTROL_REPO>/web/dashboard/dist — the override "+
				"serves the control tree's own verified build")
		mode = "control"
	}
	// Verified through the tree the artifact claims: the current repo on
	// the default path, the control tree on an override.
	verifyRepo := repoRoot
	if mode == "control" {
		verifyRepo = controlRepo
	}
	distEv := cv02RequireDashboardArtifact(t, verifyRepo, dist)

	pool := testdb.Postgres(t)
	h, store := dbRBACRouter(t, pool)
	// The wallet reads are part of the contract under test: dbRBACRouter
	// wires a nil-pool credits store (sweep shape); replace it with the real
	// pool BEFORE mounting so /api/orgs/{id}/credits/* actually serve the
	// seeded rows.
	h.SetCreditStore(credits.NewStore(pool, nil), pool)
	// Console route shape, not the portal one (same /api/me precedence
	// CV-02 documents).
	h.SetPortal(PortalOptions{Enabled: false})
	router := h.SetupRouter()
	ctx := context.Background()
	run := fmt.Sprintf("%d", time.Now().UnixNano())

	// Seed order matters: the TARGET org is created FIRST so, under the
	// listing's created_at DESC default order, the cv03FillerOrgs newer
	// orgs occupy page 1 (page_size 50) and the target lands beyond it —
	// the page-2+ resolution path under test. The preflight below asserts
	// the exclusion instead of trusting the seed order.
	target, err := store.CreateOrganization(ctx, "CV03 Target CHF "+run, "cv03-target-"+run)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE organizations SET currency = 'CHF', timezone = 'Europe/Zurich' WHERE id::text = $1`, target.ID)
	require.NoError(t, err, "cv03: set target presentation")
	for i := 0; i < cv03FillerOrgs; i++ {
		_, err := store.CreateOrganization(ctx, fmt.Sprintf("CV03 Filler %02d %s", i, run), fmt.Sprintf("cv03-fill-%02d-%s", i, run))
		require.NoError(t, err, "cv03: filler org %d", i)
	}
	memberOrg, err := store.CreateOrganization(ctx, "CV03 Member JPY "+run, "cv03-member-"+run)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE organizations SET currency = 'JPY', timezone = 'Asia/Tokyo' WHERE id::text = $1`, memberOrg.ID)
	require.NoError(t, err, "cv03: set member presentation")
	readerOrg, err := store.CreateOrganization(ctx, "CV03 Reader EUR "+run, "cv03-reader-"+run)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE organizations SET currency = 'EUR', timezone = 'Europe/Berlin' WHERE id::text = $1`, readerOrg.ID)
	require.NoError(t, err, "cv03: set reader presentation")

	// Ordinary operator member: the least privileged standard role whose
	// budgets.manage permission admits the W-CRED wallet read — a non-root
	// identity whose presentation must come from /api/me alone. Reader:
	// analytics/requests/lineage reads only — the wallet MUST stay denied.
	// Root operator for the page-2+ resolution case.
	member, err := store.CreateAdminUser(ctx,
		fmt.Sprintf("cv03-member-%s@sweep.test", run), "cv03 member",
		"integration-hash-not-used-for-login", false)
	require.NoError(t, err)
	_, err = store.CreateOrgMembership(ctx, adminstore.OrgMembership{
		UserID: member.ID, OrgID: memberOrg.ID, Role: adminstore.RoleOperator,
	})
	require.NoError(t, err)
	reader, err := store.CreateAdminUser(ctx,
		fmt.Sprintf("cv03-reader-%s@sweep.test", run), "cv03 reader",
		"integration-hash-not-used-for-login", false)
	require.NoError(t, err)
	_, err = store.CreateOrgMembership(ctx, adminstore.OrgMembership{
		UserID: reader.ID, OrgID: readerOrg.ID, Role: adminstore.RoleReader,
	})
	require.NoError(t, err)
	root, err := store.CreateAdminUser(ctx,
		fmt.Sprintf("cv03-root-%s@sweep.test", run), "cv03 root",
		"integration-hash-not-used-for-login", true)
	require.NoError(t, err)
	cookieMember := cv03SessionCookie(t, "test-session-key", member.ID, false)
	cookieRoot := cv03SessionCookie(t, "test-session-key", root.ID, true)
	cookieReader := cv03SessionCookie(t, "test-session-key", reader.ID, false)

	// Wallet rows: fixed DISTINCT balances and stamps per org (plus one
	// top-up transaction each so the history surface is real, though the
	// frozen assertions pin the wallet stat). A wrong-row read fails on
	// BOTH the amount and the rendered time — no shared value can pass a
	// different formatter. The reader org's row exists but stays DENIED.
	seedWallet := func(orgID string, cents int64, stamp string) {
		_, err := pool.Exec(ctx, `
			INSERT INTO org_credits (org_id, balance_cents, updated_at)
			VALUES ($1, $2, $3::timestamptz)
			ON CONFLICT (org_id) DO UPDATE SET balance_cents = $2, updated_at = $3::timestamptz`, orgID, cents, stamp)
		require.NoError(t, err, "cv03: wallet seed for %s", orgID)
		_, err = pool.Exec(ctx, `
			INSERT INTO credit_transactions (org_id, amount_cents, balance_after, type, created_at)
			VALUES ($1, $2, $2, 'topup', $3::timestamptz)`, orgID, cents, stamp)
		require.NoError(t, err, "cv03: wallet txn seed for %s", orgID)
	}
	seedWallet(target.ID, cv03TargetCents, cv03TargetStamp)
	seedWallet(memberOrg.ID, cv03MemberCents, cv03MemberStamp)
	seedWallet(readerOrg.ID, cv03ReaderCents, cv03ReaderStamp)

	// Reader analytics corpus: two backdated request_logs rows carrying
	// stored cost columns the cost_usd metric sums (the reader-authorized
	// analytics explorer's money surface). Inserted through the CV-02
	// helper (NOT NULL shape + window-safe backdating), then priced by
	// direct column writes.
	rdA := fmt.Sprintf("cv03-rd-a-%s", run)
	rdB := fmt.Sprintf("cv03-rd-b-%s", run)
	cv02InsertRow(t, ctx, pool, readerOrg.ID, rdA, cv02Seed{
		ModelRequested: "cv03-reader-a", ModelUsed: "cv03-reader-a",
		StatusCode: 200, DurationMs: 120, TokensIn: 10, TokensOut: 5,
		CreatedAgo: 2 * time.Hour,
	})
	cv02InsertRow(t, ctx, pool, readerOrg.ID, rdB, cv02Seed{
		ModelRequested: "cv03-reader-b", ModelUsed: "cv03-reader-b",
		StatusCode: 200, DurationMs: 130, TokensIn: 20, TokensOut: 8,
		CreatedAgo: 2 * time.Hour,
	})
	for _, row := range []struct {
		id   string
		cost float64
	}{{rdA, cv03ReaderCostA}, {rdB, cv03ReaderCostB}} {
		_, err = pool.Exec(ctx, `UPDATE request_logs SET cost_in_usd = $2, cost_status = 'legacy' WHERE request_id = $1`, row.id, row.cost)
		require.NoError(t, err, "cv03: reader analytics cost seed for %s", row.id)
	}

	// Same origin for the artifact and the API (cookie scope + same-origin
	// fetches are part of the contract under test); the barrier wraps the
	// whole mux as the outermost handler.
	barrier := cv03NewBarrier(target.ID)
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
	// LIFO: registered after srv.Close, so a parked request is flushed
	// BEFORE the server closes (and never outlives the test).
	t.Cleanup(barrier.Release)

	getJSON := func(path string, cookie *http.Cookie) (int, []byte) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
		require.NoError(t, err)
		req.AddCookie(cookie)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, body
	}

	// Preflight: all three minted sessions must authenticate against the
	// served origin with the SAME request shape the browser sends.
	for _, who := range []struct {
		name   string
		cookie *http.Cookie
	}{{"member", cookieMember}, {"root", cookieRoot}, {"reader", cookieReader}} {
		code, body := getJSON("/api/version", who.cookie)
		require.Equal(t, http.StatusOK, code,
			"cv03 preflight %s: minted session must authenticate /api/version (body: %s)", who.name, cv02Tail(body, 300))
	}

	// Preflight oracle — the page-2+ premise and the authoritative values,
	// asserted through the real API before the browser runs:
	//   * the directory page 1 (what OrgSelect lists) must NOT contain the
	//     target, and the org count must exceed one page;
	//   * the supported single-org GET must return the target's stored
	//     CHF/Europe-Zurich;
	//   * the member's /api/me must carry their own org's JPY/Asia-Tokyo;
	//   * both wallet reads must serve the DISTINCT seeded cents AND
	//     stamps (a wrong-row read fails either check);
	//   * the reader's wallet must be DENIED (row exists; denial is
	//     authorization, not absence) and their analytics query must sum
	//     the seeded costs.
	code, body := getJSON("/api/organizations?page=1", cookieRoot)
	require.Equal(t, http.StatusOK, code, "cv03 preflight: root directory listing (body: %s)", cv02Tail(body, 300))
	var listing struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Pagination struct {
			Total int64 `json:"total"`
		} `json:"pagination"`
	}
	require.NoError(t, json.Unmarshal(body, &listing), "cv03 preflight: listing JSON")
	for _, o := range listing.Data {
		require.NotEqual(t, target.ID, o.ID,
			"cv03 preflight: the target org must sit beyond directory page 1 (seed order broken)")
	}
	require.GreaterOrEqual(t, listing.Pagination.Total, int64(51),
		"cv03 preflight: expected 51+ orgs so the target is genuinely page 2+")

	code, body = getJSON("/api/organizations/"+target.ID, cookieRoot)
	require.Equal(t, http.StatusOK, code, "cv03 preflight: single-org GET (body: %s)", cv02Tail(body, 300))
	var targetGet struct {
		Currency string `json:"currency"`
		Timezone string `json:"timezone"`
	}
	require.NoError(t, json.Unmarshal(body, &targetGet), "cv03 preflight: single-org JSON")
	require.Equal(t, "CHF", targetGet.Currency, "cv03 preflight: target currency must be CHF")
	require.Equal(t, "Europe/Zurich", targetGet.Timezone, "cv03 preflight: target timezone must be Europe/Zurich")

	code, body = getJSON("/api/me", cookieMember)
	require.Equal(t, http.StatusOK, code, "cv03 preflight: member /api/me (body: %s)", cv02Tail(body, 300))
	cv03RequireMeOrg(t, body, memberOrg.ID, "JPY", "Asia/Tokyo")

	code, body = getJSON("/api/me", cookieReader)
	require.Equal(t, http.StatusOK, code, "cv03 preflight: reader /api/me (body: %s)", cv02Tail(body, 300))
	cv03RequireMeOrg(t, body, readerOrg.ID, "EUR", "Europe/Berlin")

	walletPreflight := func(name, orgID string, cents int64, stamp string, cookie *http.Cookie) {
		code, body := getJSON("/api/orgs/"+orgID+"/credits/balance", cookie)
		require.Equal(t, http.StatusOK, code, "cv03 preflight: %s wallet balance (body: %s)", name, cv02Tail(body, 300))
		var bal struct {
			BalanceCents int64     `json:"balance_cents"`
			UpdatedAt    time.Time `json:"updated_at"`
		}
		require.NoError(t, json.Unmarshal(body, &bal), "cv03 preflight: %s balance JSON", name)
		require.Equal(t, cents, bal.BalanceCents,
			"cv03 preflight: %s wallet must serve the DISTINCT seeded cents (wrong row?)", name)
		want, err := time.Parse(time.RFC3339, stamp)
		require.NoError(t, err, "cv03 preflight: %s stamp parse", name)
		require.WithinDuration(t, want, bal.UpdatedAt, time.Second,
			"cv03 preflight: %s wallet must serve the DISTINCT seeded stamp (wrong row?)", name)
	}
	walletPreflight("target", target.ID, cv03TargetCents, cv03TargetStamp, cookieRoot)
	walletPreflight("member", memberOrg.ID, cv03MemberCents, cv03MemberStamp, cookieMember)

	code, body = getJSON("/api/orgs/"+readerOrg.ID+"/credits/balance", cookieReader)
	require.Equal(t, http.StatusForbidden, code,
		"cv03 preflight: reader wallet read must be DENIED 403 even though the row exists (body: %s)", cv02Tail(body, 300))

	analyticsFrom := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	analyticsTo := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	code, body = getJSON("/api/analytics/query?org_id="+readerOrg.ID+
		"&from="+analyticsFrom+"&to="+analyticsTo+
		"&metrics=cost_usd&granularity=none&top=20", cookieReader)
	require.Equal(t, http.StatusOK, code, "cv03 preflight: reader analytics query (body: %s)", cv02Tail(body, 300))
	var analyticsRes struct {
		Totals map[string]float64 `json:"totals"`
	}
	require.NoError(t, json.Unmarshal(body, &analyticsRes), "cv03 preflight: analytics JSON")
	require.InDeltaMapValues(t, map[string]float64{"cost_usd": cv03ReaderCostA + cv03ReaderCostB}, analyticsRes.Totals, 0.001,
		"cv03 preflight: reader analytics cost_usd must sum the seeded rows exactly")

	// Fixture: the independent oracle (raw SQL read-backs + API-verified
	// expectations) the browser suite asserts against.
	var fixture cv03Fixture
	fixture.RunID = run
	fixture.SessionCookie = cookieRoot.Name
	fixture.Users.Root.Cookie = cookieRoot.Value
	fixture.Users.Member.Cookie = cookieMember.Value
	fixture.Users.Reader.Cookie = cookieReader.Value
	fixture.Target = cv03ReadOrgOracle(t, ctx, pool, target.ID)
	fixture.Member = cv03ReadOrgOracle(t, ctx, pool, memberOrg.ID)
	fixture.Reader = cv03ReadOrgOracle(t, ctx, pool, readerOrg.ID)
	fixture.Analytics.From = analyticsFrom
	fixture.Analytics.To = analyticsTo
	fixture.Analytics.Metrics = "cost_usd"
	fixture.Analytics.ExpectedCost = cv03ReaderCostA + cv03ReaderCostB
	fixture.Control.BarrierArm = "/_cv03/barrier/arm"
	fixture.Control.BarrierRelease = "/_cv03/barrier/release"
	fixture.Control.BarrierState = "/_cv03/barrier"
	fixtureRaw, err := json.MarshalIndent(fixture, "", "  ")
	require.NoError(t, err, "cv03: fixture marshal")

	artifactsRoot := os.Getenv("CV03_ORG_PRESENTATION_OUT")
	if artifactsRoot == "" {
		artifactsRoot = filepath.Join(repoRoot, "artifacts", "cv03-org-presentation")
	}
	artifacts := filepath.Join(artifactsRoot, run)
	require.NoError(t, os.MkdirAll(artifacts, 0o755), "cv03: artifacts dir")
	// The fixture carries LIVE session cookie values: it lives in a
	// private (0600) file inside the test's own TempDir — never under the
	// shared artifacts root — and is removed with the run. CI artifacts
	// keep only the SANITIZED expected effects (same oracle values, cookie
	// values stripped).
	fixtureDir := t.TempDir()
	fixturePath := filepath.Join(fixtureDir, "fixture.json")
	require.NoError(t, os.WriteFile(fixturePath, append(fixtureRaw, '\n'), 0o600),
		"cv03: private fixture write")
	sanitized := fixture
	sanitized.Users.Root.Cookie = ""
	sanitized.Users.Member.Cookie = ""
	sanitized.Users.Reader.Cookie = ""
	sanitizedRaw, err := json.MarshalIndent(sanitized, "", "  ")
	require.NoError(t, err, "cv03: sanitized effects marshal")
	require.NoError(t, os.WriteFile(filepath.Join(artifacts, "expected-effects.json"),
		append(sanitizedRaw, '\n'), 0o644), "cv03: sanitized expected-effects write")
	t.Logf("cv03: fixture (private, sanitized copy in artifacts/expected-effects.json) for base %s", srv.URL)

	report, pwErr, _ := cv03RunPlaywright(t, repoRoot, srv.URL, fixturePath, artifacts)
	specs := cv02FlattenSpecs(report.Suites, "", nil)
	cases, problems := cv03CaseVerdicts(specs)

	parked, flushed, cancelled, timedOut := barrier.counters()
	summary := cv03StandSummary{
		RunID: run, StartedUTC: started.Format(time.RFC3339),
		Mode: mode, ControlRepo: controlRepo, ControlNote: controlNote,
		Dist: distEv, RequiredCases: cv03RequiredCases, Cases: cases,
		Stats: report.Stats, GlobalErrors: len(report.Errors),
	}
	summary.Barrier.Parked = parked
	summary.Barrier.Flushed = flushed
	summary.Barrier.Cancelled = cancelled
	summary.Barrier.TimedOut = timedOut
	// The receipt is written FIRST, unconditionally: pass or fail, the
	// evidence of what ran exists. Only then is the run judged.
	receipt := cv03WriteStandSummary(t, artifacts, summary)

	// Post-run barrier contract: exactly one GET was parked (the page-2
	// target lookup), it stayed genuinely outstanding — never cancelled
	// by an unmount, never timed out — and was flushed by the explicit
	// release. Anything else means the race scenario did not happen as
	// designed, and the run is not evidence.
	require.Equal(t, 1, parked, "cv03: exactly one single-org GET must be parked (got %d)", parked)
	require.Equal(t, 1, flushed, "cv03: the parked GET must be flushed by release (got %d flushed)", flushed)
	require.Zero(t, cancelled, "cv03: the parked GET must not be cancelled by the remount (got %d cancelled)", cancelled)
	require.Zero(t, timedOut, "cv03: the parked GET must not hit the hold limit (got %d timed out)", timedOut)

	// Green named specs are NOT sufficient: the Playwright COMMAND must
	// have exited zero (exit code, JSON parse) and its GLOBAL state must
	// be clean — exactly the frozen case count expected (a shrunk or
	// grown suite is not this acceptance), zero flaky (a retried spec is
	// not a clean pass), no unexpected/skipped specs, no top-level
	// errors array (teardown/global failures). These are hard
	// requirements after the receipt, so a failing run still leaves its
	// evidence behind.
	require.NoError(t, pwErr,
		"cv03: the playwright command itself must succeed (exit status/JSON — details in %s/playwright.out)", artifacts)
	require.Equal(t, len(cv03RequiredCases), report.Stats.Expected,
		"cv03: playwright expected exactly %d specs (got %d) — suite drift", len(cv03RequiredCases), report.Stats.Expected)
	require.Zero(t, report.Stats.Flaky, "cv03: playwright reported %d flaky specs — a retried pass is not a clean pass", report.Stats.Flaky)
	require.Zero(t, report.Stats.Unexpected, "cv03: playwright reported %d unexpected results", report.Stats.Unexpected)
	require.Zero(t, report.Stats.Skipped, "cv03: playwright reported %d skipped specs", report.Stats.Skipped)
	require.Empty(t, report.Errors,
		"cv03: playwright reported %d global/teardown errors — specs may be green while the run is not", len(report.Errors))

	for _, p := range problems {
		t.Errorf("cv03: %s", p)
	}
	if len(problems) > 0 {
		t.Fatalf("cv03 org-presentation browser acceptance FAILED — see %s (receipt %s)", artifacts, receipt)
	}
	t.Logf("cv03 org-presentation browser acceptance PASSED — receipt %s", receipt)
}

func cv03RequireMeOrg(t *testing.T, body []byte, orgID, currency, timezone string) {
	t.Helper()
	var me struct {
		Organizations []struct {
			ID       string `json:"id"`
			Currency string `json:"currency"`
			Timezone string `json:"timezone"`
		} `json:"organizations"`
	}
	require.NoError(t, json.Unmarshal(body, &me))
	require.Len(t, me.Organizations, 1, "cv03: /api/me memberships for %s", orgID)
	org := me.Organizations[0]
	require.Equal(t, orgID, org.ID)
	require.Equal(t, currency, org.Currency)
	require.Equal(t, timezone, org.Timezone)
}
