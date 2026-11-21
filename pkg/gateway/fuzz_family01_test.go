// GW-COV-FAM01 behavioral fuzz family.
//
// Two halves in ONE fuzz target:
//
//   - Registry replay: the eleven frozen one-byte seeds 0x01..0x0b select
//     ADMIN-01..04, ADMIT-01..04, HOP-01..03. The CI fuzz-seed gate replays
//     exactly the seed corpus, so the expensive stands (testdb Postgres)
//     live only here, in fixed seeds, gated on Docker.
//
//     ADMIN-01..04  pkg/gateway/admin_create_user.go  (CLI happy/dup, flag+env
//     password arms, password-file arms, connectDB parse/ping)
//     ADMIT-01..04  pkg/gateway/admission.go          (resolution outage,
//     unknown/reject+event, fallback resolve, task/workload tag
//     validation, whitelist, team/agent budgets, workload cap,
//     token budget, fair shed, dead-context silence)
//     HOP-01..03    pkg/gateway/agent_hop_budget.go   (hop guards, settle
//     oracles, §5 admission matrix off/shadow/enforce)
//
//   - Generated contract: every other payload — the empty one included,
//     a real boundary whose expected behavior the ADMIN arm computes
//     independently (the empty bootstrap password must be refused) —
//     drives fam01Generated: three hermetic varying-input oracles that
//     derive their input purely from the payload, decide the expected
//     behavior independently of the implementation, and pin it with
//     literal expectations (see fam01Generated). The retained non-seed
//     seed "custard-model-42" keeps that half green under plain seed
//     replay.
//
// Generated-oracle mutation controls (each isolated mutant must fail its
// arm): M1 readAdminPassword drops its line-ending trim — ADMIN arm fails
// on trailing newlines; M2 the invalid-model event carries anything but the
// exact requested name — ADMIT arm fails; M3 the hop request body stops
// echoing the resolved target model — HOP arm fails.
//
// Structural caps reported to the record: the os.Exit arm of
// AddAdminCreateUserCommand (MarkFlagRequired failure) and the puddle
// MaxSize<1 arm of connectDB are unreachable in-process by design.
//
// Shared-fuzz-t contract: ONE *testing.T serves every case, so no helper
// here may register per-case t.Cleanup for state that later cases depend
// on (the reused untagged helpers that do — presetWorkloadLedger,
// newJudgeHopClient — only accumulate servers/ledger restores that are
// inert for later cases). Ledger and loop-budget state is released
// explicitly at the end of each arm that mutates it, and the generated
// arms own all of their state per call (local loop budget, local event
// observer, throwaway upstream server closed before returning), so a -fuzz
// campaign bounded by the installed 300s package/kind budget cannot leak
// into later iterations. No selector or gate policy is changed here.
package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/config"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/labels"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/reireirei/yabanin/pkg/pipeline/llmjudge"
	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/requestid"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/router"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// FuzzGatewayFamily01 dispatches the eleven frozen one-byte registry seeds
// 0x01..0x0b (ADMIN-01..04, ADMIT-01..04, HOP-01..03 in order) and routes
// every other payload — including the empty one — into the generated
// contract fam01Generated. The empty input is not skipped: the ADMIN arm
// independently expects the empty bootstrap password to be refused, and the
// ADMIT/HOP arms fold it to their constant fallback name. The retained seed
// "custard-model-42" is a non-seed accepted input: it proves the generated
// branch executes (and can fail) even under the CI fuzz-seed gate, which
// replays exactly the seed corpus.
var fam01Registry = map[byte]func(*testing.T){
	1: fam01Admin01, 2: fam01Admin02, 3: fam01Admin03, 4: fam01Admin04,
	5: fam01Admit01, 6: fam01Admit02, 7: fam01Admit03, 8: fam01Admit04,
	9: fam01Hop01, 10: fam01Hop02, 11: fam01Hop03,
}

func FuzzGatewayFamily01(f *testing.F) {
	for i := byte(1); i <= 11; i++ {
		f.Add([]byte{i})
	}
	f.Add([]byte("custard-model-42"))
	f.Add([]byte("custard-model-42\n"))
	f.Fuzz(func(t *testing.T, seed []byte) {
		if len(seed) == 1 {
			if run, ok := fam01Registry[seed[0]]; ok {
				run(t)
				return
			}
		}
		fam01Generated(t, seed)
	})
}

// --- shared fixtures -------------------------------------------------

// fam01CaptureEvents observes the sanitized event stream; the getter
// snapshots the events seen so far, restore re-enables the previous
// observer. Event emission is synchronous, so no locking is needed.
func fam01CaptureEvents(t *testing.T) (getter func() []*eventpub.Event, restore func()) {
	t.Helper()
	var got []*eventpub.Event
	rest := observeEvent(func(e *eventpub.Event) { got = append(got, e) })
	return func() []*eventpub.Event { return got }, rest
}

func fam01FindEvent(evs []*eventpub.Event, typ string) *eventpub.Event {
	for _, e := range evs {
		if e != nil && e.EventType == typ {
			return e
		}
	}
	return nil
}

// fam01CLI builds a fresh cobra root with the admin command registered and
// both output streams captured. A fresh root per arm keeps flag state and
// MarkFlagRequired registration independent on the shared fuzz t.
func fam01CLI(t *testing.T) (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var out, errBuf bytes.Buffer
	root := &cobra.Command{Use: "yabanin", SilenceUsage: true, SilenceErrors: true}
	root.SetOut(&out)
	root.SetErr(&errBuf)
	AddAdminCreateUserCommand(root)
	return root, &out, &errBuf
}

type fam01ErrReader struct{ msg string }

func (r fam01ErrReader) Read([]byte) (int, error) { return 0, errors.New(r.msg) }

// fam01ErrResolver models a registry outage: every checked lookup fails.
type fam01ErrResolver struct{}

func (fam01ErrResolver) Resolve(_ context.Context, _ string) resolver.ModelInfo {
	return resolver.ModelInfo{}
}

func (fam01ErrResolver) ResolveChecked(_ context.Context, _ string) (resolver.ModelInfo, error) {
	return resolver.ModelInfo{}, errors.New("registry unavailable")
}

// fam01SelectiveResolver answers only its known entries; unknown names
// resolve to the miss shape WITHOUT an error (the unknown-model path, not
// the 503 outage path). A zero miss keeps the legacy name-only shape;
// setting miss.Fallback marks the miss as a registry-declared unknown,
// which is what drives the reject/fallback policy arms of admissionCore.
type fam01SelectiveResolver struct {
	known map[string]resolver.ModelInfo
	miss  resolver.ModelInfo
}

func (r fam01SelectiveResolver) Resolve(_ context.Context, name string) resolver.ModelInfo {
	if info, ok := r.known[name]; ok {
		return info
	}
	return r.miss
}

func (r fam01SelectiveResolver) ResolveChecked(ctx context.Context, name string) (resolver.ModelInfo, error) {
	return r.Resolve(ctx, name), nil
}

// fam01CoreCtx drives admissionCore directly (no route stack, so the
// ingress auth middleware cannot strip the identity headers these arms
// stamp by hand) — for arms that need a hand-built context (principal,
// dead ctx) or want the resolved core result without upstream traffic.
func fam01CoreCtx(t *testing.T, gw *gateway, ctx context.Context, in admissionCoreInput, hdr map[string]string) (*httptest.ResponseRecorder, admissionCore, bool) {
	t.Helper()
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/embeddings", strings.NewReader(`{}`))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	core, ok := gw.admissionCore(rec, req, gw.log, in)
	return rec, core, ok
}

func fam01RequireDocker(t *testing.T) {
	t.Helper()
	if !fuzzDockerUp() {
		t.Skip("Docker is not reachable: real-storage seeds step aside (fuzzDockerUp)")
	}
}

// fam01SeedOrg inserts an organization with the given §9 mode and,
// optionally, its wallet row (the org_credits capacity source). Skipping
// the wallet exercises the no-capacity-source denial.
func fam01SeedOrg(t *testing.T, pool *pgxpool.Pool, mode string, credits bool, balanceCents int64) string {
	t.Helper()
	org := uuid.NewString()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO organizations (id, name, slug, reservations_mode) VALUES ($1, $2, $3, $4)`,
		org, "fam01-"+org[:8], "fam01-"+org[:8], mode)
	require.NoError(t, err)
	if credits {
		_, err = pool.Exec(context.Background(),
			`INSERT INTO org_credits (org_id, balance_cents, remainder_micro_usd, reserved_micro_usd)
			 VALUES ($1, $2, 0, 0)`,
			org, balanceCents)
		require.NoError(t, err)
	}
	return org
}

// fam01Pricer prices every (provider, model) at 2 USD per 1M tokens;
// fam01EmptyPricer prices nothing (the unpriced-model denial).
type fam01Pricer struct{}

func (fam01Pricer) Lookup(_, _ string) (pricing.Price, bool) {
	return pricing.Price{InputPerM: 2, OutputPerM: 2}, true
}

type fam01EmptyPricer struct{}

func (fam01EmptyPricer) Lookup(_, _ string) (pricing.Price, bool) {
	return pricing.Price{}, false
}

// fam01AdmissionFor wires the §5 controller over the live pool with the
// deployment gate pinned at enforce: the ORGANIZATION row decides the
// effective mode (EffectiveMode clamps org intent to the global ceiling,
// so off/shadow/enforce orgs under a global enforce all behave as seeded).
func fam01AdmissionFor(pool *pgxpool.Pool, priced bool) *budget.Admission {
	var base pricing.Pricer = fam01Pricer{}
	if !priced {
		base = fam01EmptyPricer{}
	}
	store := budget.NewReservationStoreWithConfig(pool, nil, budget.ReservationConfig{
		DefaultGraceFloorCents: 0, // free capacity == balance
	})
	rates := budget.ScopedRateSource{
		Base:   budget.BaseRateSource{Pricer: base},
		Resale: budget.ResaleRateSource{Markup: pricing.NewMarkupPricer(pool, base, nil)},
	}
	return budget.NewAdmission(store, rates, nil, "fam01-replica-"+uuid.NewString()[:8],
		budget.ModeEnforce, reservationOrgLoader(pool), budget.DefaultAdmissionConfig())
}

// --- ADMIN-01: CLI happy path, duplicate refusal, stdin arm (Docker) ---

func fam01Admin01(t *testing.T) {
	t.Helper()
	fam01RequireDocker(t)
	pool := testdb.Postgres(t)
	store := adminstore.New(pool, slog.New(slog.DiscardHandler), nil)
	t.Setenv("YABANIN_PG_URI", pool.Config().ConnString())
	t.Setenv("YABANIN_GATEWAY_PG_URI", "")

	pw := rand.Text()
	rootEmail := "root-" + uuid.NewString()[:8] + "@fam01.example"
	opEmail := "op-" + uuid.NewString()[:8] + "@fam01.example"
	pwFile := filepath.Join(t.TempDir(), "pw")
	require.NoError(t, os.WriteFile(pwFile, []byte(pw), 0o600))
	t.Setenv("YABANIN_ADMIN_PASSWORD_FILE", pwFile)

	// The success output goes to process stdout (fmt.Printf), so the
	// oracle is the DATABASE row, not the captured cobra writer.
	root, _, _ := fam01CLI(t)
	root.SetArgs([]string{"admin", "create-user", "--email", rootEmail,
		"--display-name", "Fam01 Root", "--root"})
	require.NoError(t, root.Execute())

	u, err := store.GetAdminUserByEmailWithHash(context.Background(), rootEmail)
	require.NoError(t, err)
	require.NotEmpty(t, u.ID)
	require.Equal(t, "Fam01 Root", u.DisplayName)
	require.True(t, u.IsRoot)
	require.True(t, u.Active)
	require.NoError(t, adminauth.VerifyPassword(pw, u.PasswordHash), "the stored hash must verify the file password")
	require.Error(t, adminauth.VerifyPassword("wrong-password", u.PasswordHash), "a wrong password must not verify")

	// Duplicate bootstrap is refused.
	root2, _, _ := fam01CLI(t)
	root2.SetArgs([]string{"admin", "create-user", "--email", rootEmail})
	err = root2.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")

	// --password-stdin arm: the trimmed stdin secret becomes the hash.
	root3, _, _ := fam01CLI(t)
	root3.SetArgs([]string{"admin", "create-user", "--email", opEmail, "--password-stdin"})
	root3.SetIn(strings.NewReader("fam01-stdin-pw\n"))
	require.NoError(t, root3.Execute())

	u2, err := store.GetAdminUserByEmailWithHash(context.Background(), opEmail)
	require.NoError(t, err)
	require.False(t, u2.IsRoot, "without --root the operator is a normal admin")
	require.NoError(t, adminauth.VerifyPassword("fam01-stdin-pw", u2.PasswordHash))

	longEmail := "long-" + uuid.NewString()[:8] + "@fam01.example"
	root4, _, _ := fam01CLI(t)
	root4.SetArgs([]string{"admin", "create-user", "--email", longEmail, "--password-stdin"})
	root4.SetIn(strings.NewReader(strings.Repeat("p", 73) + "\n"))
	err = root4.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "hash password")
	var count int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM admin_users WHERE email = $1`, longEmail).Scan(&count))
	require.Zero(t, count, "a rejected password must not create an admin row")

	_, err = pool.Exec(context.Background(), `CREATE OR REPLACE FUNCTION fam01_reject_admin_insert()
		RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'fam01 forced insert failure'; END; $$ LANGUAGE plpgsql`)
	require.NoError(t, err)
	_, err = pool.Exec(context.Background(), `CREATE TRIGGER fam01_reject_insert
		BEFORE INSERT ON admin_users FOR EACH ROW EXECUTE FUNCTION fam01_reject_admin_insert()`)
	require.NoError(t, err)
	defer func() {
		_, _ = pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS fam01_reject_insert ON admin_users`)
		_, _ = pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS fam01_reject_admin_insert()`)
	}()
	rejectEmail := "reject-" + uuid.NewString()[:8] + "@fam01.example"
	root5, _, _ := fam01CLI(t)
	root5.SetArgs([]string{"admin", "create-user", "--email", rejectEmail})
	err = root5.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "create admin user")
	require.Contains(t, err.Error(), "fam01 forced insert failure")
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM admin_users WHERE email = $1`, rejectEmail).Scan(&count))
	require.Zero(t, count, "a failed INSERT must not persist an admin row")
	_, err = pool.Exec(context.Background(), `DROP TRIGGER fam01_reject_insert ON admin_users`)
	require.NoError(t, err)
	_, err = pool.Exec(context.Background(), `DROP FUNCTION fam01_reject_admin_insert()`)
	require.NoError(t, err)
}

// --- ADMIN-02: flag/env password and PG-env arms (no Docker) ----------

func fam01Admin02(t *testing.T) {
	t.Helper()
	// Missing --email: cobra's required-flag guard fires before RunE.
	root, _, _ := fam01CLI(t)
	root.SetArgs([]string{"admin", "create-user"})
	err := root.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), `required flag(s) "email" not set`)

	direct, _, _ := fam01CLI(t)
	command, _, err := direct.Find([]string{"admin", "create-user"})
	require.NoError(t, err)
	require.EqualError(t, command.RunE(command, nil), "--email is required")

	// Email without any password source.
	t.Setenv("YABANIN_ADMIN_PASSWORD_FILE", "")
	root2, _, _ := fam01CLI(t)
	root2.SetArgs([]string{"admin", "create-user", "--email", "a@fam01.example"})
	err = root2.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "password must be supplied with --password-stdin or YABANIN_ADMIN_PASSWORD_FILE")

	// Failing stdin reader.
	root3, _, _ := fam01CLI(t)
	root3.SetArgs([]string{"admin", "create-user", "--email", "a@fam01.example", "--password-stdin"})
	root3.SetIn(fam01ErrReader{"disk failure"})
	err = root3.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "read password from stdin")

	// Empty stdin password.
	root4, _, _ := fam01CLI(t)
	root4.SetArgs([]string{"admin", "create-user", "--email", "a@fam01.example", "--password-stdin"})
	root4.SetIn(strings.NewReader("\n"))
	err = root4.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "password from --password-stdin is empty")

	// Password ok but no PG URI configured.
	t.Setenv("YABANIN_PG_URI", "")
	t.Setenv("YABANIN_GATEWAY_PG_URI", "")
	root5, _, _ := fam01CLI(t)
	root5.SetArgs([]string{"admin", "create-user", "--email", "a@fam01.example", "--password-stdin"})
	root5.SetIn(strings.NewReader("some-password\n"))
	err = root5.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "YABANIN_PG_URI or YABANIN_GATEWAY_PG_URI environment variable is required")
}

// --- ADMIN-03: YABANIN_ADMIN_PASSWORD_FILE arms (no Docker) -----------

func fam01Admin03(t *testing.T) {
	t.Helper()
	// Unreadable/missing file.
	t.Setenv("YABANIN_ADMIN_PASSWORD_FILE", filepath.Join(t.TempDir(), "absent"))
	root, _, _ := fam01CLI(t)
	root.SetArgs([]string{"admin", "create-user", "--email", "a@fam01.example"})
	err := root.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "read YABANIN_ADMIN_PASSWORD_FILE")

	// Empty file.
	empty := filepath.Join(t.TempDir(), "empty")
	require.NoError(t, os.WriteFile(empty, []byte("\n"), 0o600))
	t.Setenv("YABANIN_ADMIN_PASSWORD_FILE", empty)
	root2, _, _ := fam01CLI(t)
	root2.SetArgs([]string{"admin", "create-user", "--email", "a@fam01.example"})
	err = root2.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "YABANIN_ADMIN_PASSWORD_FILE is empty")

	// Valid file, refused PG endpoint: the CLI wraps connectDB's ping
	// failure (port 1 is the canonical refused port; no Docker needed).
	full := filepath.Join(t.TempDir(), "full")
	require.NoError(t, os.WriteFile(full, []byte("pg-secret\n"), 0o600))
	t.Setenv("YABANIN_ADMIN_PASSWORD_FILE", full)
	t.Setenv("YABANIN_PG_URI", "postgres://127.0.0.1:1/fam01?sslmode=disable")
	t.Setenv("YABANIN_GATEWAY_PG_URI", "")
	root3, _, _ := fam01CLI(t)
	root3.SetArgs([]string{"admin", "create-user", "--email", "a@fam01.example"})
	err = root3.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "connect to database")
}

// --- ADMIN-04: connectDB parse and ping arms (no Docker) --------------

func fam01Admin04(t *testing.T) {
	t.Helper()
	_, err := connectDB("://missing-scheme")
	require.Error(t, err)
	require.Contains(t, err.Error(), "parse pg_uri")

	_, err = connectDB("postgres://127.0.0.1:1/fam01?sslmode=disable")
	require.Error(t, err)
	require.Contains(t, err.Error(), "ping database")
}

// --- ADMIT-01: resolution, tags, whitelist, residency ------------------

func fam01Admit01(t *testing.T) {
	t.Helper()
	const embBody = `{"model":"m","input":"x"}`

	// Registry outage → 503 model_registry_unavailable.
	gw, _, _ := newAdmissionMatrixGateway(t)
	gw.res = fam01ErrResolver{}
	rec := postMatrixRequest(t, gw, "/v1/embeddings", "application/json", embBody, nil)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	require.Equal(t, "model_registry_unavailable", errorType(t, rec))

	// Unknown model + reject → 404 + request.invalid carrying the
	// REQUESTED model name.
	gw2, _, _ := newAdmissionMatrixGateway(t)
	gw2.res = fam01SelectiveResolver{miss: resolver.ModelInfo{ModelName: "fam01-fb", Fallback: true}}
	gw2.unknownModelPolicy = "reject"
	events, restore := fam01CaptureEvents(t)
	rec2 := postMatrixRequest(t, gw2, "/v1/embeddings", "application/json", embBody, nil)
	require.Equal(t, http.StatusNotFound, rec2.Code, rec2.Body.String())
	require.Equal(t, "not_found_error", errorType(t, rec2))
	require.Contains(t, rec2.Body.String(), "model_not_found")
	ev := fam01FindEvent(events(), "request.invalid")
	require.NotNil(t, ev, "the unknown-model rejection must publish request.invalid")
	require.Equal(t, "m", ev.ModelRequested)
	restore()

	// Unknown model + fallback → resolved core carries the fallback.
	gw3, _, _ := newAdmissionMatrixGateway(t)
	gw3.unknownModelPolicy = "fallback"
	gw3.res = resolver.NewResolver(unknownModelPool{}, "fb-model", 0, slog.Default())
	rec3, core3, ok3 := fam01CoreCtx(t, gw3, context.Background(), admissionCoreInput{Model: "m"}, nil)
	require.True(t, ok3)
	require.Empty(t, rec3.Body.String(), "admissionCore itself writes nothing on success")
	require.Equal(t, "fb-model", core3.Info.ModelName, "the unknown model resolves to the fallback")

	// Malformed task tag → 400 invalid_task_id.
	gw4, _, _ := newAdmissionMatrixGateway(t)
	rec4 := postMatrixRequest(t, gw4, "/v1/embeddings", "application/json", embBody,
		map[string]string{"X-Yabanin-Task": "bad id"})
	require.Equal(t, http.StatusBadRequest, rec4.Code, rec4.Body.String())
	require.Equal(t, "invalid_task_id", errorType(t, rec4))

	// Malformed workload key → 400 invalid_workload_id.
	gw5, _, _ := newAdmissionMatrixGateway(t)
	rec5 := postMatrixRequest(t, gw5, "/v1/embeddings", "application/json", embBody,
		map[string]string{"X-Yabanin-Workload": "team a"})
	require.Equal(t, http.StatusBadRequest, rec5.Code, rec5.Body.String())
	require.Equal(t, "invalid_workload_id", errorType(t, rec5))

	// Whitelist deny → 403; whitelist outage → 503.
	gw6, _, _ := newAdmissionMatrixGateway(t)
	gw6.wl = fakeAccess{allowed: false}
	rec6 := postMatrixRequest(t, gw6, "/v1/embeddings", "application/json", embBody,
		map[string]string{"X-Org-Id": "o1"})
	require.Equal(t, http.StatusForbidden, rec6.Code, rec6.Body.String())
	require.Equal(t, "permission_denied_error", errorType(t, rec6))

	gw7, _, _ := newAdmissionMatrixGateway(t)
	gw7.wl = fakeAccess{err: errors.New("whitelist backend down")}
	rec7 := postMatrixRequest(t, gw7, "/v1/embeddings", "application/json", embBody,
		map[string]string{"X-Org-Id": "o1"})
	require.Equal(t, http.StatusServiceUnavailable, rec7.Code, rec7.Body.String())
	require.Equal(t, "whitelist_check_unavailable", errorType(t, rec7))

	// Residency denial → 403 residency_policy_violation. Residency runs
	// in the admit() wrapper (admissionCore stops after the spend
	// checks), gated on out.OrgID != "" — a routed matrix request always
	// runs with the auth-stamped empty org, so the arm drives admit()
	// directly with a hand-stamped org.
	gw8, _, _ := newAdmissionMatrixGateway(t)
	gw8.residencyEnforcer = fakeResidency{dec: policy.Decision{Allowed: false, Region: "EU", Reason: "model not resident"}}
	req8 := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/embeddings", strings.NewReader(embBody))
	req8.Header.Set("X-Org-Id", "o1")
	rec8 := httptest.NewRecorder()
	_, ok8 := gw8.admit(rec8, req8, admitInput{Endpoint: "embeddings", Model: "m", Body: []byte(embBody)})
	require.False(t, ok8)
	require.Equal(t, http.StatusForbidden, rec8.Code, rec8.Body.String())
	require.Equal(t, "residency_policy_violation", errorType(t, rec8))
}

// --- ADMIT-02: team budget gates --------------------------------------

func fam01Admit02(t *testing.T) {
	t.Helper()
	// X-Team-Id is an auth-stamped identity header (client copies are
	// stripped at ingress), so these arms drive admissionCore directly.
	hdr := map[string]string{"X-Team-Id": "t7"}

	// No budget configured → 403.
	gw, _, _ := newAdmissionMatrixGateway(t)
	gw.budgetEnforcer = fakeTeamBudget{err: budget.ErrNoBudget}
	rec, _, ok := fam01CoreCtx(t, gw, context.Background(), admissionCoreInput{Model: "m"}, hdr)
	require.False(t, ok)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Equal(t, "budget_not_configured", errorType(t, rec))

	// Budget exceeded → 429 + request.budget_exceeded carrying the
	// RESOLVED model name and the team scope.
	gw2, _, _ := newAdmissionMatrixGateway(t)
	gw2.budgetEnforcer = fakeTeamBudget{err: budget.ErrBudgetExceeded}
	events, restore := fam01CaptureEvents(t)
	rec2, _, ok2 := fam01CoreCtx(t, gw2, context.Background(), admissionCoreInput{Model: "m"}, hdr)
	require.False(t, ok2)
	require.Equal(t, http.StatusTooManyRequests, rec2.Code, rec2.Body.String())
	require.Equal(t, "budget_exceeded", errorType(t, rec2))
	ev := fam01FindEvent(events(), "request.budget_exceeded")
	require.NotNil(t, ev, "a team-budget refusal must publish request.budget_exceeded")
	require.Equal(t, "t7", ev.TeamID)
	require.Equal(t, "fim", ev.ModelRequested, "the budget event carries the RESOLVED model name")
	restore()

	// Backend failure → 503.
	gw3, _, _ := newAdmissionMatrixGateway(t)
	gw3.budgetEnforcer = fakeTeamBudget{err: errors.New("budget backend down")}
	rec3, _, ok3 := fam01CoreCtx(t, gw3, context.Background(), admissionCoreInput{Model: "m"}, hdr)
	require.False(t, ok3)
	require.Equal(t, http.StatusServiceUnavailable, rec3.Code, rec3.Body.String())
	require.Equal(t, "budget_check_unavailable", errorType(t, rec3))
}

// --- ADMIT-03: agent budget gates + dead-context silence ---------------

func fam01Admit03(t *testing.T) {
	t.Helper()
	agentReq := func(gw *gateway, err error) (*httptest.ResponseRecorder, bool) {
		gw.agentEnforcer = fakeAgentBudget{err: err}
		rec, _, ok := fam01CoreCtx(t, gw, context.Background(), admissionCoreInput{Model: "m"},
			map[string]string{"X-Agent-Id": "a1"})
		return rec, ok
	}

	// No agent budget configured → 403.
	gw, _, _ := newAdmissionMatrixGateway(t)
	rec, ok := agentReq(gw, budget.ErrNoAgentBudget)
	require.False(t, ok)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Equal(t, "agent_budget_not_configured", errorType(t, rec))

	// Agent budget exceeded → 429.
	gw2, _, _ := newAdmissionMatrixGateway(t)
	rec2, ok2 := agentReq(gw2, budget.ErrAgentBudgetExceeded)
	require.False(t, ok2)
	require.Equal(t, http.StatusTooManyRequests, rec2.Code, rec2.Body.String())
	require.Equal(t, "agent_budget_exceeded", errorType(t, rec2))

	// Backend failure → 503.
	gw3, _, _ := newAdmissionMatrixGateway(t)
	rec3, ok3 := agentReq(gw3, errors.New("agent budget backend down"))
	require.False(t, ok3)
	require.Equal(t, http.StatusServiceUnavailable, rec3.Code, rec3.Body.String())
	require.Equal(t, "agent_budget_check_unavailable", errorType(t, rec3))

	// Dead context: the fair admission returns ctx.Err() (not a shed) and
	// admissionCore writes NOTHING — recorder stays at its zero value.
	gw4, _, _ := newAdmissionMatrixGateway(t)
	gw4.fair = router.NewFairAdmission(router.FairAdmissionConfig{
		Capacity: 1, MaxPerTenant: 1, QueueLimit: 0,
		WaitTimeout: 50 * time.Millisecond, ShedRetryAfter: 90 * time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec4, _, ok4 := fam01CoreCtx(t, gw4, ctx, admissionCoreInput{Model: "m"}, nil)
	require.False(t, ok4)
	require.Equal(t, http.StatusOK, rec4.Code, "nothing was written")
	require.Empty(t, rec4.Body.String())
}

// --- ADMIT-04: workload cap, token budget, fair shed -------------------

func fam01Admit04(t *testing.T) {
	t.Helper()
	const embBody = `{"model":"m","input":"x"}`

	// Workload cap: preset a 100-µUSD window, saturate the ("", "w1")
	// window (the auth middleware strips client X-Org-Id in strict APIKey
	// mode, so a routed matrix request admits under org ""), and the next
	// request on that workload is refused 429.
	gw, _, _ := newAdmissionMatrixGateway(t)
	presetWorkloadLedger(t, 100)
	l := workloadLedgerShared.Load()
	require.NotNil(t, l)
	l.Charge("", "w1", money.MicroUSD(100))
	rec := postMatrixRequest(t, gw, "/v1/embeddings", "application/json", embBody,
		map[string]string{"X-Yabanin-Workload": "w1"})
	require.Equal(t, http.StatusTooManyRequests, rec.Code, rec.Body.String())
	workloadDeniedEnvelope(t, rec.Body.Bytes())
	workloadLedgerShared.Store(nil)

	// Token budget: task scope at cap → 429 + Retry-After 60. The org
	// component is the auth-stamped "" (client X-Org-Id is stripped).
	gw2, _, _ := newAdmissionMatrixGateway(t)
	gw2.tokenBudget = NewTokenBudget(1000, 0, time.Minute)
	gw2.tokenBudget.Record(TaskBudgetScope, "", "tk9", 1000)
	rec2 := postMatrixRequest(t, gw2, "/v1/embeddings", "application/json", embBody,
		map[string]string{"X-Yabanin-Task": "tk9"})
	require.Equal(t, http.StatusTooManyRequests, rec2.Code, rec2.Body.String())
	require.Equal(t, "token_budget_exceeded", errorType(t, rec2))
	require.Equal(t, "60", rec2.Header().Get("Retry-After"))

	// Fair shed: capacity 1 held by an unreleased ticket, QueueLimit 0 →
	// immediate 429 with the capped Retry-After and the shed message.
	gw3, _, _ := newAdmissionMatrixGateway(t)
	gw3.fair = router.NewFairAdmission(router.FairAdmissionConfig{
		Capacity: 1, MaxPerTenant: 1, QueueLimit: 0,
		WaitTimeout: 50 * time.Millisecond, ShedRetryAfter: 90 * time.Second,
	})
	held, err := gw3.fair.Admit(context.Background(), "", "w1")
	require.NoError(t, err)
	rec3 := postMatrixRequest(t, gw3, "/v1/embeddings", "application/json", embBody,
		map[string]string{"X-Yabanin-Workload": "w1"})
	held.Release()
	require.Equal(t, http.StatusTooManyRequests, rec3.Code, rec3.Body.String())
	require.Equal(t, "rate_limit_exceeded", errorType(t, rec3))
	require.Equal(t, "60", rec3.Header().Get("Retry-After"), "Retry-After is capped at 60s")
	require.Contains(t, rec3.Body.String(), "gateway capacity reached")
}

// --- HOP-01: budgeted judge client guards ------------------------------

func fam01Hop01(t *testing.T) {
	t.Helper()
	// Unmarked meta: the recursion-exclusion contract refuses the call.
	up := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
	client, req := newJudgeHopClient(t, up, nil)
	req.Meta = &pipeline.RequestMeta{Org: "org-judge"}
	_, err := client.JudgeChat(context.Background(), req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "recursion-exclusion contract")
	require.Zero(t, up.hits.Load(), "an unmarked judge call must never reach the wire")

	// Pool not wired.
	wired := (&gateway{log: slog.New(slog.DiscardHandler)}).newBudgetedJudgeClient(
		llmjudge.ModelResolverFunc(func(context.Context, string) (llmjudge.Target, error) {
			return llmjudge.Target{}, nil
		}),
		llmjudge.KeyResolverFunc(func(context.Context, string, llmjudge.Target) (string, error) {
			return "", nil
		}),
	)
	_, isBudgeted := wired.(*budgetedJudgeClient)
	require.True(t, isBudgeted, "the drop-in wiring must return the budgeted judge client")

	client2, req2 := newJudgeHopClient(t, up, func(c *budgetedJudgeClient) { c.pool = nil })
	_, err = client2.JudgeChat(context.Background(), req2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "pool is not wired")

	// Loop cap: the second hop on the same episode is refused fail-closed.
	loop := budget.NewLoopBudget(1, time.Minute)
	client3, req3 := newJudgeHopClient(t, up, func(c *budgetedJudgeClient) { c.loop = loop })
	ctx := requestid.NewContext(context.Background(), requestid.ID("fam01-hop1-loop"))
	_, err = client3.JudgeChat(ctx, req3)
	require.NoError(t, err, "the first hop is under the cap")
	_, err = client3.JudgeChat(ctx, req3)
	require.ErrorIs(t, err, budget.ErrLoopBudgetExceeded)
	require.Equal(t, int64(1), up.hits.Load(), "the refused hop must not reach the wire")
	loop.Release("fam01-hop1-loop")

	// Agent budget: the parent request's agent identity is checked G2.
	client4, req4 := newJudgeHopClient(t, up, func(c *budgetedJudgeClient) {
		c.agentEnforcer = fakeAgentBudget{err: budget.ErrAgentBudgetExceeded}
	})
	ctx4 := withPrincipal(requestid.NewContext(context.Background(), requestid.ID("fam01-hop1-agent")),
		principal{AgentID: "agent-1"})
	_, err = client4.JudgeChat(ctx4, req4)
	require.ErrorIs(t, err, budget.ErrAgentBudgetExceeded)
	require.Contains(t, err.Error(), "judge agent budget")
	require.Equal(t, int64(1), up.hits.Load(), "a budget-denied hop must not reach the wire")
}

// --- HOP-02: settle oracles -------------------------------------------

func fam01Hop02(t *testing.T) {
	t.Helper()
	// Success settles EXACT upstream usage and the priced cost.
	up := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
	client, req := newJudgeHopClient(t, up, nil)
	events, restore := fam01CaptureEvents(t)
	ep := "fam01-hop2-settle"
	ctx := withPrincipal(requestid.NewContext(context.Background(), requestid.ID(ep)),
		principal{AgentID: "agent-1"})
	resp, err := client.JudgeChat(ctx, req)
	require.NoError(t, err)
	require.JSONEq(t, `{"verdict":"allow"}`, resp.Content)
	require.Equal(t, "gpt-4o-mini", resp.Model)
	require.Equal(t, int64(1), up.hits.Load())

	ev := fam01FindEvent(events(), "request.completed")
	require.NotNil(t, ev, "every judge hop must settle exactly one event")
	require.Equal(t, agentHopEndpoint, ev.Endpoint)
	require.Equal(t, ep, ev.RequestID)
	require.Equal(t, "org-judge", ev.OrgID)
	require.Equal(t, "agent-1", ev.AgentID)
	require.Equal(t, int64(11), ev.TokensIn, "EXACT upstream usage, never estimated")
	require.Equal(t, int64(7), ev.TokensOut)
	require.Equal(t, "provider", ev.UsageSource)
	require.Equal(t, "priced", ev.CostStatus)
	require.Empty(t, ev.Error)
	want := provider.ComputeCost(provider.Usage{
		PromptTokens: 11, CompletionTokens: 7, TotalTokens: 18, Source: provider.UsageSourceProvider,
	}, "openai", "gpt-4o-mini").EstimatedCostUSD
	require.InDelta(t, want, ev.EstimatedCostUSD, 0)
	require.Empty(t, ev.Reservations, "off mode publishes no reserve tuples")
	sharedLoopBudget().Release(ep)
	restore()

	// Upstream failure settles the zero spend with the upstream_error
	// termination.
	up2 := &judgeHopUpstream{t: t, status: http.StatusInternalServerError, body: `{"error":"boom"}`}
	client2, req2 := newJudgeHopClient(t, up2, nil)
	events2, restore2 := fam01CaptureEvents(t)
	_, err = client2.JudgeChat(context.Background(), req2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "judge upstream status 500")
	ev2 := fam01FindEvent(events2(), "request.completed")
	require.NotNil(t, ev2, "a failed hop still settles its (zero) spend")
	require.Equal(t, agentHopEndpoint, ev2.Endpoint)
	require.Equal(t, int64(500), ev2.StatusCode)
	require.NotEmpty(t, ev2.Error)
	require.Equal(t, int64(0), ev2.TokensIn)
	require.Equal(t, int64(0), ev2.TokensOut)
	require.Zero(t, ev2.EstimatedCostUSD)
	require.Equal(t, string(budget.TerminationUpstreamErr), ev2.Termination)
	restore2()

	// Workload charge: the first hop's settle charges the shared ledger,
	// so the second hop on the same workload identity is refused.
	up3 := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
	client3, req3 := newJudgeHopClient(t, up3, nil)
	presetWorkloadLedger(t, 1)
	defer workloadLedgerShared.Store(nil)
	wctx := withLabels(requestid.NewContext(context.Background(), requestid.ID("fam01-hop2-wl")),
		labels.Result{Labels: labels.Set{metaLabelWorkload: "wJ2"}})
	_, err = client3.JudgeChat(wctx, req3)
	require.NoError(t, err, "the first hop on an unspent window is admitted")
	_, err = client3.JudgeChat(wctx, req3)
	require.Error(t, err)
	require.Contains(t, err.Error(), "judge workload budget")
	require.Equal(t, int64(1), up3.hits.Load(), "the refused hop must not reach the wire again")
	sharedLoopBudget().Release("fam01-hop2-wl")
}

// --- HOP-03: §5 admission matrix over live Postgres (Docker) ----------

func fam01Hop03(t *testing.T) {
	t.Helper()
	fam01RequireDocker(t)
	pool := testdb.Postgres(t)
	up := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
	priced := fam01AdmissionFor(pool, true)
	empty := fam01AdmissionFor(pool, false)

	hop := func(adm *budget.Admission, org, ep string) error {
		client, req := newJudgeHopClient(t, up, func(c *budgetedJudgeClient) { c.admission = adm })
		if org != "" {
			req.Meta = judgeHopMeta(org)
		}
		err := func() error {
			ctx := requestid.NewContext(context.Background(), requestid.ID(ep))
			_, err := client.JudgeChat(ctx, req)
			return err
		}()
		sharedLoopBudget().Release(ep)
		return err
	}

	// (a) reservations off for the deploy: the hop succeeds unreserved.
	require.NoError(t, hop(nil, "", "fam01-hop3-a"), "a nil admission controller is the legacy behavior")

	// (b) org off under a global-enforce ceiling: EffectiveMode keeps the
	// org at off — success without reserve tuples.
	orgB := fam01SeedOrg(t, pool, "off", true, 0)
	eventsB, restoreB := fam01CaptureEvents(t)
	require.NoError(t, hop(priced, orgB, "fam01-hop3-b"))
	evB := fam01FindEvent(eventsB(), "request.completed")
	require.NotNil(t, evB)
	require.Empty(t, evB.Reservations, "an off org settles no reserve tuples")
	restoreB()

	// (c) shadow + unpriced: the would-deny is recorded, the hop proceeds.
	orgC := fam01SeedOrg(t, pool, "shadow", true, 0)
	require.NoError(t, hop(empty, orgC, "fam01-hop3-c"), "shadow never denies")

	// (d) shadow + priced + zero balance: grant refusal recorded, proceeds.
	orgD := fam01SeedOrg(t, pool, "shadow", true, 0)
	require.NoError(t, hop(priced, orgD, "fam01-hop3-d"))

	// (e) enforce + unpriced: the estimator fails closed (I3) before any
	// upstream traffic.
	hitsBefore := up.hits.Load()
	orgE := fam01SeedOrg(t, pool, "enforce", true, 0)
	err := hop(empty, orgE, "fam01-hop3-e")
	require.Error(t, err)
	require.ErrorIs(t, err, budget.ErrUnpricedModel)
	require.Contains(t, err.Error(), "judge hop budget admission")
	require.Equal(t, hitsBefore, up.hits.Load(), "an unpriced enforce hop must not reach the wire")

	// (f) enforce + priced + no capacity source (no org_credits row).
	orgF := fam01SeedOrg(t, pool, "enforce", false, 0)
	err = hop(priced, orgF, "fam01-hop3-f")
	require.Error(t, err)
	require.ErrorIs(t, err, budget.ErrNoCapacitySource)
	require.Equal(t, hitsBefore, up.hits.Load(), "a hop without a capacity source must not reach the wire")

	// (g) enforce + priced + funded wallet: reserved, settled, completed.
	orgG := fam01SeedOrg(t, pool, "enforce", true, 5000)
	eventsG, restoreG := fam01CaptureEvents(t)
	require.NoError(t, hop(priced, orgG, "fam01-hop3-g"))
	evG := fam01FindEvent(eventsG(), "request.completed")
	require.NotNil(t, evG)
	require.NotEmpty(t, evG.Reservations, "an enforce-mode hop must carry its reserve tuples")
	require.Equal(t, string(budget.TerminationCompleted), evG.Termination, "the settled hop terminates completed")
	require.Equal(t, int64(1), up.hits.Load()-hitsBefore, "exactly the funded hop reached the wire")
	restoreG()
}

// --- generated contract: varying-input oracles (hermetic, no Docker) ---

// fam01SafeName folds arbitrary seed bytes into a bounded identifier that is
// safe to interpolate into JSON wire bodies and registry lookups. Bytes
// outside [A-Za-z0-9._-] are dropped; the name caps at 64 runes; an empty
// fold falls back to a constant so every payload yields a usable input.
func fam01SafeName(seed []byte) string {
	var b strings.Builder
	for _, c := range seed {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '.', c == '_', c == '-':
			b.WriteByte(c)
		}
		if b.Len() == 64 {
			break
		}
	}
	if b.Len() == 0 {
		return "fam01-gen"
	}
	return b.String()
}

// fam01Generated is the ACTIVE half of the fuzz contract: any non-seed
// payload (the empty input included — len != 1 or first byte outside
// 0x01..0x0b) drives three varying-input oracles, one per family. The
// empty payload is a deliberate boundary: the ADMIN arm must see the
// empty bootstrap password refused, while ADMIT/HOP fold it to the
// constant fallback name. Each arm derives its input purely
// from the payload, computes the expected behavior independently of the
// implementation under test, and asserts literal expectations. Everything
// here is hermetic — no Docker, no database, one throwaway httptest server
// per hop arm, a local loop budget, and a local event observer — so the
// arms can run unboundedly under -fuzz without leaking state.
func fam01Generated(t *testing.T, seed []byte) {
	t.Helper()
	// ADMIN: boundary parsing of the bootstrap password from the raw bytes.
	pw := seed
	if len(pw) > 128 {
		pw = pw[:128]
	}
	got, err := readAdminPassword(true, bytes.NewReader(pw))
	trimmed := strings.TrimRight(string(pw), "\r\n")
	if trimmed == "" {
		require.Error(t, err, "an all-blank stdin password must be refused")
		require.Contains(t, err.Error(), "password from --password-stdin is empty")
		require.Empty(t, got)
	} else {
		require.NoError(t, err)
		require.Equal(t, trimmed, got, "the stdin password is trimmed of its line ending only")
	}

	// ADMIT: resolution of the payload-derived model name.
	fam01GeneratedAdmit(t, fam01SafeName(seed))

	// HOP: the payload-derived judge target riding the wire.
	fam01GeneratedHop(t, fam01SafeName(seed))
}

// fam01GeneratedAdmit resolves the derived name against a fixed one-entry
// registry. Known "m" → admitted with the resolved info and no envelope;
// anything else → 404 not_found_error + request.invalid carrying the EXACT
// requested name. The gateway is a minimal literal (no server, no cleanup
// registration) so a campaign cannot accumulate leaked resources.
func fam01GeneratedAdmit(t *testing.T, name string) {
	t.Helper()
	gw := &gateway{
		cfg: config.Gateway{},
		log: slog.New(slog.DiscardHandler),
		res: fam01SelectiveResolver{
			known: map[string]resolver.ModelInfo{
				"m": {ModelName: "fim", Provider: "openai", Enabled: true},
			},
			miss: resolver.ModelInfo{ModelName: "fam01-fb", Fallback: true},
		},
		pool:      upstream.NewPool(upstream.Options{}),
		eventNote: func(*eventpub.Event) {},
	}
	gw.unknownModelPolicy = "reject"

	events, restore := fam01CaptureEvents(t)
	defer restore()
	rec, core, ok := fam01CoreCtx(t, gw, context.Background(), admissionCoreInput{Model: name}, nil)
	if name == "m" {
		require.True(t, ok, "the known model resolves and is admitted")
		require.Equal(t, "fim", core.Info.ModelName)
		require.Empty(t, rec.Body.String(), "admissionCore itself writes nothing on success")
		require.Nil(t, fam01FindEvent(events(), "request.invalid"), "a known model publishes no invalid event")
		return
	}
	require.False(t, ok, "an unknown model is rejected under the reject policy")
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	require.Equal(t, "not_found_error", errorType(t, rec))
	require.Contains(t, rec.Body.String(), "model_not_found")
	ev := fam01FindEvent(events(), "request.invalid")
	require.NotNil(t, ev, "the unknown-model rejection must publish request.invalid")
	require.Equal(t, name, ev.ModelRequested, "the event carries the exact requested name")
}

// fam01GeneratedHop sends one judge hop whose TARGET is the derived name and
// proves the resolution rode the wire: the captured request body carries it
// as the JSON "model", the recursion-exclusion marker header is present, and
// the parsed verdict comes back. The loop budget and upstream server are
// local to the call, so repeated campaign iterations stay independent.
func fam01GeneratedHop(t *testing.T, ref string) {
	t.Helper()
	var gotBody, gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read judge wire body: %v", err)
		}
		gotBody, gotHeader = string(b), r.Header.Get(llmjudge.JudgeHeader)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(judgeHopOKBody))
	}))
	defer srv.Close()

	client := NewBudgetedJudgeClient(
		upstream.NewPool(upstream.Options{}),
		llmjudge.ModelResolverFunc(func(_ context.Context, m string) (llmjudge.Target, error) {
			return llmjudge.Target{Model: m, Provider: "openai", UpstreamURL: srv.URL}, nil
		}),
		llmjudge.KeyResolverFunc(func(context.Context, string, llmjudge.Target) (string, error) {
			return "upstream-key", nil
		}),
		budget.NewAdmission(nil, budget.ScopedRateSource{}, nil, "fam01-gen", budget.ModeOff, nil, budget.AdmissionConfig{}),
		budget.NewLoopBudget(2, time.Minute),
		nil, nil, judgeHopLogger(t),
		// Preview2 durable accounting (additive option — the positional
		// signature stays source-compatible).
		WithJudgeInvocationStore(&fakeInvocationStore{}),
	)
	req := judgeHopRequest(ref)

	ctx := requestid.NewContext(context.Background(), requestid.ID("fam01-gen-hop"))
	resp, err := client.JudgeChat(ctx, req)
	require.NoError(t, err)
	require.JSONEq(t, `{"verdict":"allow"}`, resp.Content)
	require.Equal(t, llmjudge.JudgeLabelValue, gotHeader, "the judge marker must ride the wire")
	var wire struct {
		Model string `json:"model"`
	}
	require.NoError(t, json.Unmarshal([]byte(gotBody), &wire))
	require.Equal(t, ref, wire.Model, "the resolved target model must be the wire model")
}
