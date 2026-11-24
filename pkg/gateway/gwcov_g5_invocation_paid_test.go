package cli

// G5 coverage recovery: independent behavioral and fault-injection tests for
// the zero-coverage blocks of pkg/gateway/invocation.go (nil-store and
// nil-identity fail-closed arms, terminal-facts retry boundaries),
// paid_route_common.go (body read, plan/reserve denials, upstream client
// refusal), gateway_shadow.go (job build and call arms) and gateway_policy.go
// (orgless pre-upstream arm). Each case asserts the externally visible
// contract (status code, error identity, side-effect-free posture), not just
// branch execution.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/config"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// --- g5 helpers -------------------------------------------------------------

// g5DiscardLogger keeps failure logging out of test output.
func g5DiscardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// g5errReader fails the first Read with the scripted error so readRouteBody
// exercises its non-MaxBytes read-failure arm.
type g5errReader struct{ err error }

func (r g5errReader) Read([]byte) (int, error) { return 0, r.err }

// g5UnitPricer is a static non-token rate catalog (pricing.UnitPricer) keyed
// by provider + model; it prices the wallet scope without any database.
type g5UnitPricer map[string]pricing.UnitEntry

func (p g5UnitPricer) LookupUnit(providerName, model string) (pricing.UnitEntry, bool) {
	e, ok := p[providerName+"\x00"+model]
	return e, ok
}

// g5EnforceOrgs opts every org into enforce reservations.
func g5EnforceOrgs(context.Context, string) (budget.OrgSettings, error) {
	return budget.OrgSettings{Mode: budget.ModeEnforce}, nil
}

// --- invocation.go ----------------------------------------------------------

// TestGWCovG5NilInvocationStoreArms pins the fail-closed posture of every
// durable-seam entry point when the store is unwired: each refuses with
// ErrInvocationStoreUnavailable before any dispatch-side effect.
func TestGWCovG5_NilInvocationStoreArms(t *testing.T) {
	t.Run("nilInvocationStore", func(t *testing.T) {
		err := nilInvocationStore(nil)
		require.ErrorIs(t, err, ErrInvocationStoreUnavailable)
		require.Contains(t, err.Error(), "nil store")
	})

	t.Run("beginPaidDispatch refuses on nil store", func(t *testing.T) {
		h := newTestIdentity()
		err := h.beginPaidDispatch(t.Context(), nil, invocationKindChat)
		require.ErrorIs(t, err, ErrInvocationStoreUnavailable)
		require.False(t, h.Admitted(), "a nil store must never mark admitted (zero provider arrivals)")
	})

	t.Run("void refuses on nil store", func(t *testing.T) {
		h := newTestIdentity()
		err := h.void(t.Context(), nil)
		require.ErrorIs(t, err, ErrInvocationStoreUnavailable)
	})

	t.Run("recordTerminalFacts refuses on nil store", func(t *testing.T) {
		h := newTestIdentity()
		err := h.recordTerminalFacts(t.Context(), nil, map[string]string{"k": "v"})
		require.ErrorIs(t, err, ErrInvocationStoreUnavailable)
	})

	t.Run("commitInvocationTerminal requires an event", func(t *testing.T) {
		h := newTestIdentity()
		err := h.commitInvocationTerminal(t.Context(), nil, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "terminal commit requires an event")
	})
}

// TestGWCovG5InvocationContextIdentity pins the context plumbing: a nil
// holder leaves the context untouched, an absent holder renders "" for logs,
// and confirmPaidInvocation fails closed when admission never minted one.
func TestGWCovG5_InvocationContextIdentity(t *testing.T) {
	t.Run("withInvocationIdentity nil holder is identity", func(t *testing.T) {
		ctx := context.Background()
		require.Equal(t, ctx, withInvocationIdentity(ctx, nil))
	})

	t.Run("invocationIDFromCtx absent holder renders empty", func(t *testing.T) {
		require.Empty(t, invocationIDFromCtx(context.Background()))
	})

	t.Run("confirmPaidInvocation without identity refuses", func(t *testing.T) {
		gw := &gateway{}
		err := gw.confirmPaidInvocation(context.Background(), invocationKindChat)
		require.ErrorIs(t, err, ErrInvocationStoreUnavailable)
		require.Contains(t, err.Error(), "no invocation identity")
	})
}

// TestGWCovG5WriteInvocationStartRefusalNonStoreError pins the two refusal
// envelopes: store-unavailability answers the history_unavailable 503 family,
// any other start failure answers a plain 500 refusing the paid dispatch.
func TestGWCovG5_WriteInvocationStartRefusalNonStoreError(t *testing.T) {
	t.Run("non-store error answers 500 refusing dispatch", func(t *testing.T) {
		rec := httptest.NewRecorder()
		writeInvocationStartRefusal(rec, errors.New("deterministic boom"))
		require.Equal(t, http.StatusInternalServerError, rec.Code)
		require.Contains(t, rec.Body.String(), "refusing paid dispatch")
		require.Contains(t, rec.Body.String(), "deterministic boom")
		require.NotContains(t, rec.Body.String(), "history_unavailable")
	})

	t.Run("store-unavailable answers 503 history envelope", func(t *testing.T) {
		rec := httptest.NewRecorder()
		writeInvocationStartRefusal(rec, fmt.Errorf("wrap: %w", ErrInvocationStoreUnavailable))
		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
		require.Contains(t, rec.Body.String(), "history_unavailable")
	})
}

// TestGWCovG5StampAndCommitAdmittedWithoutStore pins the loud failure when
// an admitted invocation reaches the terminal funnel on a gateway with no
// invocation store wired: the event must not silently publish.
func TestGWCovG5_StampAndCommitAdmittedWithoutStore(t *testing.T) {
	store := &fakeInvocationStore{}
	h := newTestIdentity()
	require.NoError(t, h.beginPaidDispatch(t.Context(), store, invocationKindChat))
	require.True(t, h.Admitted())

	gw := &gateway{log: g5DiscardLogger()} // invocations deliberately unwired
	ctx := withInvocationIdentity(context.Background(), h)
	ev := &eventpub.Event{}

	err := gw.stampAndCommitInvocationTerminal(ctx, ev, g5DiscardLogger())
	require.ErrorIs(t, err, ErrInvocationStoreUnavailable)
	require.Contains(t, err.Error(), "no store to commit terminal facts")
	require.Equal(t, h.ID(), ev.InvocationID, "identity is still stamped on the event")
}

// TestGWCovG5VoidUndispatchedInvocationLogsVoidFailure pins that a failing
// void after a local refusal is logged loudly (the reconciler owns the row).
func TestGWCovG5_VoidUndispatchedInvocationLogsVoidFailure(t *testing.T) {
	store := &fakeInvocationStore{voidErr: errors.New("void write failed")}
	h := newTestIdentity()
	require.NoError(t, h.beginPaidDispatch(t.Context(), store, invocationKindChat))

	var buf bytes.Buffer
	l := slog.New(slog.NewTextHandler(&buf, nil))
	gw := &gateway{invocations: store, log: g5DiscardLogger()}
	ctx := withInvocationIdentity(context.Background(), h)

	gw.voidUndispatchedInvocation(ctx, l)
	require.Contains(t, buf.String(), "could not close admission after local refusal")
	require.Contains(t, buf.String(), h.ID())
	require.Contains(t, buf.String(), "void write failed")
	require.Empty(t, store.voided, "the failed void must not be recorded as voided")
}

// TestGWCovG5RetryInvocationWriteContextExpiresDuringBackoff pins the
// unknown-outcome join: when the bounded terminal-facts window expires while
// a retryable write is outstanding, the caller sees both the write error and
// the context error.
func TestGWCovG5_RetryInvocationWriteContextExpiresDuringBackoff(t *testing.T) {
	err := retryInvocationWrite(context.Background(), func(context.Context) error {
		// Sleep past terminalFactsTimeout (3s) so the derived context is
		// already expired when the retry backoff select runs; io.EOF is a
		// transport ambiguity and must be retried.
		time.Sleep(terminalFactsTimeout + 200*time.Millisecond)
		return io.EOF
	})
	require.ErrorIs(t, err, io.EOF)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

// TestGWCovG5ShouldRetryTerminalCommitDivergentIsFatal pins the retry
// taxonomy: a divergent stored payload never converges (no retry), while
// transient transaction classes and transport ambiguities do.
func TestGWCovG5_ShouldRetryTerminalCommitDivergentIsFatal(t *testing.T) {
	require.False(t, shouldRetryTerminalCommit(nil), "success never retries")
	require.False(t, shouldRetryTerminalCommit(fmt.Errorf("outer: %w", ErrTerminalFactsDivergent)),
		"a divergent payload can never converge")
	require.True(t, shouldRetryTerminalCommit(io.EOF), "transport ambiguity retries")
	require.True(t, shouldRetryTerminalCommit(&pgconn.PgError{Code: "40001"}),
		"serialization_failure retries")
}

// --- paid_route_common.go ---------------------------------------------------

// TestGWCovG5ReadRouteBodyReadFailureAnswers400 pins the read-failure
// contract of the paid routes: a generic body read error answers 400; the
// gateway's MaxBytes cap answers the 413 payload-size refusal.
func TestGWCovG5_ReadRouteBodyReadFailureAnswers400(t *testing.T) {
	t.Run("generic read error answers 400", func(t *testing.T) {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/embeddings", nil)
		r.Body = io.NopCloser(g5errReader{err: errors.New("connection reset")})
		rec := httptest.NewRecorder()

		body, ok := readRouteBody(rec, r)
		require.False(t, ok)
		require.Nil(t, body)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Contains(t, rec.Body.String(), "request body too large or malformed")
	})

	t.Run("max-bytes read error answers 413", func(t *testing.T) {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/embeddings", nil)
		r.Body = io.NopCloser(g5errReader{err: fmt.Errorf("limited: %w", &http.MaxBytesError{Limit: 32})})
		rec := httptest.NewRecorder()

		body, ok := readRouteBody(rec, r)
		require.False(t, ok)
		require.Nil(t, body)
		require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
		require.Contains(t, rec.Body.String(), "request body too large")
	})
}

// TestGWCovG5ReservePlannedRequestPlanDenial pins the plan-stage refusal:
// an enforce org whose planned chain is unpriced is refused terminally with
// the 403 model_unpriced envelope before any reservation side effect.
func TestGWCovG5_ReservePlannedRequestPlanDenial(t *testing.T) {
	adm := budget.NewAdmission(nil, budget.ScopedRateSource{}, g5DiscardLogger(), "g5-replica",
		budget.ModeEnforce, g5EnforceOrgs, budget.AdmissionConfig{})
	gw := &gateway{admission: adm, log: g5DiscardLogger()}
	req := budget.Request{
		OrgID: "org-g5",
		Chain: []budget.ChainHop{{Provider: "openai", Model: "g5-unpriced"}},
	}

	rec := httptest.NewRecorder()
	rctx, gate, ok := gw.reservePlannedRequest(context.Background(), rec,
		httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil), "chat.completions", req)

	require.False(t, ok, "an unpriced enforce plan must refuse")
	require.Nil(t, gate)
	require.Nil(t, rctx)
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Contains(t, rec.Body.String(), "model_unpriced")
}

// TestGWCovG5ReservePlannedRequestReserveDenial pins the reserve-stage
// refusal: with the plan priced (unit catalog) and the reservation store
// unreachable, enforce fails closed with the 503 reservation envelope — the
// probe treats the outage as unknown (plan proceeds) and the grant is the
// authority that denies.
func TestGWCovG5_ReservePlannedRequestReserveDenial(t *testing.T) {
	ctx := context.Background()
	// A pgx pool against a refused local port: no dial happens at
	// construction; every later use (probe, grant) fails fast with a
	// connection error, which the admission layers surface gracefully.
	pool, err := pgxpool.New(ctx, "postgres://g5@127.0.0.1:1/g5?sslmode=disable&connect_timeout=1")
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	store := budget.NewReservationStore(pool, g5DiscardLogger())
	units := g5UnitPricer{
		"openai\x00g5-image-model": {
			Provider: "openai", Model: "g5-image-model",
			Unit: pricing.UnitPerImage, Rate: 0.01,
		},
	}
	adm := budget.NewAdmission(store,
		budget.ScopedRateSource{Base: budget.BaseRateSource{Units: units}},
		g5DiscardLogger(), "g5-replica", budget.ModeEnforce, g5EnforceOrgs, budget.AdmissionConfig{})
	adm.Start(ctx)
	t.Cleanup(adm.Stop)

	gw := &gateway{admission: adm, log: g5DiscardLogger()}
	qty := 2.0
	req := budget.Request{
		OrgID:    "org-g5",
		Chain:    []budget.ChainHop{{Provider: "openai", Model: "g5-image-model"}},
		UnitKind: pricing.UnitPerImage,
		UnitQty:  &qty,
	}

	rec := httptest.NewRecorder()
	rctx, gate, ok := gw.reservePlannedRequest(context.Background(), rec,
		httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/images/generations", nil), "images", req)

	require.False(t, ok, "a grant-denying enforce reserve must refuse")
	require.Nil(t, gate)
	require.Nil(t, rctx)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	require.Contains(t, rec.Body.String(), "reservation admission temporarily unavailable")
}

// TestGWCovG5PaidUpstreamClientPoolFailure pins the pre-dispatch refusal: an
// unbuildable upstream client (invalid custom base URL) answers 502 and
// finalizes the reservation gate with no provider arrival.
func TestGWCovG5_PaidUpstreamClientPoolFailure(t *testing.T) {
	gw := &gateway{pool: upstream.NewPool(upstream.Options{}), log: g5DiscardLogger()}
	gate := &reservationGate{}
	adm := admitted{
		Info: resolver.ModelInfo{
			Provider:    "openai",
			ModelName:   "g5-model",
			UpstreamURL: "http://[::1]:namedport", // unparseable port
		},
		Body: []byte(`{"model":"g5-model"}`),
	}

	rec := httptest.NewRecorder()
	client, upstreamBody, apiKey, defaultedProvider, upstreamURL, ok := gw.paidUpstreamClient(
		g5DiscardLogger(), rec, gate, adm, "openai")

	require.False(t, ok)
	require.Nil(t, client)
	require.Nil(t, upstreamBody)
	require.Empty(t, apiKey)
	// The failure return at this seam leaves every dispatch input unset: no
	// half-resolved provider or URL may leak to a caller that got ok=false.
	require.Empty(t, defaultedProvider)
	require.Empty(t, upstreamURL)
	require.Equal(t, http.StatusBadGateway, rec.Code)
	require.Contains(t, rec.Body.String(), "failed to initialise upstream client")
}

// --- gateway_shadow.go ------------------------------------------------------

// TestGWCovG5BuildShadowJobUnmarshalFallsBackToEmptyMap pins the degraded
// body rewrite: a non-object JSON body degrades to the forced model/stream
// job instead of failing or leaking the client's malformed structure.
func TestGWCovG5_BuildShadowJobUnmarshalFallsBackToEmptyMap(t *testing.T) {
	gw := &gateway{pool: upstream.NewPool(upstream.Options{}), log: g5DiscardLogger()}
	gw.cfg.Shadow = config.Shadow{Model: "g5-shadow"}

	for name, body := range map[string][]byte{
		"array body":         []byte(`[1,2,3]`),
		"overflowing number": []byte(`{"temperature":1e999}`),
	} {
		t.Run(name, func(t *testing.T) {
			job := gw.buildShadowJob(context.Background(), body, "primary-m", "org-1", "team-1", "sess-1", "req-1", g5DiscardLogger())
			require.NotEmpty(t, job.Body, "the degraded job still carries a rewritten body")

			var m map[string]any
			require.NoError(t, json.Unmarshal(job.Body, &m))
			require.Equal(t, map[string]any{
				"model":  "g5-shadow",
				"stream": false,
			}, m, "the empty-map fallback yields exactly the forced fields")
		})
	}
}

// TestGWCovG5ShadowCallResolvesGatewayDefaultsAndClient pins the call-arms:
// an unconfigured shadow URL/key falls back to the gateway's provider URL
// and key, and an unbuildable pool client fails the shadow call BEFORE the
// durable shadow admission — with a valid URL the same call reaches the
// invocation-store check instead.
func TestGWCovG5_ShadowCallResolvesGatewayDefaultsAndClient(t *testing.T) {
	newJob := func(providerURL string) (shadowCall, []byte) {
		gw := &gateway{pool: upstream.NewPool(upstream.Options{}), log: g5DiscardLogger()}
		gw.cfg.Shadow = config.Shadow{Model: "g5-shadow"} // no UpstreamURL, no APIKey
		gw.cfg.Provider = providerURL
		body := []byte(`{"model":"primary-m"}`)
		job := gw.buildShadowJob(context.Background(), body, "primary-m", "org-1", "team-1", "sess-1", "req-1", g5DiscardLogger())
		return job.Call, body
	}

	t.Run("invalid gateway URL fails at the pool client", func(t *testing.T) {
		call, _ := newJob("http://[::1]:namedport")
		_, err := call(context.Background())
		require.Error(t, err)
		require.Contains(t, err.Error(), "shadow upstream client for openai")
	})

	t.Run("valid URL reaches the durable admission check", func(t *testing.T) {
		call, _ := newJob("http://127.0.0.1:9")
		_, err := call(context.Background())
		require.Error(t, err)
		require.Contains(t, err.Error(), "no invocation store wired",
			"a buildable client must fail later, at the shadow admission seam")
	})
}

// TestGWCovG5ShadowParseUsageWithoutAdapter pins the nil-adapter arm: when
// the shadow model's provider has no adapter, usage parsing degrades to the
// zero Usage instead of panicking; a resolvable provider still parses.
func TestGWCovG5_ShadowParseUsageWithoutAdapter(t *testing.T) {
	payload := []byte(`{"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`)

	t.Run("unknown provider yields zero usage", func(t *testing.T) {
		gw := &gateway{res: stubModelResolver{
			"g5-shadow": {ModelName: "g5-shadow", Provider: "nosuchprovider", Enabled: true},
		}, log: g5DiscardLogger()}
		gw.cfg.Shadow = config.Shadow{Model: "g5-shadow"}

		job := gw.buildShadowJob(context.Background(), []byte(`{"model":"primary-m"}`),
			"primary-m", "org-1", "team-1", "sess-1", "req-1", g5DiscardLogger())
		require.Equal(t, provider.Usage{}, job.ParseUsage(payload))
	})

	t.Run("resolvable provider parses usage", func(t *testing.T) {
		gw := &gateway{res: stubModelResolver{
			"g5-shadow": {ModelName: "g5-shadow", Provider: "openai", Enabled: true},
		}, log: g5DiscardLogger()}
		gw.cfg.Shadow = config.Shadow{Model: "g5-shadow"}

		job := gw.buildShadowJob(context.Background(), []byte(`{"model":"primary-m"}`),
			"primary-m", "org-1", "team-1", "sess-1", "req-1", g5DiscardLogger())
		require.Equal(t, int64(5), job.ParseUsage(payload).PromptTokens)
	})
}

// --- gateway_policy.go ------------------------------------------------------

// TestGWCovG5PolicyPreUpstreamOrgless pins the orgless arm: with a live
// policy runtime and no org header, the pre-upstream hook passes the body
// through untouched, records no decision JSON and writes nothing.
func TestGWCovG5_PolicyPreUpstreamOrgless(t *testing.T) {
	gw := &gateway{policyRuntime: &PolicyRuntime{mode: PolicyModeShadow}, log: g5DiscardLogger()}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	body := []byte(`{"model":"m"}`)

	gotBody, decisions, ok := gw.policyPreUpstream(httptest.NewRecorder(), r,
		"chat.completions", "m", "openai", body)

	require.True(t, ok, "an orgless request is not policy-gated")
	require.Equal(t, body, gotBody)
	require.Empty(t, decisions)
}

// shadowCall names the job's provider call signature for readability above.
type shadowCall func(context.Context) ([]byte, error)
