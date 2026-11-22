package cli

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/circuit"
)

// refusalAdmissionsClosed reports whether the admission accounting for one
// refused request behind a dispatched call with identity healthyID is exact:
// the refusal starts at most one admission with an identity distinct from
// the dispatch, and the void list equals that admission exactly once — no
// repeated void, no substitution with the dispatched identity, nothing
// missing. Zero starts (early rejection before admission) is valid and
// voids nothing.
func refusalAdmissionsClosed(admitted []admissionRecord, voided []string, healthyID string) bool {
	extra := len(admitted) - 1
	if extra < 0 || extra > 1 || len(voided) != extra {
		return false
	}
	seen := make(map[string]bool, len(voided))
	for _, id := range voided {
		if id == healthyID || seen[id] {
			return false
		}
		seen[id] = true
	}
	for _, rec := range admitted[1:] {
		if !seen[rec.InvocationID] {
			return false
		}
	}
	return true
}

func TestOpenCircuitClosesUndispatchedAdmission(t *testing.T) {
	for name, scope := range map[string]circuit.Scope{"global": circuit.ScopeGlobal, "per_endpoint": circuit.ScopePerEndpoint} {
		for _, transport := range []string{"buffered", "stream"} {
			t.Run(name+"/"+transport, func(t *testing.T) {
				upstream := newRT03Upstream(t, nil)
				models := stubModelResolver{
					"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: upstream.srv.URL, Enabled: true},
				}
				gw := circuitGateway(t, upstream.srv.URL, models, scope, 1)
				store := &fakeInvocationStore{}
				gw.invocations = store
				rec := rt02Post(t, gw, rt03ChatBody, nil)
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				require.Equal(t, 1, upstream.totalCalls(), "the healthy call contacted the provider exactly once")
				require.Len(t, store.admitted, 1)
				require.Len(t, store.facts, 1)
				key := circuit.GlobalBreakerKey
				if scope == circuit.ScopePerEndpoint {
					key = circuit.EndpointKey(upstream.srv.URL)
				}
				gw.circuits.RecordFailure(key)
				probe := rt03ChatBody
				if transport == "stream" {
					probe = strings.Replace(probe, "{", `{"stream":true,`, 1)
				}
				rec = rt02Post(t, gw, probe, nil)
				if transport == "stream" {
					require.Equal(t, http.StatusOK, rec.Code)
					require.Contains(t, rec.Body.String(), "service_unavailable_error")
				} else {
					require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
				}
				require.Equal(t, 1, upstream.totalCalls(), "entry refusal contacted provider")
				require.Len(t, store.facts, 1, "entry refusal added a terminal charge")
				require.True(t, refusalAdmissionsClosed(store.admitted, store.voided, store.admitted[0].InvocationID),
					"breaker refusal must close its admission exactly: %d admissions, voided %v", len(store.admitted), store.voided)
			})
		}
	}
}

// TestRefusalAdmissionsClosed is the focused negative for the oracle
// predicate: both valid arms (the ordinary admitted-then-voided refusal and
// the correct zero-start early rejection) pass, and every audited defect —
// duplicate starts, repeated void of only the first identity, substitution
// or reuse of the dispatched identity, missing and spurious voids — is
// rejected.
func TestRefusalAdmissionsClosed(t *testing.T) {
	cases := []struct {
		name     string
		admitted []admissionRecord
		voided   []string
		want     bool
	}{
		{
			name:     "ordinary admitted-then-voided refusal",
			admitted: []admissionRecord{{InvocationID: "dispatched"}, {InvocationID: "refused"}},
			voided:   []string{"refused"},
			want:     true,
		},
		{
			name:     "correct zero-start early rejection",
			admitted: []admissionRecord{{InvocationID: "dispatched"}},
			want:     true,
		},
		{
			name:     "duplicate admission starts for one refusal",
			admitted: []admissionRecord{{InvocationID: "dispatched"}, {InvocationID: "first"}, {InvocationID: "second"}},
			voided:   []string{"first", "second"},
			want:     false,
		},
		{
			name:     "two distinct extra starts with two voids of only the first",
			admitted: []admissionRecord{{InvocationID: "dispatched"}, {InvocationID: "first"}, {InvocationID: "second"}},
			voided:   []string{"first", "first"},
			want:     false,
		},
		{
			name:     "void substitutes the dispatched identity",
			admitted: []admissionRecord{{InvocationID: "dispatched"}, {InvocationID: "refused"}},
			voided:   []string{"dispatched"},
			want:     false,
		},
		{
			name:     "extra start reuses the dispatched identity with a matching void",
			admitted: []admissionRecord{{InvocationID: "dispatched"}, {InvocationID: "dispatched"}},
			voided:   []string{"dispatched"},
			want:     false,
		},
		{
			name:     "missing void leaves the refusal start durable",
			admitted: []admissionRecord{{InvocationID: "dispatched"}, {InvocationID: "refused"}},
			want:     false,
		},
		{
			name:     "spurious void without any start",
			admitted: []admissionRecord{{InvocationID: "dispatched"}},
			voided:   []string{"ghost"},
			want:     false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, refusalAdmissionsClosed(tc.admitted, tc.voided, "dispatched"),
				"admitted %+v voided %v", tc.admitted, tc.voided)
		})
	}
}

func TestOpenFallbackPreservesDispatchedAdmission(t *testing.T) {
	primary := newRT03Upstream(t, func(rt03Call) rt03Response { return rt03Down() })
	fallback := newRT03Upstream(t, nil)
	models := stubModelResolver{
		"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: primary.srv.URL, Enabled: true, FailoverModels: []string{"f1"}},
		"f1": {ModelName: "f1", Provider: "openai", UpstreamURL: fallback.srv.URL, Enabled: true},
	}
	gw := circuitGateway(t, primary.srv.URL, models, circuit.ScopePerEndpoint, 1)
	store := &fakeInvocationStore{}
	gw.invocations = store
	gw.circuits.RecordFailure(circuit.EndpointKey(fallback.srv.URL))
	rec := rt02Post(t, gw, rt03ChatBody, nil)
	require.GreaterOrEqual(t, rec.Code, 500)
	require.Equal(t, 1, primary.totalCalls())
	require.Zero(t, fallback.totalCalls())
	require.Len(t, store.admitted, 1)
	require.Empty(t, store.voided, "a fallback's open breaker must never void a real primary dispatch")
}

type disconnectedVoidStore struct {
	fakeInvocationStore
	attempts []string
}

func (s *disconnectedVoidStore) VoidInvocation(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.attempts = append(s.attempts, id)
	if len(s.attempts) == 1 {
		return io.ErrUnexpectedEOF
	}
	return s.fakeInvocationStore.VoidInvocation(ctx, id)
}

func TestVoidUndispatchedSurvivesClientAndStoreDisconnect(t *testing.T) {
	store := new(disconnectedVoidStore)
	gw := &gateway{invocations: store}
	id := newTestIdentity()
	ctx, cancel := context.WithCancel(withInvocationIdentity(t.Context(), id))
	require.NoError(t, id.beginPaidDispatch(ctx, store, invocationKindChat))
	cancel()
	gw.voidUndispatchedInvocation(ctx, testLogger())
	require.Equal(t, []string{id.ID(), id.ID()}, store.attempts)
	require.Equal(t, []string{id.ID()}, store.voided)
	require.Empty(t, store.facts)
}
