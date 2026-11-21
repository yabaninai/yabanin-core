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
				require.Equal(t, 1, upstream.totalCalls())
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
				require.Len(t, store.voided, len(store.admitted)-1, "proven non-dispatch left a durable start open")
				if len(store.voided) > 0 {
					require.Equal(t, store.admitted[1].InvocationID, store.voided[0])
				}
			})
		}
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
