package cli

// Owner-review regression (judge-boundary-review, result2.log): under race,
// a local KeyResolver failure produced one paid durable admission with ZERO
// HTTP arrivals — the confirmed start committed before the hop's fallible
// local setup. The start now commits inside call, immediately before the
// actual upstream Do; a never-dispatched local failure records no admission,
// no facts, and releases the reservation at zero spend. The healthy twin
// pins the paid contract: one admission, one same-ID facts row, 11/7 tokens.

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline/llmjudge"
	"github.com/stretchr/testify/require"
)

func TestIndependentJudgeLocalFailure(t *testing.T) {
	for _, failed := range []bool{false, true} {
		name := "healthy"
		if failed {
			name = "local_key_failure"
		}
		t.Run(name, func(t *testing.T) {
			up := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
			c, r := newJudgeHopClient(t, up, nil)
			store := &fakeInvocationStore{}
			c.invocations = store
			if failed {
				c.keys = llmjudge.KeyResolverFunc(func(context.Context, string, llmjudge.Target) (string, error) {
					return "", errors.New("synthetic local key lookup failure")
				})
			}
			_, err := c.JudgeChat(t.Context(), r)
			if failed {
				require.ErrorContains(t, err, "local key lookup failure")
				require.Zero(t, up.hits.Load())
				require.Empty(t, store.admitted, "local setup failure recorded a paid-dispatch start")
				require.Empty(t, store.facts)
				return
			}
			require.NoError(t, err)
			require.EqualValues(t, 1, up.hits.Load())
			require.Len(t, store.admitted, 1)
			require.Len(t, store.facts, 1)
			require.Equal(t, store.admitted[0].InvocationID, store.facts[0].InvocationID)
			require.Equal(t, "11", store.facts[0].Fields["tokens_in"])
			require.Equal(t, "7", store.facts[0].Fields["tokens_out"])
		})
	}
}
