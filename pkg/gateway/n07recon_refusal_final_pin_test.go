package cli

import (
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/router"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// n07reconNoRefusalRetryPolicy returns a MaxAttempts-3 policy whose
// classifier counts consultations and FAILS the test if it is ever asked to
// judge a refusal-shaped outcome: a deterministic adapter refusal is final
// (CONTRACT §1), so the retry classifier must never be armed with one.
func n07reconNoRefusalRetryPolicy(t *testing.T, counter *atomic.Int64) retry.Policy {
	t.Helper()
	return retry.Policy{
		MaxAttempts:  3,
		BaseDelay:    time.Nanosecond,
		MaxDelay:     time.Nanosecond,
		JitterFactor: 0,
		RetryOn: func(statusCode int, err error) bool {
			if err != nil {
				var policyErr *router.PolicyError
				var ufe *provider.UnsupportedFeatureError
				if errors.As(err, &policyErr) || errors.As(err, &ufe) {
					t.Errorf("retry classifier consulted on a refusal-shaped outcome (status %d, err %v) — a refusal is final", statusCode, err)
				}
			}
			counter.Add(1)
			return retry.DefaultClassifier(statusCode, err)
		},
	}
}

// N07-RECON F3 pin: an adapter refusal riding the terminal capability
// carrier (400 invalid_request_error + capability_not_supported, proven
// before any byte left the process) is FINAL — the per-model retry loop must
// not re-invoke the attempt. Before the chatRetryPolicy guard the carrier
// fell through to DefaultClassifier (err != nil → retryable), so the loop
// re-armed the classifier three times under MaxAttempts: 3 and recomputed the
// identical refusal (w4c-04 review finding F3: the CONTRACT §1 "no retry"
// invariant was vacuous — nothing observed it; network, failover and
// accounting stayed correct, the refusal result was simply recomputed).
func TestN07Recon_RefusalCarrier_IsFinal_NoSameModelRetry(t *testing.T) {
	srv, calls, _ := t02JSONUpstream(t)
	gw := streamTestGateway(srv.URL)
	t02Registry(t, gw, srv.URL, map[string]resolver.ModelInfo{
		"m1": {Provider: "bedrock"},
	})
	var classifyCalls atomic.Int64
	gw.retryPolicy = n07reconNoRefusalRetryPolicy(t, &classifyCalls)

	rec := t02ChatRequest(t, gw, `{"model":"m1","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"f","parameters":{"type":"object","properties":{}}}}]}`, false)

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Equal(t, "capability_not_supported", n07p6t02ErrorCode(t, rec))
	assert.Contains(t, rec.Body.String(), "tools/tool_choice are not supported yet")
	assert.Zero(t, classifyCalls.Load(),
		"a deterministic refusal is final: the retry classifier must never be consulted on it")
	assert.Zero(t, calls.Load(), "the refusal is pre-flight: no upstream dial")
}

// Companion pin (survives before and after the F3 guard): a typed
// unsupported-feature refusal under the same MaxAttempts: 3 policy renders
// the full 400 unsupported_feature envelope and never reaches the retry
// classifier at all — the unknown-outcome attempt is refused by MayRepeat
// before the classifier is asked.
func TestN07Recon_UnsupportedFeature_UnderRetryPolicy_TypedEnvelopeOnce(t *testing.T) {
	srv, calls, _ := t02JSONUpstream(t)
	gw := streamTestGateway(srv.URL)
	t02Registry(t, gw, srv.URL, map[string]resolver.ModelInfo{
		"m1": {Provider: "bedrock"},
	})
	var classifyCalls atomic.Int64
	gw.retryPolicy = n07reconNoRefusalRetryPolicy(t, &classifyCalls)

	body := `{"model":"m1","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.invalid/y.png"}}]}]}`
	rec := t02ChatRequest(t, gw, body, false)

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Equal(t, "unsupported_feature", n07p6t02ErrorCode(t, rec))
	assert.Contains(t, rec.Body.String(), "image inputs are not supported yet")
	assert.Zero(t, classifyCalls.Load(),
		"the typed refusal carries unknown-outcome safety: MayRepeat refuses it before the classifier is consulted")
	assert.Zero(t, calls.Load(), "the refusal is pre-flight: no upstream dial")
}

// Unit pin on the guard itself: chatRetryPolicy must refuse refusal-shaped
// outcomes outright (terminal capability carrier, typed unsupported-feature
// rejection) and delegate everything else to the configured classifier.
func TestN07Recon_ChatRetryPolicy_RefusalShapesAreTerminal(t *testing.T) {
	var delegated atomic.Int64
	base := retry.Policy{
		MaxAttempts: 3,
		RetryOn: func(statusCode int, err error) bool {
			delegated.Add(1)
			return retry.DefaultClassifier(statusCode, err)
		},
	}
	policy := chatRetryPolicy(base)

	// Refusal shapes: terminal, never delegated.
	assert.False(t, policy.RetryOn(http.StatusBadRequest, &router.PolicyError{
		Status:  http.StatusBadRequest,
		ErrType: "invalid_request_error",
		ErrCode: "capability_not_supported",
		Message: "refusal",
	}), "the terminal capability carrier must not be retryable")
	assert.False(t, policy.RetryOn(0, &retry.RequestNotSentError{
		Err: &provider.UnsupportedFeatureError{Provider: "bedrock", Reason: "media"},
	}), "a typed unsupported-feature rejection must not be retryable")
	assert.Zero(t, delegated.Load(), "refusal shapes must be answered by the guard itself")

	// Non-refusal outcomes: delegate unchanged (DefaultClassifier semantics:
	// any non-nil error is retryable — including a plain 4xx error, which is
	// exactly why refusal shapes must be answered by the guard itself).
	assert.True(t, policy.RetryOn(http.StatusTooManyRequests, nil), "429 stays retryable")
	assert.True(t, policy.RetryOn(0, assert.AnError), "transport errors stay retryable")
	assert.True(t, policy.RetryOn(http.StatusBadRequest, assert.AnError),
		"non-refusal outcomes delegate unchanged (DefaultClassifier: err != nil is retryable)")
	assert.Equal(t, int64(3), delegated.Load(), "every non-refusal consultation reaches the configured classifier")
}
