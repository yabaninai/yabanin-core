package router_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/router"
)

// fakeResolver stubs resolver.Resolver by returning a preset ModelInfo per
// model name (so we can build failover chains without a DB).
type fakeResolver struct {
	byName map[string]resolver.ModelInfo
}

func newFakeResolver(entries map[string]resolver.ModelInfo) *fakeResolver {
	if entries == nil {
		entries = map[string]resolver.ModelInfo{}
	}
	return &fakeResolver{byName: entries}
}

func (f *fakeResolver) Resolve(_ context.Context, name string) resolver.ModelInfo {
	if info, ok := f.byName[name]; ok {
		return info
	}
	return resolver.ModelInfo{ModelName: name}
}

// compile-time check: *fakeResolver satisfies router.ModelResolver.
var _ router.ModelResolver = (*fakeResolver)(nil)

func TestFallback_PrimarySuccess_NoFallback(t *testing.T) {
	primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"secondary"}}
	res := newFakeResolver(nil)
	fe := router.NewFallbackExecutor(res, 3, nil)

	var calls []string
	final, code, attempts, err := fe.Execute(context.Background(), primary,
		func(_ context.Context, info resolver.ModelInfo) (int, error) {
			calls = append(calls, info.ModelName)
			return 200, nil
		})

	require.NoError(t, err)
	assert.Equal(t, 200, code)
	assert.Equal(t, "primary", final.ModelName)
	assert.Equal(t, []string{"primary"}, calls)
	require.Len(t, attempts, 1)
	assert.True(t, attempts[0].Success)
}

func TestFallback_Primary5xx_SecondarySuccess(t *testing.T) {
	primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"secondary"}}
	secondary := resolver.ModelInfo{ModelName: "secondary"}
	res := newFakeResolver(map[string]resolver.ModelInfo{"secondary": secondary})
	fe := router.NewFallbackExecutor(res, 3, nil)

	var calls []string
	final, code, attempts, err := fe.Execute(context.Background(), primary,
		func(_ context.Context, info resolver.ModelInfo) (int, error) {
			calls = append(calls, info.ModelName)
			if info.ModelName == "primary" {
				return 503, errors.New("upstream error 503")
			}
			return 200, nil
		})

	require.NoError(t, err)
	assert.Equal(t, 200, code)
	assert.Equal(t, "secondary", final.ModelName)
	assert.Equal(t, []string{"primary", "secondary"}, calls)
	require.Len(t, attempts, 2)
	assert.False(t, attempts[0].Success)
	assert.True(t, attempts[1].Success)
}

func TestFallback_AllFail_LastErrorReturned(t *testing.T) {
	primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"secondary", "tertiary"}}
	res := newFakeResolver(map[string]resolver.ModelInfo{
		"secondary": {ModelName: "secondary"},
		"tertiary":  {ModelName: "tertiary"},
	})
	fe := router.NewFallbackExecutor(res, 3, nil)

	final, code, attempts, err := fe.Execute(context.Background(), primary,
		func(_ context.Context, info resolver.ModelInfo) (int, error) {
			return 503, errors.New("boom")
		})

	require.Error(t, err)
	assert.Equal(t, 503, code)
	assert.Equal(t, "tertiary", final.ModelName)
	require.Len(t, attempts, 3)
	for _, a := range attempts {
		assert.False(t, a.Success)
	}
}

func TestFallback_4xx_NotRetryable_ImmediateReturn(t *testing.T) {
	primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"secondary"}}
	res := newFakeResolver(nil)
	fe := router.NewFallbackExecutor(res, 3, nil)

	var calls []string
	_, code, attempts, _ := fe.Execute(context.Background(), primary,
		func(_ context.Context, info resolver.ModelInfo) (int, error) {
			calls = append(calls, info.ModelName)
			return 400, nil
		})

	assert.Equal(t, 400, code)
	assert.Equal(t, []string{"primary"}, calls)
	require.Len(t, attempts, 1)
}

func TestFallback_MaxHopsRespected(t *testing.T) {
	primary := resolver.ModelInfo{ModelName: "m0", FailoverModels: []string{"m1", "m2", "m3", "m4"}}
	fe := router.NewFallbackExecutor(nil, 3, nil) // maxHops = 3

	var calls []string
	_, _, attempts, _ := fe.Execute(context.Background(), primary,
		func(_ context.Context, info resolver.ModelInfo) (int, error) {
			calls = append(calls, info.ModelName)
			return 503, nil
		})

	assert.Len(t, calls, 3) // primary + 2 failovers
	require.Len(t, attempts, 3)
}

func TestFallback_NetworkErrorTriggersNext(t *testing.T) {
	primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"secondary"}}
	res := newFakeResolver(map[string]resolver.ModelInfo{"secondary": {ModelName: "secondary"}})
	fe := router.NewFallbackExecutor(res, 3, nil)

	var calls []string
	_, code, attempts, _ := fe.Execute(context.Background(), primary,
		func(_ context.Context, info resolver.ModelInfo) (int, error) {
			calls = append(calls, info.ModelName)
			if info.ModelName == "primary" {
				// A dial failure carries proof the request never left, so it
				// stays chain-advanceable. An error without that proof has an
				// unknown outcome and would end the chain instead.
				return 0, &net.OpError{Op: "dial", Err: errors.New("connect: connection refused")}
			}
			return 200, nil
		})

	assert.Equal(t, 200, code)
	assert.Equal(t, []string{"primary", "secondary"}, calls)
	require.Len(t, attempts, 2)
	assert.Equal(t, "not_executed", attempts[0].Outcome)
	assert.Equal(t, "executed", attempts[1].Outcome)
}

func TestFallback_NoFailoverModels_SingleAttempt(t *testing.T) {
	primary := resolver.ModelInfo{ModelName: "primary"}
	fe := router.NewFallbackExecutor(nil, 3, nil)

	var calls []string
	_, code, attempts, _ := fe.Execute(context.Background(), primary,
		func(_ context.Context, info resolver.ModelInfo) (int, error) {
			calls = append(calls, info.ModelName)
			return 500, nil
		})

	assert.Equal(t, 500, code)
	assert.Equal(t, []string{"primary"}, calls)
	require.Len(t, attempts, 1)
}

func TestFallback_ContextCancelStopsChain(t *testing.T) {
	primary := resolver.ModelInfo{ModelName: "m0", FailoverModels: []string{"m1", "m2"}}
	ctx, cancel := context.WithCancel(context.Background())

	var calls []string
	fe := router.NewFallbackExecutor(nil, 5, nil)
	cancel() // cancel before first call
	_, _, _, _ = fe.Execute(ctx, primary,
		func(_ context.Context, info resolver.ModelInfo) (int, error) {
			calls = append(calls, info.ModelName)
			return 503, nil
		})
	// Either zero attempts (if ctx already cancelled at first check) or one —
	// but never the full chain.
	assert.LessOrEqual(t, len(calls), 1)
}

func TestFallback_WithClassifierOverride(t *testing.T) {
	primary := resolver.ModelInfo{ModelName: "primary", FailoverModels: []string{"secondary"}}
	res := newFakeResolver(nil)
	fe := router.NewFallbackExecutor(res, 3, nil).
		WithClassifier(func(code int, err error) bool {
			return false // nothing retryable
		})

	var calls []string
	_, _, _, _ = fe.Execute(context.Background(), primary,
		func(_ context.Context, info resolver.ModelInfo) (int, error) {
			calls = append(calls, info.ModelName)
			return 503, nil // would normally retry; our classifier disagrees
		})

	assert.Equal(t, []string{"primary"}, calls, "custom classifier must stop the chain")
}

func TestFallback_AttemptsTracePopulated(t *testing.T) {
	primary := resolver.ModelInfo{
		ModelName:      "primary",
		UpstreamURL:    "https://primary.local",
		Provider:       "openai",
		FailoverModels: []string{"secondary"},
	}
	res := newFakeResolver(map[string]resolver.ModelInfo{
		"secondary": {ModelName: "secondary", UpstreamURL: "https://sec.local", Provider: "anthropic"},
	})
	fe := router.NewFallbackExecutor(res, 3, nil)

	_, _, attempts, _ := fe.Execute(context.Background(), primary,
		func(_ context.Context, info resolver.ModelInfo) (int, error) {
			if info.ModelName == "primary" {
				return 503, nil
			}
			return 200, nil
		})

	require.Len(t, attempts, 2)
	assert.Equal(t, "primary", attempts[0].ModelName)
	assert.Equal(t, "https://primary.local", attempts[0].UpstreamURL)
	assert.Equal(t, "openai", attempts[0].Provider)
	assert.False(t, attempts[0].Success)

	assert.Equal(t, "secondary", attempts[1].ModelName)
	assert.Equal(t, "anthropic", attempts[1].Provider)
	assert.True(t, attempts[1].Success)
}
