package cli

import (
	"context"
	"time"

	"github.com/reireirei/yabanin/pkg/labels"
)

type labelsCtxKey struct{}
type principalLabelsCtxKey struct{}
type principalCtxKey struct{}

// principal is the trusted key identity for later endpoints (AT-14).
type principal struct {
	APIKeyID          string
	AgentID           string
	CanMintSessions   bool
	CanReadUsage      bool
	SessionKeyID      string
	SessionMaxTokens  *int64
	SessionMaxCostUSD *float64
	SessionExpiresAt  time.Time
	// KeyExpiresAt mirrors auth.ResolveResult.KeyExpiresAt (AUTH-03): the
	// effective parent-key expiry. Session minting must not create a key
	// that outlives it. Zero means no expiry.
	KeyExpiresAt time.Time
}

func withPrincipal(ctx context.Context, p principal) context.Context {
	return context.WithValue(ctx, principalCtxKey{}, p)
}

func principalFrom(ctx context.Context) (principal, bool) {
	if ctx == nil {
		return principal{}, false
	}
	p, ok := ctx.Value(principalCtxKey{}).(principal)
	return p, ok
}

func withLabels(ctx context.Context, r labels.Result) context.Context {
	return context.WithValue(ctx, labelsCtxKey{}, r)
}

func labelsFrom(ctx context.Context) labels.Set {
	if ctx == nil {
		return labels.Set{}
	}
	res, _ := ctx.Value(labelsCtxKey{}).(labels.Result)
	if res.Labels == nil {
		return labels.Set{}
	}
	return res.Labels
}

func withPrincipalLabelSources(ctx context.Context, sources []labels.Source) context.Context {
	return context.WithValue(ctx, principalLabelsCtxKey{}, sources)
}

func principalLabelSources(ctx context.Context) []labels.Source {
	if ctx == nil {
		return nil
	}
	sources, _ := ctx.Value(principalLabelsCtxKey{}).([]labels.Source)
	return sources
}
