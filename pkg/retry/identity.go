package retry

import "context"

// RequestIdentity is the stable identity of one client request, carried
// unchanged across every attempt of that request — every retry-loop pass and
// every fallback-chain hop. It is minted once at the API boundary and never
// re-derived per attempt: an upstream deduplication contract (IdempotencyProof)
// can only recognize a repeated operation when every attempt presents the same
// identity, and per-attempt usage records join on it. Re-minting the identity
// per attempt would silently defeat both.
type RequestIdentity struct {
	// RequestID is the gateway-assigned request identifier. It is the join
	// key between every attempt of one client request — including attempts
	// served by different providers after a fallback — and the usage and
	// attribution rows derived from them.
	RequestID string
	// IdempotencyKey is the optional upstream deduplication key handed to
	// providers that advertise a dedup contract. The same value must reach
	// every attempt of the request: a per-attempt key would defeat the very
	// contract it is meant to satisfy.
	IdempotencyKey string
}

type identityCtxKey struct{}

// WithRequestIdentity returns a context carrying id for the request lifetime.
// Attempt closures read it via RequestIdentityFrom to present the same
// identity to every upstream call; the fallback executor reads it to stamp
// every attempt-trace entry. Empty fields stay empty — nothing here invents
// identity. The parent context is never modified.
func WithRequestIdentity(ctx context.Context, id RequestIdentity) context.Context {
	return context.WithValue(ctx, identityCtxKey{}, id)
}

// RequestIdentityFrom returns the request identity carried in ctx (the zero
// value when none was attached). A nil ctx returns the zero value.
func RequestIdentityFrom(ctx context.Context) RequestIdentity {
	if ctx == nil {
		return RequestIdentity{}
	}
	id, _ := ctx.Value(identityCtxKey{}).(RequestIdentity)
	return id
}
