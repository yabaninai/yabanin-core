package builtins

import "context"

// contract above is unchanged). PartialsSourceFunc adapts an ordinary
// function to the PartialsSource seam, so wiring code can plug a store
// lookup without declaring a named type. The production source is the
// prompt-studio store: adminstore.Store.PartialsLookup(orgID) returns a
// value that satisfies this interface structurally (pkg/adminstore/
// promptstudio.go) and can be passed as the "source" param directly.

// PartialsSourceFunc is a function implementing PartialsSource.
type PartialsSourceFunc func(ctx context.Context, name string) (body string, found bool, err error)

// Get resolves one partial name (PartialsSource contract).
func (f PartialsSourceFunc) Get(ctx context.Context, name string) (string, bool, error) {
	return f(ctx, name)
}

// compile-time guard: the func adapter satisfies the seam.
var _ PartialsSource = PartialsSourceFunc(nil)
