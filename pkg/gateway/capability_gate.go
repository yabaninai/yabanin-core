package cli

import (
	"net/http"

	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/router"
)

// Adapter capability refusals (provider.CapabilityError) are client-shaped
// refusals, not upstream failures: the adapter proved the requested feature
// cannot be served BEFORE any request byte left the gateway. capabilityPolicy
// renders the refusal as the terminal policy error the fallback executor and
// the JSON/SSE terminal handlers already consume: 400 invalid_request_error
// with the stable capability_not_supported code and the adapter's precise
// message.
//
// The carrier is chain-terminal — no transport retry, no failover to another
// model (a refusal must never silently downgrade the capability away), no
// circuit-breaker penalty, no credential quarantine, and no upstream
// accounting (nothing was sent).
func capabilityPolicy(capErr *provider.CapabilityError) *router.PolicyError {
	return &router.PolicyError{
		Status:  http.StatusBadRequest,
		ErrType: apierrors.ErrorCodeInvalidRequest,
		ErrCode: apierrors.CodeCapabilityNotSupported,
		Message: capErr.Error(),
	}
}
