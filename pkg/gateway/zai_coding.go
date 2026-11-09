package cli

import (
	"net/http"

	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/resolver"
)

const zaiCodingProvider = "zai-coding"

func (gw *gateway) zaiCodingEndpoint() string {
	return provider.ZAICodingEndpoint(gw.cfg.ZAICodingBaseURL)
}

func (gw *gateway) upstreamURL(mi resolver.ModelInfo) string {
	if mi.Provider == zaiCodingProvider {
		return gw.zaiCodingEndpoint()
	}
	if mi.UpstreamURL != "" {
		return mi.UpstreamURL
	}
	return gw.cfg.Provider
}

// zaiCodingViolation is the non-writing Z.AI Coding Plan / data-boundary
// contract, applied by the RT-02 final-candidate gate (candidate_gate.go) on
// every path — chat JSON/SSE and all non-chat endpoints — after routing has
// chosen the candidate. blocked is false when the candidate is allowed;
// otherwise the gateResult carries the exact pre-existing wire contract
// (403 provider_not_authorized when the plan is disabled, 400
// unsupported_feature when the model is outside the allowlist).
func zaiCodingViolation(enabled bool, requestedModel string, info resolver.ModelInfo) (gateResult, bool) {
	if info.Provider != zaiCodingProvider {
		return gateResult{Outcome: gateAllowed}, false
	}
	if !enabled {
		return gateResult{
			Outcome: gateDenied,
			Status:  http.StatusForbidden,
			ErrType: apierrors.ErrorCodePermissionDenied,
			ErrCode: apierrors.CodeProviderNotAuthorized,
			Message: "Z.AI Coding Plan is disabled on this gateway",
		}, true
	}
	if provider.ZAICodingModelAllowed(requestedModel) || provider.ZAICodingModelAllowed(info.ModelName) {
		return gateResult{Outcome: gateAllowed}, false
	}
	return gateResult{
		Outcome: gateDenied,
		Status:  http.StatusBadRequest,
		ErrType: apierrors.ErrorCodeInvalidRequest,
		ErrCode: apierrors.CodeUnsupportedFeature,
		Message: "model is not in the Z.AI Coding Plan allowlist",
	}, true
}

func (gw *gateway) mapProviderUpstream(providerName string, lastCode int, lastErr error) (status int, errType, code, message string) {
	message = "upstream provider unavailable"
	if providerName == zaiCodingProvider && lastCode >= 400 {
		status, errType, code = provider.MapZAICodingStatus(lastCode)
		switch code {
		case apierrors.CodeProviderNotAuthorized:
			message = "Z.AI Coding Plan is not authorized for this credential"
		case apierrors.CodeQuotaExhausted:
			message = "Z.AI Coding Plan quota exhausted"
		}
		return status, errType, code, message
	}
	status, errType = mapUpstreamError(lastErr)
	if lastCode >= 400 {
		status, errType = apierrors.MapUpstreamStatus(lastCode)
	}
	return status, errType, "", message
}

func allowedUpstreamsForGateway(allowed []string, zaiEnabled bool, zaiEndpoint, providerURL string) []string {
	// Empty operator list is not "everything allowed": the default grants
	// egress to exactly the explicitly configured provider origin. Any other
	// destination (including redirect targets) stays refused until an
	// operator approves it. A non-empty list keeps its strict meaning — the
	// provider origin must already be listed by the operator.
	if len(allowed) == 0 {
		if providerURL == "" {
			return nil
		}
		allowed = []string{providerURL}
	}
	if !zaiEnabled {
		return allowed
	}
	out := make([]string, len(allowed), len(allowed)+1)
	copy(out, allowed)
	return append(out, zaiEndpoint)
}
