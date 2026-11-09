package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

//   - gateway_jwt_validations_total{outcome="ok"} — tokens that passed the
//     full validation chain (signature, iss/aud/exp/nbf, org claim);
//   - gateway_jwt_errors_total{reason=...} — every rejected token or JWKS
//     failure, classified by reason (signature, alg, unknown_kid, issuer,
//     audience, expired, not_yet_valid, org_claim, jwks_unavailable, form).
//
// No claim values, subjects, org ids or key ids are ever label values.
var (
	GatewayJWTValidationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "jwt_validations_total",
			Help:      "Gateway bearer JWT validations by outcome (ok only; rejections are in jwt_errors_total).",
		},
		[]string{"outcome"},
	)

	GatewayJWTErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "jwt_errors_total",
			Help:      "Gateway bearer JWT rejections and JWKS failures by reason.",
		},
		[]string{"reason"},
	)
)

var jwtCollectors = []prometheus.Collector{
	GatewayJWTValidationsTotal,
	GatewayJWTErrorsTotal,
}

func init() {
	allCollectors = append(allCollectors, jwtCollectors...)
}
