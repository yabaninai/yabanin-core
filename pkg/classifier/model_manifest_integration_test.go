package classifier

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration_MLService_ConsumerBindsModelProvenance exercises the
// consumer entry point named by the packet contract: NewMLClassifier against
// an isolated synthetic stand of the FastAPI ml_v1 service (deploy/classifier
// serving bge-small-en-v1.5 + 3-class head), composed exactly as
// pkg/gateway wireClassifier wires it (circuit breaker → registry → rule-tier
// fallback). The weights that very service serves are the ones
// ModelProvenance documents, so the manifest must validate at the same
// boundary.
func TestIntegration_MLService_ConsumerBindsModelProvenance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/health":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/classify":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"class_name": "medium",
				"confidence": 0.82,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	ml := NewMLClassifier(server.URL, slog.Default())
	assert.Equal(t, "ml_v1", ml.Name())
	assert.Equal(t, string(SourceMLV1), ml.Name())
	require.NoError(t, ml.HealthCheck(context.Background()), "synthetic ml_v1 stand health endpoint")

	res, err := ml.Classify(context.Background(), Input{
		Prompt: "integration synthetic prompt",
		OrgID:  "org-r003-integration",
	})
	require.NoError(t, err, "synthetic ml_v1 stand classify")
	assert.Equal(t, ClassMedium, res.Class)
	assert.Equal(t, string(SourceMLV1), res.Source)
	assert.Greater(t, res.Confidence, 0.0)

	primary := NewRegistryClassifier(NewRegistry(
		NewCircuitBreakerClassifier(ml, NewCircuitBreaker(3, 30*time.Second, 1)),
		NewRuleTier(),
	))
	viaPrimary, err := primary.Classify(context.Background(), Input{
		Prompt: "integration synthetic prompt",
		OrgID:  "org-r003-integration",
	})
	require.NoError(t, err, "classification through the gateway composition")
	assert.Equal(t, string(SourceMLV1), viaPrimary.Source)

	prov := ModelProvenance()
	require.NoError(t, prov.Validate(), "the encoder weights the ml_v1 service serves must carry confirmed rights")
	assert.Equal(t, "BAAI/bge-small-en-v1.5", prov.ID, "encoder documented for the ml_v1 service")
}
