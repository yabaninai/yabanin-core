package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// shadowTestStore embeds the package's full mock (satisfies StoreInterface)
// and overrides only GetShadowComparison.
type shadowTestStore struct {
	*mockStore
	comparison *adminstore.ShadowComparison
	err        error
	gotOrg     string
	gotDays    int
}

func (s *shadowTestStore) GetShadowComparison(_ context.Context, orgID string, days int) (*adminstore.ShadowComparison, error) {
	s.gotOrg, s.gotDays = orgID, days
	return s.comparison, s.err
}

func TestShadowComparisonHandler_OK(t *testing.T) {
	st := &shadowTestStore{mockStore: newMockStore(),
		comparison: &adminstore.ShadowComparison{
			Period:       "last_30_days",
			PrimaryModel: "gpt-4o-mini",
			ShadowModel:  "gpt-4o",
			Overlap:      120,
			DeltaPct:     -18.4,
			Verdict:      "cheaper",
			ByModel: []adminstore.ShadowModelCompare{{
				PrimaryModel: "gpt-4o-mini", ShadowModel: "gpt-4o",
				Overlap: 120, PrimaryAvgUSD: 0.001, ShadowAvgUSD: 0.0008,
				DeltaPct: -18.4, Verdict: "cheaper",
			}},
		},
	}
	h := &AdminHandlers{store: st}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/analytics/shadow?days=30&org_id=org-9", nil)
	w := httptest.NewRecorder()
	h.ShadowComparisonHandler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if st.gotOrg != "org-9" || st.gotDays != 30 {
		t.Errorf("store got org=%q days=%d, want org-9/30", st.gotOrg, st.gotDays)
	}
	var rep adminstore.ShadowComparison
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if rep.Verdict != "cheaper" || rep.Overlap != 120 {
		t.Errorf("rep = %+v", rep)
	}
}

func TestShadowComparisonHandler_Defaults(t *testing.T) {
	st := &shadowTestStore{mockStore: newMockStore(), comparison: &adminstore.ShadowComparison{Verdict: "insufficient_data"}}
	h := &AdminHandlers{store: st}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/analytics/shadow", nil)
	w := httptest.NewRecorder()
	h.ShadowComparisonHandler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if st.gotDays != 30 {
		t.Errorf("default days = %d, want 30", st.gotDays)
	}
	if st.gotOrg != "" {
		t.Errorf("org = %q, want empty", st.gotOrg)
	}
}

func TestShadowComparisonHandler_Error(t *testing.T) {
	st := &shadowTestStore{mockStore: newMockStore(), err: context.DeadlineExceeded}
	h := &AdminHandlers{store: st}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/analytics/shadow", nil)
	w := httptest.NewRecorder()
	h.ShadowComparisonHandler().ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}
