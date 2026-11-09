package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// qualityTestStore embeds the package's full mock (satisfies StoreInterface)
// and overrides only GetQualityScores, capturing the org + window.
type qualityTestStore struct {
	*mockStore
	report  *adminstore.QualityReport
	err     error
	gotOrg  string
	gotFrom time.Time
	gotTo   time.Time
}

func (s *qualityTestStore) GetQualityScores(_ context.Context, orgID string, from, to time.Time) (*adminstore.QualityReport, error) {
	s.gotOrg, s.gotFrom, s.gotTo = orgID, from, to
	return s.report, s.err
}

func TestQualityScoresHandler_OK(t *testing.T) {
	st := &qualityTestStore{
		mockStore: newMockStore(),
		report: &adminstore.QualityReport{
			Verdict:       "has_data",
			TotalVerdicts: 200,
			ByModel: []adminstore.QualityModelScore{
				{PrimaryModel: "glm-5.3", ShadowModel: "qwen-local", Verdicts: 200,
					CheapQuality: 0.55, PremiumQuality: 0.85, UpgradeRate: 0.7},
			},
			Recommendation: &adminstore.QualityRecommendation{
				HasRecommendation: true, PrimaryModel: "glm-5.3", ShadowModel: "qwen-local",
				MatchExpr: `model_requested == "glm-5.3"`, TargetModel: "qwen-local", Priority: 50,
			},
		},
	}
	h := &AdminHandlers{store: st}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/analytics/quality?days=30&org_id=org-9", nil)
	w := httptest.NewRecorder()
	h.QualityScoresHandler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if st.gotOrg != "org-9" {
		t.Errorf("store got org=%q, want org-9", st.gotOrg)
	}
	// The window spans ~days back from now.
	if d := st.gotTo.Sub(st.gotFrom); d < 29*24*time.Hour || d > 31*24*time.Hour {
		t.Errorf("window = %v, want ~30d", d)
	}
	var rep adminstore.QualityReport
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if rep.Verdict != "has_data" || rep.TotalVerdicts != 200 {
		t.Errorf("rep = %+v", rep)
	}
	if rep.Recommendation == nil || !rep.Recommendation.HasRecommendation {
		t.Errorf("expected a recommendation, got %+v", rep.Recommendation)
	}
}

func TestQualityScoresHandler_Defaults(t *testing.T) {
	st := &qualityTestStore{mockStore: newMockStore(), report: &adminstore.QualityReport{Verdict: "insufficient_data"}}
	h := &AdminHandlers{store: st}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/analytics/quality", nil)
	w := httptest.NewRecorder()
	h.QualityScoresHandler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if st.gotOrg != "" {
		t.Errorf("org = %q, want empty", st.gotOrg)
	}
	if d := st.gotTo.Sub(st.gotFrom); d < 29*24*time.Hour || d > 31*24*time.Hour {
		t.Errorf("default window = %v, want ~30d", d)
	}
}

func TestQualityScoresHandler_Error(t *testing.T) {
	st := &qualityTestStore{mockStore: newMockStore(), err: context.DeadlineExceeded}
	h := &AdminHandlers{store: st}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/analytics/quality", nil)
	w := httptest.NewRecorder()
	h.QualityScoresHandler().ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestQualityScoresHandler_NilStore(t *testing.T) {
	h := &AdminHandlers{}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/analytics/quality", nil)
	w := httptest.NewRecorder()
	h.QualityScoresHandler().ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 with nil store", w.Code)
	}
}
