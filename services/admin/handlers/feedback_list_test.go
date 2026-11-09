package handlers

// W-FEED: unit tests for the root-only owner feedback surface (list + CSV
// export) over a stub lister — the store/query behavior is covered by the
// pkg/feedback integration tests, the guarding by the routes golden.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/feedback"
)

type stubFeedbackLister struct {
	captured feedback.ListFilter
	page     feedback.ListPage
	err      error
}

func (s *stubFeedbackLister) ListFeedback(_ context.Context, filter feedback.ListFilter) (feedback.ListPage, error) {
	s.captured = filter
	if s.err != nil {
		return feedback.ListPage{}, s.err
	}
	return s.page, nil
}

func feedbackListHarness(tb testing.TB, lister FeedbackLister) *AdminHandlers {
	tb.Helper()
	h := New(newMockStore(), "test-session-key", "feedback.test", nil)
	if lister != nil {
		h.SetFeedbackLister(lister)
	}
	tb.Cleanup(h.Stop)
	return h
}

func TestListFeedbackHandlerUnwiredAnswers503(t *testing.T) {
	h := feedbackListHarness(t, nil)

	rec := httptest.NewRecorder()
	h.ListFeedbackHandler().ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/feedback", nil))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	rec = httptest.NewRecorder()
	h.ExportFeedbackHandler().ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/feedback/export", nil))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestListFeedbackHandlerReturnsPage(t *testing.T) {
	stub := &stubFeedbackLister{page: feedback.ListPage{
		Entries: []feedback.Entry{{
			ID:            7,
			OrgID:         "org-a",
			RequestID:     "req-1",
			PromptHash:    "abc",
			OriginalClass: "easy",
			Action:        "thumbs_down",
			CreatedAt:     time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC),
		}},
		Total:    1,
		Page:     2,
		PageSize: 50,
	}}
	h := feedbackListHarness(t, stub)

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/feedback?org_id=org-a&rating=thumbs_down&page=2&page_size=50", nil)
	h.ListFeedbackHandler().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "org-a", stub.captured.OrgID)
	assert.Equal(t, "thumbs_down", stub.captured.Action)
	assert.Equal(t, 2, stub.captured.Page)

	var got feedback.ListPage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Len(t, got.Entries, 1)
	assert.Equal(t, "req-1", got.Entries[0].RequestID)
	assert.Equal(t, int64(1), got.Total)
}

func TestListFeedbackHandlerInvalidRatingAndPageAre400(t *testing.T) {
	h := feedbackListHarness(t, &stubFeedbackLister{})

	for _, query := range []string{"?rating=star", "?page=0", "?page=nope", "?page_size=-3"} {
		rec := httptest.NewRecorder()
		h.ListFeedbackHandler().ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/feedback"+query, nil))
		assert.Equal(t, http.StatusBadRequest, rec.Code, "query %s", query)
	}
}

func TestListFeedbackHandlerListerFailureIs500(t *testing.T) {
	h := feedbackListHarness(t, &stubFeedbackLister{err: errors.New("db down")})

	rec := httptest.NewRecorder()
	h.ListFeedbackHandler().ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/feedback", nil))
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestExportFeedbackHandlerServesCSV(t *testing.T) {
	stub := &stubFeedbackLister{page: feedback.ListPage{
		Entries: []feedback.Entry{{
			ID:            3,
			OrgID:         "org-b",
			RequestID:     "req,2",
			PromptHash:    "hash\"1",
			OriginalClass: "hard",
			Action:        "regenerate",
			CreatedAt:     time.Date(2026, 10, 5, 8, 30, 0, 0, time.UTC),
		}},
		Total: 1,
		Page:  1,
	}}
	h := feedbackListHarness(t, stub)

	rec := httptest.NewRecorder()
	h.ExportFeedbackHandler().ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/feedback/export?org_id=org-b", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/csv")
	assert.Contains(t, rec.Header().Get("Content-Disposition"), "attachment; filename=feedback-")

	body := rec.Body.String()
	lines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	require.Len(t, lines, 2)
	assert.Equal(t, "id,org_id,request_id,prompt_hash,original_class,action,created_at", lines[0])
	// RFC 4180 quoting: the comma and quote in fixture values must survive
	// a round trip through any CSV parser.
	assert.Equal(t, `3,org-b,"req,2","hash""1",hard,regenerate,2026-10-05T08:30:00Z`, lines[1])
}
