package handlers

// E06-P01 W03-C02: acceptance battery for the list endpoint's filter/sort
// query surface (severity exact match, inclusive confidence range, sort
// dictionary). Every invalid value must fail loud with 400; absent params
// keep the pre-W03-C02 behavior byte-for-byte.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/inbox"
)

// sifRow is one seeded fixture incident with full control of the W03-C02
// axes (severity, confidence, last_seen, id for deterministic tie-breaks).
func sifRow(t *testing.T, org uuid.UUID, id, sev string, conf float64, last time.Time) inbox.Incident {
	t.Helper()
	inc := siIncident(t, org, "evt-"+id, last)
	inc.ID = uuid.MustParse(id)
	inc.Severity = sev
	inc.Confidence = conf
	inc.LastSeen = last
	inc.FirstSeen = last
	return inc
}

// sifSeedRows installs a fixed 4-row spread covering every dictionary word,
// both range sides and distinct timestamps.
func sifSeedRows(t *testing.T, f *securityInboxFixture, org uuid.UUID) {
	t.Helper()
	base := time.Date(2026, 11, 8, 9, 0, 0, 0, time.UTC)
	rows := []inbox.Incident{
		sifRow(t, org, "00000000-0000-0000-0000-0000000000a1", inbox.SeverityHigh, 0.9, base.Add(3*time.Hour)),
		sifRow(t, org, "00000000-0000-0000-0000-0000000000a2", inbox.SeverityLow, 0.2, base.Add(1*time.Hour)),
		sifRow(t, org, "00000000-0000-0000-0000-0000000000a3", inbox.SeverityMedium, 0.75, base.Add(2*time.Hour)),
		sifRow(t, org, "00000000-0000-0000-0000-0000000000a4", inbox.SeverityHigh, 0.5, base),
	}
	f.rows[org] = rows
	for _, r := range rows {
		f.incidents[r.ID] = r
	}
}

// sifList drives the list endpoint with the admin-1 (org_admin) session and
// returns the decoded incident ids in response order.
func sifList(t *testing.T, get func(path string, cookie *http.Cookie, headerOrg string) *httptest.ResponseRecorder, org uuid.UUID, query string) []uuid.UUID {
	t.Helper()
	w := get("/api/organizations/"+org.String()+"/security-inbox"+query, siSessionCookie(t, "admin-1", false), "")
	var body struct {
		Data []struct {
			ID uuid.UUID `json:"id"`
		} `json:"data"`
	}
	if w.Code != http.StatusOK {
		t.Fatalf("list %q = %d, want 200 (body %s)", query, w.Code, w.Body.String())
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	ids := make([]uuid.UUID, 0, len(body.Data))
	for _, d := range body.Data {
		ids = append(ids, d.ID)
	}
	return ids
}

func TestSecurityInboxFiltersSeverity(t *testing.T) {
	orgA := uuid.New()
	f := newSecurityInboxFixture()
	siSeed(t, f, orgA)
	sifSeedRows(t, f, orgA)
	get := siServe(t, f)
	a1 := uuid.MustParse("00000000-0000-0000-0000-0000000000a1")
	a2 := uuid.MustParse("00000000-0000-0000-0000-0000000000a2")
	a3 := uuid.MustParse("00000000-0000-0000-0000-0000000000a3")
	a4 := uuid.MustParse("00000000-0000-0000-0000-0000000000a4")

	t.Run("exact dictionary match", func(t *testing.T) {
		ids := sifList(t, get, orgA, "?severity=high")
		require.Equal(t, []uuid.UUID{a1, a4}, ids) // newest first within the match
		ids = sifList(t, get, orgA, "?severity=medium")
		require.Equal(t, []uuid.UUID{a3}, ids)
	})

	t.Run("unknown word is 400", func(t *testing.T) {
		w := get("/api/organizations/"+orgA.String()+"/security-inbox?severity=critical", siSessionCookie(t, "admin-1", false), "")
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "severity")
	})

	t.Run("dictionary is case-sensitive", func(t *testing.T) {
		w := get("/api/organizations/"+orgA.String()+"/security-inbox?severity=HIGH", siSessionCookie(t, "admin-1", false), "")
		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("filter is exact, not substring", func(t *testing.T) {
		ids := sifList(t, get, orgA, "?severity=low")
		require.Equal(t, []uuid.UUID{a2}, ids)
	})
}

func TestSecurityInboxFiltersConfidenceRange(t *testing.T) {
	orgA := uuid.New()
	f := newSecurityInboxFixture()
	siSeed(t, f, orgA)
	sifSeedRows(t, f, orgA)
	get := siServe(t, f)

	t.Run("min bound is inclusive", func(t *testing.T) {
		ids := sifList(t, get, orgA, "?confidence_min=0.75")
		require.Len(t, ids, 2) // 0.9 and 0.75
	})

	t.Run("max bound is inclusive", func(t *testing.T) {
		ids := sifList(t, get, orgA, "?confidence_max=0.5")
		require.Len(t, ids, 2) // 0.2 and 0.5
	})

	t.Run("both bounds narrow exactly", func(t *testing.T) {
		ids := sifList(t, get, orgA, "?confidence_min=0.5&confidence_max=0.75")
		require.Len(t, ids, 2) // 0.5 and 0.75
	})

	t.Run("inverted range is 400", func(t *testing.T) {
		w := get("/api/organizations/"+orgA.String()+"/security-inbox?confidence_min=0.9&confidence_max=0.1", siSessionCookie(t, "admin-1", false), "")
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "confidence_min")
	})

	t.Run("non-numeric bound is 400", func(t *testing.T) {
		w := get("/api/organizations/"+orgA.String()+"/security-inbox?confidence_min=lots", siSessionCookie(t, "admin-1", false), "")
		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("bound outside [0,1] is 400", func(t *testing.T) {
		for _, q := range []string{"?confidence_min=1.5", "?confidence_max=-0.1"} {
			w := get("/api/organizations/"+orgA.String()+"/security-inbox"+q, siSessionCookie(t, "admin-1", false), "")
			require.Equal(t, http.StatusBadRequest, w.Code, "query %q", q)
		}
	})
}

func TestSecurityInboxFiltersSort(t *testing.T) {
	orgA := uuid.New()
	f := newSecurityInboxFixture()
	siSeed(t, f, orgA)
	sifSeedRows(t, f, orgA)
	get := siServe(t, f)
	a1 := uuid.MustParse("00000000-0000-0000-0000-0000000000a1")
	a2 := uuid.MustParse("00000000-0000-0000-0000-0000000000a2")
	a3 := uuid.MustParse("00000000-0000-0000-0000-0000000000a3")
	a4 := uuid.MustParse("00000000-0000-0000-0000-0000000000a4")

	t.Run("default is newest first (pre-W03-C02 behavior)", func(t *testing.T) {
		ids := sifList(t, get, orgA, "")
		require.Equal(t, []uuid.UUID{a1, a3, a2, a4}, ids)
	})

	t.Run("explicit last_seen matches the default", func(t *testing.T) {
		ids := sifList(t, get, orgA, "?sort=last_seen")
		require.Equal(t, []uuid.UUID{a1, a3, a2, a4}, ids)
	})

	t.Run("severity sorts worst first, ties by recency then id", func(t *testing.T) {
		// high(0.9, newest) then high(0.5, oldest) — severity equal, last_seen desc.
		ids := sifList(t, get, orgA, "?sort=severity")
		require.Equal(t, []uuid.UUID{a1, a4, a3, a2}, ids)
	})

	t.Run("confidence sorts highest first", func(t *testing.T) {
		ids := sifList(t, get, orgA, "?sort=confidence")
		require.Equal(t, []uuid.UUID{a1, a3, a4, a2}, ids)
	})

	t.Run("unknown sort key is 400", func(t *testing.T) {
		w := get("/api/organizations/"+orgA.String()+"/security-inbox?sort=priority", siSessionCookie(t, "admin-1", false), "")
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "sort")
	})

	t.Run("equal keys break deterministically by id", func(t *testing.T) {
		// Same confidence on two rows: id order must be stable across calls.
		base := time.Date(2026, 11, 8, 9, 0, 0, 0, time.UTC)
		orgT := uuid.New()
		siSeed(t, f, orgT)
		f.rows[orgT] = []inbox.Incident{
			sifRow(t, orgT, "00000000-0000-0000-0000-0000000000b2", inbox.SeverityLow, 0.5, base),
			sifRow(t, orgT, "00000000-0000-0000-0000-0000000000b1", inbox.SeverityLow, 0.5, base),
		}
		first := sifList(t, get, orgT, "?sort=confidence")
		second := sifList(t, get, orgT, "?sort=confidence")
		require.Equal(t, first, second)
		require.Equal(t, []uuid.UUID{
			uuid.MustParse("00000000-0000-0000-0000-0000000000b1"),
			uuid.MustParse("00000000-0000-0000-0000-0000000000b2"),
		}, first)
	})
}

func TestSecurityInboxFiltersCombinedAndIdempotent(t *testing.T) {
	orgA := uuid.New()
	f := newSecurityInboxFixture()
	siSeed(t, f, orgA)
	sifSeedRows(t, f, orgA)
	get := siServe(t, f)

	t.Run("filter and sort compose", func(t *testing.T) {
		// severity=high → {0.9 newest, 0.5 oldest}; sort=confidence → same
		// order here; the range keeps both.
		ids := sifList(t, get, orgA, "?severity=high&confidence_min=0.4&confidence_max=0.95&sort=confidence")
		require.Equal(t, []uuid.UUID{
			uuid.MustParse("00000000-0000-0000-0000-0000000000a1"),
			uuid.MustParse("00000000-0000-0000-0000-0000000000a4"),
		}, ids)
	})

	t.Run("empty after filter is 200 with empty array", func(t *testing.T) {
		w := get("/api/organizations/"+orgA.String()+"/security-inbox?confidence_min=0.95", siSessionCookie(t, "admin-1", false), "")
		require.Equal(t, http.StatusOK, w.Code)
		require.Contains(t, w.Body.String(), `"data":[]`)
	})

	t.Run("identical calls are byte-identical", func(t *testing.T) {
		path := "/api/organizations/" + orgA.String() + "/security-inbox?sort=severity&confidence_min=0.25"
		cookie := siSessionCookie(t, "admin-1", false)
		first := get(path, cookie, "")
		second := get(path, cookie, "")
		require.Equal(t, first.Body.String(), second.Body.String())
	})

	t.Run("params do not bypass the permission gate", func(t *testing.T) {
		w := get("/api/organizations/"+orgA.String()+"/security-inbox?sort=severity", siSessionCookie(t, "admin-4", false), "")
		require.Equal(t, http.StatusForbidden, w.Code, "operator without security.read stays 403 regardless of params")
	})
}
