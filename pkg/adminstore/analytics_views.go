package adminstore

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// AnalyticsView is a saved analytics explorer query.
type AnalyticsView struct {
	ID        string            `json:"id"`
	OrgID     string            `json:"org_id"`
	OwnerID   string            `json:"owner_id"`
	Name      string            `json:"name"`
	Query     map[string]string `json:"query"`
	Shared    bool              `json:"shared"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// NormalizeAnalyticsViewQuery validates a view query with ParseAnalyticsQuery
// and returns the canonical parameter map.
func NormalizeAnalyticsViewQuery(raw map[string]string, now time.Time) (map[string]string, error) {
	values := url.Values{}
	for key, value := range raw {
		values.Set(key, value)
	}
	if values.Get("metrics") == "" {
		values.Set("metrics", "requests")
	}
	parsed, err := ParseAnalyticsQuery(values, "UTC", now)
	if err != nil {
		return nil, err
	}
	out := map[string]string{
		"org_id":      parsed.OrgID,
		"from":        parsed.From.UTC().Format(time.RFC3339),
		"to":          parsed.To.UTC().Format(time.RFC3339),
		"metrics":     strings.Join(parsed.Metrics, ","),
		"granularity": parsed.Granularity,
		"top":         strconv.Itoa(parsed.Top),
		"tz":          parsed.TZ.String(),
	}
	if len(parsed.GroupBy) > 0 {
		out["group_by"] = strings.Join(parsed.GroupBy, ",")
	}
	if parsed.FilterText != "" {
		out["filter"] = parsed.FilterText
	}
	if parsed.Compare {
		out["compare"] = "previous"
	}
	if parsed.Format != "" && parsed.Format != "json" {
		out["format"] = parsed.Format
	}
	return out, nil
}

// ListAnalyticsViews returns the caller's views and the org's shared views.
func (s *Store) ListAnalyticsViews(ctx context.Context, orgID, ownerID string) ([]AnalyticsView, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	rows, err := s.db.Query(ctx,
		`SELECT id::text, org_id::text, owner_id, name, query, shared, created_at, updated_at
		   FROM analytics_views
		  WHERE org_id = $1::uuid AND (owner_id = $2 OR shared = true)
		  ORDER BY name`, orgID, ownerID)
	if err != nil {
		return nil, fmt.Errorf("list analytics views: %w", err)
	}
	defer rows.Close()
	var out []AnalyticsView
	for rows.Next() {
		view, err := scanAnalyticsView(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, view)
	}
	if out == nil {
		out = []AnalyticsView{}
	}
	return out, rows.Err()
}

// CountAnalyticsViews counts views owned by the caller in the org.
func (s *Store) CountAnalyticsViews(ctx context.Context, orgID, ownerID string) (int, error) {
	if s.db == nil {
		return 0, fmt.Errorf("database not available")
	}
	var n int
	err := s.db.QueryRow(ctx,
		`SELECT count(*) FROM analytics_views WHERE org_id = $1::uuid AND owner_id = $2`,
		orgID, ownerID).Scan(&n)
	return n, err
}

// CreateAnalyticsView inserts a view and returns the stored row.
func (s *Store) CreateAnalyticsView(ctx context.Context, view AnalyticsView) (AnalyticsView, error) {
	if s.db == nil {
		return AnalyticsView{}, fmt.Errorf("database not available")
	}
	raw, err := json.Marshal(view.Query)
	if err != nil {
		return AnalyticsView{}, err
	}
	row := s.db.QueryRow(ctx,
		`INSERT INTO analytics_views (org_id, owner_id, name, query, shared)
		 VALUES ($1::uuid, $2, $3, $4::jsonb, $5)
		 RETURNING id::text, org_id::text, owner_id, name, query, shared, created_at, updated_at`,
		view.OrgID, view.OwnerID, view.Name, raw, view.Shared)
	return scanAnalyticsView(row)
}

// GetAnalyticsView loads one view. Missing rows are ErrNotFound.
func (s *Store) GetAnalyticsView(ctx context.Context, id string) (AnalyticsView, error) {
	if s.db == nil {
		return AnalyticsView{}, fmt.Errorf("database not available")
	}
	row := s.db.QueryRow(ctx,
		`SELECT id::text, org_id::text, owner_id, name, query, shared, created_at, updated_at
		   FROM analytics_views WHERE id = $1::uuid`, id)
	view, err := scanAnalyticsView(row)
	if err != nil {
		if IsNotFound(err) {
			return AnalyticsView{}, ErrNotFound
		}
		return AnalyticsView{}, err
	}
	return view, nil
}

// UpdateAnalyticsView replaces the name, query, and shared flag.
func (s *Store) UpdateAnalyticsView(ctx context.Context, view AnalyticsView) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	raw, err := json.Marshal(view.Query)
	if err != nil {
		return err
	}
	tag, err := s.db.Exec(ctx,
		`UPDATE analytics_views
		    SET name = $2, query = $3::jsonb, shared = $4, updated_at = now()
		  WHERE id = $1::uuid`, view.ID, view.Name, raw, view.Shared)
	if err != nil {
		return fmt.Errorf("update analytics view: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteAnalyticsView removes a view. A missing id is ErrNotFound.
func (s *Store) DeleteAnalyticsView(ctx context.Context, id string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	tag, err := s.db.Exec(ctx, `DELETE FROM analytics_views WHERE id = $1::uuid`, id)
	if err != nil {
		return fmt.Errorf("delete analytics view: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

type viewScanner interface {
	Scan(dest ...any) error
}

func scanAnalyticsView(row viewScanner) (AnalyticsView, error) {
	var view AnalyticsView
	var raw []byte
	if err := row.Scan(&view.ID, &view.OrgID, &view.OwnerID, &view.Name, &raw, &view.Shared, &view.CreatedAt, &view.UpdatedAt); err != nil {
		return AnalyticsView{}, err
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &view.Query); err != nil {
			return AnalyticsView{}, fmt.Errorf("analytics view query: %w", err)
		}
	}
	if view.Query == nil {
		view.Query = map[string]string{}
	}
	return view, nil
}
