package adminstore

import "fmt"

// Sort is a validated sorting request attached to a PageFilter.
// Column is an allowlist key resolved through a SortColumns map; the raw
// user-supplied string never reaches SQL.
type Sort struct {
	Column string
	Desc   bool
	Set    bool // true when the client explicitly asked for a sort
}

// SortColumns maps allowlisted column names to fixed SQL expressions.
// Map values are compile-time literals; the map is the only path from a
// user string into an ORDER BY clause.
type SortColumns map[string]string

// Allowlists for the admin list endpoints (AUX-02).
// Secrets (api_keys.key_hash, admin_users.password_hash) are deliberately
// not sortable.
var (
	APIKeySortColumns = SortColumns{
		"id":         "id",
		"name":       "name",
		"org_id":     "org_id",
		"team_id":    "team_id",
		"active":     "active",
		"created_at": "created_at",
	}
	OrganizationSortColumns = SortColumns{
		"id":         "id",
		"name":       "name",
		"slug":       "slug",
		"currency":   "currency",
		"timezone":   "timezone",
		"created_at": "created_at",
	}
	ModelSortColumns = SortColumns{
		"id":           "id",
		"model_name":   "model_name",
		"display_name": "display_name",
		"tier":         "tier",
		"provider":     "provider",
		"enabled":      "enabled",
		"created_at":   "created_at",
	}
	RoutingRuleSortColumns = SortColumns{
		"id":           "id",
		"match_expr":   "match_expr",
		"target_model": "target_model",
		"priority":     "priority",
		"enabled":      "enabled",
		"created_at":   "created_at",
	}
	AdminUserSortColumns = SortColumns{
		"id":           "id",
		"email":        "email",
		"display_name": "display_name",
		"is_root":      "is_root",
		"active":       "active",
		"created_at":   "created_at",
	}
)

// OrderBy renders the ORDER BY clause for this page's sort request.
// defColumn/defDesc preserve each endpoint's pre-sorting default order.
// An unknown column falls back to the default (the HTTP layer already
// rejects it with 400 invalid_sort; this is defense in depth for direct
// store callers). Every clause ends with ", id ASC" so equal sort values
// keep pagination stable.
func (f PageFilter) OrderBy(allowed SortColumns, defColumn string, defDesc bool) string {
	column, desc := defColumn, defDesc
	if f.Sort != nil && f.Sort.Set {
		if _, ok := allowed[f.Sort.Column]; ok {
			column, desc = f.Sort.Column, f.Sort.Desc
		}
	}
	expr, ok := allowed[column]
	if !ok {
		expr = "id"
	}
	dir := "ASC"
	if desc {
		dir = "DESC"
	}
	return fmt.Sprintf(" ORDER BY %s %s, id ASC", expr, dir)
}
