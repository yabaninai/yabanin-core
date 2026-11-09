package adminstore

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/reireirei/yabanin/pkg/labels"
)

// ErrAnalyticsTimeout is returned when Postgres cancels the statement
// (SQLSTATE 57014). Handlers map it to 503 analytics_timeout.
var ErrAnalyticsTimeout = errors.New("analytics_timeout")

// analyticsTimeout is the SET LOCAL statement_timeout for analytics reads.
// Tests replace it to force SQLSTATE 57014.
var analyticsTimeout = "5s"

// analyticsForceSleep, when set, runs pg_sleep before the read so a 1ms
// timeout is deterministic in integration tests.
var analyticsForceSleep = false

// analyticsPointLimit caps buckets × (top+1). Tests lower it to reach
// too_many_points inside the 93-day raw window.
var analyticsPointLimit = 50000

var analyticsTimeoutRe = regexp.MustCompile(`^[0-9]+(ms|s|min)$`)

// AnalyticsQuery is a validated GET /api/analytics/query.
type AnalyticsQuery struct {
	OrgID       string
	From, To    time.Time
	Metrics     []string
	GroupBy     []string
	Granularity string
	Filter      *RequestQuery
	FilterText  string
	Top         int
	Compare     bool
	TZ          *time.Location
	Format      string
	Now         time.Time
}

// AnalyticsQueryError is a 400 from ParseAnalyticsQuery. Pos is set for
// invalid_filter.
type AnalyticsQueryError struct {
	Code   string
	Msg    string
	Pos    int
	HasPos bool
}

func (e *AnalyticsQueryError) Error() string {
	if e.HasPos {
		return fmt.Sprintf("%s: %s at position %d", e.Code, e.Msg, e.Pos)
	}
	if e.Msg == "" {
		return e.Code
	}
	return e.Code + ": " + e.Msg
}

func aqErr(code, msg string) error {
	return &AnalyticsQueryError{Code: code, Msg: msg}
}

// AnalyticsColumn is one result column.
type AnalyticsColumn struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Unit string `json:"unit,omitempty"`
}

// AnalyticsQueryEcho is the query object in the JSON response.
type AnalyticsQueryEcho struct {
	Metrics     []string `json:"metrics"`
	GroupBy     []string `json:"group_by"`
	Granularity string   `json:"granularity"`
	From        string   `json:"from"`
	To          string   `json:"to"`
	TZ          string   `json:"tz"`
	Top         int      `json:"top"`
	Filter      string   `json:"filter"`
}

// AnalyticsCompare is the previous-window totals.
type AnalyticsCompare struct {
	From   string         `json:"from"`
	To     string         `json:"to"`
	Totals map[string]any `json:"totals"`
}

// AnalyticsCoverage counts rows whose price is not a measured cost.
type AnalyticsCoverage struct {
	UnpricedRequests int64    `json:"unpriced_requests"`
	UnpricedShare    *float64 `json:"unpriced_share"`
	LegacyRows       int64    `json:"legacy_rows"`
}

// AnalyticsResult is the JSON body of GET /api/analytics/query.
type AnalyticsResult struct {
	Query        AnalyticsQueryEcho           `json:"query"`
	Source       string                       `json:"source"`
	Columns      []AnalyticsColumn            `json:"columns"`
	Rows         [][]any                      `json:"rows"`
	Totals       map[string]any               `json:"totals"`
	Compare      *AnalyticsCompare            `json:"compare,omitempty"`
	Coverage     AnalyticsCoverage            `json:"coverage"`
	DisplayNames map[string]map[string]string `json:"display_names,omitempty"`
	Truncated    bool                         `json:"truncated"`
	GeneratedAt  time.Time                    `json:"generated_at"`
}

// LabelKeyStat is one row of GET /api/analytics/label-keys.
type LabelKeyStat struct {
	Key                  string `json:"key"`
	Requests             int64  `json:"requests"`
	ApproxDistinctValues int64  `json:"approx_distinct_values"`
}

// ParseAnalyticsQuery validates the analytics query string.
// orgTZ is the organization's IANA timezone, used when tz is omitted.
func ParseAnalyticsQuery(v url.Values, orgTZ string, now time.Time) (*AnalyticsQuery, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	orgID := strings.TrimSpace(v.Get("org_id"))
	if orgID == "" {
		return nil, aqErr("org_required", "org_id is required")
	}
	from, err := time.Parse(time.RFC3339, strings.TrimSpace(v.Get("from")))
	if err != nil {
		return nil, aqErr("invalid_range", "from must be RFC3339")
	}
	to, err := time.Parse(time.RFC3339, strings.TrimSpace(v.Get("to")))
	if err != nil {
		return nil, aqErr("invalid_range", "to must be RFC3339")
	}
	if !from.Before(to) {
		return nil, aqErr("invalid_range", "from must be before to")
	}
	metrics := splitCSV(v.Get("metrics"))
	if len(metrics) < 1 || len(metrics) > 6 {
		return nil, aqErr("invalid_metric", "metrics must list 1 to 6 names")
	}
	seenM := map[string]bool{}
	for _, m := range metrics {
		if seenM[m] {
			return nil, aqErr("invalid_metric", "duplicate metric "+m)
		}
		seenM[m] = true
		if _, ok := analyticsMetrics[m]; !ok {
			return nil, aqErr("invalid_metric", "unknown metric "+m)
		}
	}
	groupBy := splitCSV(v.Get("group_by"))
	if len(groupBy) > 2 {
		return nil, aqErr("invalid_dimension", "group_by accepts at most 2 dimensions")
	}
	seenD := map[string]bool{}
	for i, d := range groupBy {
		canon, ok := canonicalDim(d)
		if !ok {
			return nil, aqErr("invalid_dimension", "unknown dimension "+d)
		}
		if seenD[canon] {
			return nil, aqErr("invalid_dimension", "duplicate dimension "+canon)
		}
		seenD[canon] = true
		groupBy[i] = canon
	}
	gran := strings.TrimSpace(v.Get("granularity"))
	if gran == "" {
		gran = "none"
	}
	switch gran {
	case "none", "hour", "day", "week", "month":
	default:
		return nil, aqErr("invalid_granularity", "granularity must be none, hour, day, week or month")
	}
	if gran == "hour" && to.Sub(from) > 14*24*time.Hour {
		return nil, aqErr("invalid_granularity", "hour granularity requires a range of at most 14 days")
	}
	top := 20
	if raw := strings.TrimSpace(v.Get("top")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 100 {
			return nil, aqErr("invalid_top", "top must be an integer from 1 to 100")
		}
		top = n
	}
	tzName := strings.TrimSpace(v.Get("tz"))
	if tzName == "" {
		tzName = strings.TrimSpace(orgTZ)
	}
	if tzName == "" {
		tzName = "UTC"
	}
	loc, err := time.LoadLocation(tzName)
	if err != nil {
		return nil, aqErr("invalid_tz", "unknown timezone "+tzName)
	}
	var filter *RequestQuery
	filterText := strings.TrimSpace(v.Get("filter"))
	if filterText != "" {
		rq, err := ParseYQL(filterText)
		if err != nil {
			pos := 0
			var yerr *YQLError
			if errors.As(err, &yerr) {
				pos = yerr.Position()
			}
			return nil, &AnalyticsQueryError{Code: "invalid_filter", Msg: err.Error(), Pos: pos, HasPos: true}
		}
		filter = rq
	}
	limit := 93 * 24 * time.Hour
	if analyticsSource(&AnalyticsQuery{Metrics: metrics, GroupBy: groupBy, Granularity: gran, FilterText: filterText}) != "raw" {
		limit = 400 * 24 * time.Hour
	}
	if to.Sub(from) > limit {
		return nil, aqErr("range_too_large", "raw queries cover at most 93 days; use granularity=day and no filter to hit rollups")
	}
	format := strings.TrimSpace(v.Get("format"))
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" {
		return nil, aqErr("invalid_range", "format must be json or csv")
	}
	cmp := strings.TrimSpace(v.Get("compare"))
	if cmp != "" && cmp != "previous" {
		return nil, aqErr("invalid_range", "compare must be previous")
	}
	buckets := analyticsBuckets(from, to, gran, loc)
	if buckets*(top+1) > analyticsPointLimit {
		return nil, aqErr("too_many_points", "narrow the range, granularity or top")
	}
	if groupBy == nil {
		groupBy = []string{}
	}
	return &AnalyticsQuery{
		OrgID: orgID, From: from, To: to, Metrics: metrics, GroupBy: groupBy,
		Granularity: gran, Filter: filter, FilterText: filterText, Top: top,
		Compare: cmp == "previous", TZ: loc, Format: format, Now: now,
	}, nil
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func canonicalDim(raw string) (string, bool) {
	if _, ok := analyticsDimExpr[raw]; ok {
		return raw, true
	}
	const prefix = "label:"
	if !strings.HasPrefix(strings.ToLower(raw), prefix) {
		return "", false
	}
	key, ok := labels.NormalizeKey(raw[len(prefix):])
	if !ok {
		return "", false
	}
	return prefix + key, true
}

func analyticsBuckets(from, to time.Time, gran string, loc *time.Location) int {
	if gran == "" || gran == "none" {
		return 1
	}
	if loc == nil {
		loc = time.UTC
	}
	from, to = from.In(loc), to.In(loc)
	if gran == "month" {
		n := 0
		cur := time.Date(from.Year(), from.Month(), 1, 0, 0, 0, 0, loc)
		for cur.Before(to) && n < 10000 {
			n++
			cur = cur.AddDate(0, 1, 0)
		}
		if n < 1 {
			return 1
		}
		return n
	}
	var step time.Duration
	switch gran {
	case "hour":
		step = time.Hour
	case "week":
		step = 7 * 24 * time.Hour
	default:
		step = 24 * time.Hour
	}
	n := int(to.Sub(from) / step)
	if to.Sub(from)%step != 0 {
		n++
	}
	n++ // partial bucket on the leading edge
	if n < 1 {
		return 1
	}
	return n
}

// csvSafe prefixes formula-looking cells so a spreadsheet does not evaluate them.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	default:
		return s
	}
}

// WriteCSV writes the result with a header row. team and agent dimensions
// gain a companion name column.
func (r *AnalyticsResult) WriteCSV(w io.Writer) error {
	cw := csv.NewWriter(w)
	header := make([]string, 0, len(r.Columns)+2)
	type col struct {
		name    string
		nameCol bool
	}
	plan := make([]col, 0, len(r.Columns)+2)
	for _, c := range r.Columns {
		header = append(header, c.Name)
		plan = append(plan, col{name: c.Name})
		if c.Name == "team" || c.Name == "agent" {
			header = append(header, c.Name+"_name")
			plan = append(plan, col{name: c.Name, nameCol: true})
		}
	}
	if err := cw.Write(header); err != nil {
		return err
	}
	for _, row := range r.Rows {
		rec := make([]string, len(plan))
		src := 0
		for i, p := range plan {
			if p.nameCol {
				id := ""
				if src > 0 && src-1 < len(row) && row[src-1] != nil {
					id = fmt.Sprint(row[src-1])
				}
				name := ""
				if r.DisplayNames != nil && r.DisplayNames[p.name] != nil {
					name = r.DisplayNames[p.name][id]
				}
				rec[i] = csvSafe(name)
				continue
			}
			cell := ""
			if src < len(row) && row[src] != nil {
				cell = fmt.Sprint(row[src])
			}
			rec[i] = csvSafe(cell)
			src++
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// RunAnalyticsQuery executes the raw analytics read in one read-only
// transaction. statement_timeout cancels map to ErrAnalyticsTimeout.
func (s *Store) RunAnalyticsQuery(ctx context.Context, q *AnalyticsQuery) (*AnalyticsResult, error) {
	if s.pool == nil {
		return nil, fmt.Errorf("database not available")
	}
	if q == nil || q.TZ == nil {
		return nil, fmt.Errorf("analytics query is incomplete")
	}
	built, err := buildAnalyticsSQL(q)
	if err != nil {
		return nil, err
	}
	timeout := analyticsTimeout
	if !analyticsTimeoutRe.MatchString(timeout) {
		return nil, fmt.Errorf("refusing statement_timeout %q", timeout)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout = '"+timeout+"'"); err != nil {
		return nil, mapAnalyticsTimeout(err)
	}
	if analyticsForceSleep {
		if _, err := tx.Exec(ctx, "SELECT pg_sleep(1)"); err != nil {
			return nil, mapAnalyticsTimeout(err)
		}
	}
	var topKeys []string
	if built.TopSQL != "" {
		topKeys, err = scanTopKeys(ctx, tx, built.TopSQL, built.TopArgs)
		if err != nil {
			return nil, mapAnalyticsTimeout(err)
		}
		built.MainArgs = append(built.MainArgs, topKeys)
	}
	rows, err := scanAnalyticsRows(ctx, tx, built, q)
	if err != nil {
		return nil, mapAnalyticsTimeout(err)
	}
	totals, coverage, err := scanTotals(ctx, tx, built.TotalsSQL, built.TotalsArgs, q.Metrics)
	if err != nil {
		return nil, mapAnalyticsTimeout(err)
	}
	var compare *AnalyticsCompare
	if q.Compare {
		span := q.To.Sub(q.From)
		prevFrom := q.From.Add(-span)
		args := append([]any{}, built.TotalsArgs...)
		args[1] = prevFrom
		args[2] = q.From
		prevTotals, _, err := scanTotals(ctx, tx, built.TotalsSQL, args, q.Metrics)
		if err != nil {
			return nil, mapAnalyticsTimeout(err)
		}
		compare = &AnalyticsCompare{
			From:   prevFrom.In(q.TZ).Format(time.RFC3339),
			To:     q.From.In(q.TZ).Format(time.RFC3339),
			Totals: prevTotals,
		}
	}
	names, err := loadDisplayNames(ctx, tx, q, rows)
	if err != nil {
		return nil, mapAnalyticsTimeout(err)
	}
	truncated := false
	if len(q.GroupBy) > 0 && len(topKeys) == q.Top {
		truncated = rowsHaveOther(rows, built.HasTime, len(q.GroupBy))
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapAnalyticsTimeout(err)
	}
	groupBy := q.GroupBy
	if groupBy == nil {
		groupBy = []string{}
	}
	return &AnalyticsResult{
		Query: AnalyticsQueryEcho{
			Metrics: q.Metrics, GroupBy: groupBy, Granularity: q.Granularity,
			From: q.From.In(q.TZ).Format(time.RFC3339), To: q.To.In(q.TZ).Format(time.RFC3339),
			TZ: q.TZ.String(), Top: q.Top, Filter: q.FilterText,
		},
		Source: analyticsPublicSource(q), Columns: analyticsColumns(q, built.HasTime), Rows: rows,
		Totals: totals, Compare: compare, Coverage: coverage, DisplayNames: names,
		Truncated: truncated, GeneratedAt: q.Now.UTC(),
	}, nil
}

func analyticsColumns(q *AnalyticsQuery, hasTime bool) []AnalyticsColumn {
	cols := make([]AnalyticsColumn, 0, 1+len(q.GroupBy)+len(q.Metrics))
	if hasTime {
		cols = append(cols, AnalyticsColumn{Name: "time", Type: "time"})
	}
	for _, d := range q.GroupBy {
		cols = append(cols, AnalyticsColumn{Name: d, Type: "string"})
	}
	for _, m := range q.Metrics {
		cols = append(cols, AnalyticsColumn{Name: m, Type: "number", Unit: analyticsMetrics[m].unit})
	}
	return cols
}

func mapAnalyticsTimeout(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "57014" {
		return ErrAnalyticsTimeout
	}
	return err
}

func scanTopKeys(ctx context.Context, tx pgx.Tx, sql string, args []any) ([]string, error) {
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []string
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			return nil, err
		}
		keys = append(keys, g)
	}
	if keys == nil {
		keys = []string{}
	}
	return keys, rows.Err()
}

func scanAnalyticsRows(ctx context.Context, tx pgx.Tx, built analyticsBuilt, q *AnalyticsQuery) ([][]any, error) {
	rows, err := tx.Query(ctx, built.MainSQL, built.MainArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]any
	nDim := len(q.GroupBy)
	nMet := len(q.Metrics)
	for rows.Next() {
		var timeVal time.Time
		dims := make([]string, nDim)
		mets := make([]*float64, nMet)
		dest := make([]any, 0, boolToInt(built.HasTime)+nDim+nMet)
		if built.HasTime {
			dest = append(dest, &timeVal)
		}
		for i := range dims {
			dest = append(dest, &dims[i])
		}
		for i := range mets {
			dest = append(dest, &mets[i])
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		rec := make([]any, 0, len(dest))
		if built.HasTime {
			rec = append(rec, timeVal.In(q.TZ).Format(time.RFC3339))
		}
		for _, d := range dims {
			rec = append(rec, d)
		}
		for _, m := range mets {
			if m == nil {
				rec = append(rec, nil)
			} else {
				rec = append(rec, *m)
			}
		}
		out = append(out, rec)
	}
	if out == nil {
		out = [][]any{}
	}
	return out, rows.Err()
}

func scanTotals(ctx context.Context, tx pgx.Tx, sql string, args []any, metrics []string) (map[string]any, AnalyticsCoverage, error) {
	mets := make([]*float64, len(metrics))
	dest := make([]any, 0, len(metrics)+3)
	for i := range mets {
		dest = append(dest, &mets[i])
	}
	var unpriced, legacy, total int64
	dest = append(dest, &unpriced, &legacy, &total)
	var cov AnalyticsCoverage
	if err := tx.QueryRow(ctx, sql, args...).Scan(dest...); err != nil {
		return nil, cov, err
	}
	totals := make(map[string]any, len(metrics))
	for i, name := range metrics {
		if mets[i] == nil {
			totals[name] = nil
		} else {
			totals[name] = *mets[i]
		}
	}
	cov.UnpricedRequests = unpriced
	cov.LegacyRows = legacy
	if total > 0 {
		share := float64(unpriced) / float64(total)
		cov.UnpricedShare = &share
	}
	return totals, cov, nil
}

func rowsHaveOther(rows [][]any, hasTime bool, nDim int) bool {
	start := 0
	if hasTime {
		start = 1
	}
	for _, row := range rows {
		for i := 0; i < nDim && start+i < len(row); i++ {
			if row[start+i] == "(other)" {
				return true
			}
		}
	}
	return false
}

func loadDisplayNames(ctx context.Context, tx pgx.Tx, q *AnalyticsQuery, rows [][]any) (map[string]map[string]string, error) {
	want := map[string]bool{}
	for _, d := range q.GroupBy {
		if d == "team" || d == "agent" {
			want[d] = true
		}
	}
	if len(want) == 0 {
		return map[string]map[string]string{}, nil
	}
	start := 0
	if q.Granularity != "" && q.Granularity != "none" {
		start = 1
	}
	ids := map[string][]string{}
	seen := map[string]map[string]bool{}
	idx := start
	for _, d := range q.GroupBy {
		if want[d] {
			if seen[d] == nil {
				seen[d] = map[string]bool{}
			}
			for _, row := range rows {
				if idx >= len(row) {
					continue
				}
				id, _ := row[idx].(string)
				if !validUUID(id) || seen[d][id] {
					continue
				}
				seen[d][id] = true
				ids[d] = append(ids[d], id)
			}
		}
		idx++
	}
	out := map[string]map[string]string{}
	for dim, list := range ids {
		if len(list) == 0 {
			continue
		}
		qsql := "SELECT id::text, name FROM organizations_teams WHERE org_id = $1::uuid AND id::text = ANY($2::text[])"
		if dim == "agent" {
			qsql = "SELECT id::text, name FROM agent_keys WHERE org_id = $1::uuid AND id::text = ANY($2::text[])"
		}
		r, err := tx.Query(ctx, qsql, q.OrgID, list)
		if err != nil {
			return nil, err
		}
		names := map[string]string{}
		for r.Next() {
			var id, name string
			if err := r.Scan(&id, &name); err != nil {
				r.Close()
				return nil, err
			}
			names[id] = name
		}
		if err := r.Err(); err != nil {
			r.Close()
			return nil, err
		}
		r.Close()
		if len(names) > 0 {
			out[dim] = names
		}
	}
	if len(out) == 0 {
		return map[string]map[string]string{}, nil
	}
	return out, nil
}

func validUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				return false
			}
		}
	}
	return true
}

// ListLabelKeys returns the most common label keys in the window, sampled
// from the newest 100000 request rows.
func (s *Store) ListLabelKeys(ctx context.Context, orgID string, from, to time.Time) ([]LabelKeyStat, error) {
	if s.pool == nil {
		return nil, fmt.Errorf("database not available")
	}
	rows, err := s.pool.Query(ctx, labelKeysSQL, orgID, from, to)
	if err != nil {
		return nil, mapAnalyticsTimeout(err)
	}
	defer rows.Close()
	var out []LabelKeyStat
	for rows.Next() {
		var st LabelKeyStat
		if err := rows.Scan(&st.Key, &st.Requests, &st.ApproxDistinctValues); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	if out == nil {
		out = []LabelKeyStat{}
	}
	return out, rows.Err()
}
