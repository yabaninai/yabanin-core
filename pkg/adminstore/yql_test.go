package adminstore

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseYQL_Valid(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"simple compare", "status >= 400", "status >= 400"},
		{"word value", "model = gpt-4o", "model = gpt-4o"},
		{"quoted value", `model = "gpt 4o"`, `model = "gpt 4o"`},
		{"double-equals tolerated", "status == 500", "status = 500"},
		{"and", "status >= 400 and model = gpt-4o", "status >= 400 AND model = gpt-4o"},
		{"or", "status < 400 or status >= 500", "status < 400 OR status >= 500"},
		{"not", "not (error ~ timeout)", "NOT (error ~ timeout)"},
		{"mixed precedence", "status < 400 and cache = exact or status >= 500", "(status < 400 AND cache = exact) OR status >= 500"},
		{"parens", "(status < 400 or status >= 500) and model = gpt-4o", "(status < 400 OR status >= 500) AND model = gpt-4o"},
		{"in list", "status in (400, 404, 500)", "status in (400, 404, 500)"},
		{"not in list", "model not in (gpt-4o, claude-3)", "model not in (gpt-4o, claude-3)"},
		{"is empty", "task is empty", "task is empty"},
		{"is not empty", "task is not empty", "task is not empty"},
		{"is null alias", "task is null", "task is empty"},
		{"contains", "error ~ timeout", "error ~ timeout"},
		{"not contains", "error !~ timeout", "error !~ timeout"},
		{"cache miss", "cache = miss", "cache = miss"},
		{"tool equals", "tool = bash", "tool = bash"},
		{"text search", `text ~ "provider error"`, `text ~ "provider error"`},
		{"uppercase keywords", "status >= 400 AND model = gpt-4o", "status >= 400 AND model = gpt-4o"},
		{"case-insensitive field", "Model_Used = gpt-4o", "model = gpt-4o"},
		{"field aliases", "duration_ms > 1000", "latency > 1000"},
		{"uuid value", "agent = 00000000-0000-0000-0000-000000000001", "agent = 00000000-0000-0000-0000-000000000001"},
		{"session alias", "session_id = 00000000-0000-0000-0000-000000000002", "session = 00000000-0000-0000-0000-000000000002"},
		{"decimal", "cost >= 0.001", "cost >= 0.001"},
		{"no spaces around op", "status>=400", "status >= 400"},
		{"order by", "order by created desc", ""},
		{"order by asc explicit", "order by cost asc", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rq, err := ParseYQL(tc.input)
			require.NoError(t, err)
			require.NotNil(t, rq)
			if tc.want != "" {
				require.Equal(t, tc.want, rq.root.String())
			}
		})
	}
}

func TestParseYQL_Order(t *testing.T) {
	rq, err := ParseYQL("status >= 400 order by cost desc")
	require.NoError(t, err)
	require.NotNil(t, rq.Order)
	require.Equal(t, "cost", rq.Order.Field)
	require.True(t, rq.Order.Desc)

	rq, err = ParseYQL("order by created")
	require.NoError(t, err)
	require.NotNil(t, rq.Order)
	require.Equal(t, "created", rq.Order.Field)
	require.False(t, rq.Order.Desc) // Jira default is ASC

	rq, err = ParseYQL("status >= 400")
	require.NoError(t, err)
	require.Nil(t, rq.Order)
}

func TestParseYQL_Errors(t *testing.T) {
	cases := []struct {
		name  string
		input string
		msg   string
	}{
		{"unknown field", "bogus = 1", `unknown field "bogus"`},
		{"missing operator", "status 400", "expected an operator"},
		{"missing value", "status >=", "expected a value"},
		{"non-numeric value", "status >= abc", `expects a number`},
		{"negative number", "cost >= -1", "non-negative"},
		{"keyword as value", "status = and", "cannot be a value"},
		{"keyword as field", "and = 5", "unexpected keyword"},
		{"empty in list", "status in ()", "empty 'in' list"},
		{"missing paren in list", "status in (400, 500", "expected ',' or ')'"},
		{"unclosed group", "(status = 400", "expected ')'"},
		{"trailing junk", "status = 400)", "trailing input"},
		{"unterminated string", `model = "gpt`, "unterminated string"},
		{"bad cache value", "cache = wat", "exact, semantic or miss"},
		{"bad datetime", "created >= yolo", "invalid datetime"},
		{"empty on non-nullable", "status is empty", "cannot be empty"},
		{"op not for kind", "status ~ 400", "not supported for field"},
		{"tool range op", "tool > bash", "not supported for field"},
		{"text equality", "text = foo", "not supported for field"},
		{"order by non-orderable", "order by tool", "cannot be used for ordering"},
		{"order without by", "order created", "expected 'by'"},
		{"bad character", "status = 400 #", "unexpected character"},
		{"dangling not", "not", "expected an expression after 'not'"},
		{"dangling and", "status = 400 and", "expected an expression after 'and'"},
		{"is without empty", "task is bogus", "expected 'empty' or 'null'"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rq, err := ParseYQL(tc.input)
			require.Error(t, err)
			require.Nil(t, rq)
			require.Contains(t, err.Error(), tc.msg)
		})
	}
}

func TestParseYQL_EmptyAndTooLong(t *testing.T) {
	// Empty and whitespace-only input yield the shared no-query sentinel:
	// non-nil, but a no-op everywhere (empty WHERE fragment, no ORDER BY) —
	// so no consumer needs a nil-pointer distinction.
	rq, err := ParseYQL("")
	require.NoError(t, err)
	require.Same(t, yqlNoQuery, rq)

	rq, err = ParseYQL("   ")
	require.NoError(t, err)
	require.Same(t, yqlNoQuery, rq)
	frag, _ := rq.whereSQL(nil)
	require.Empty(t, frag)
	require.Nil(t, rq.Order)

	rq, err = ParseYQL("status = 400 and (" + strings.Repeat("model = x or ", 400) + "model = y)")
	require.Error(t, err)
	require.Nil(t, rq)
	require.Contains(t, err.Error(), "too long")
}

func TestParseYQL_RelativeTime(t *testing.T) {
	before := time.Now()
	rq, err := ParseYQL("created >= -24h")
	require.NoError(t, err)
	after := time.Now()

	w, args := requestListWhere(RequestListFilters{OrgID: "org-1", Query: rq})
	require.Contains(t, w, "rl.created_at >= $2::timestamptz")
	require.Len(t, args, 2)
	when, ok := args[1].(time.Time)
	require.True(t, ok)
	require.WithinDuration(t, before.Add(-24*time.Hour), when, after.Sub(before)+time.Second)
}

// The WHERE fragments must combine YQL with the flat filters with continuing
// placeholder numbering (mirrors TestRequestListWhere_Filters).
func TestRequestListWhere_WithYQL(t *testing.T) {
	rq, err := ParseYQL("status >= 400 and (model in (gpt-4o, claude-3) or tool = bash) order by cost desc")
	require.NoError(t, err)

	w, args := requestListWhere(RequestListFilters{
		OrgID:    "org-1",
		Model:    "gpt-4o", // flat filter stays $2, YQL continues at $3
		CacheHit: "miss",
		Query:    rq,
	})
	require.Contains(t, w, "org_id = $1")
	require.Contains(t, w, "COALESCE(ab_group, '') <> 'shadow'")
	require.Contains(t, w, "model_used = $2")
	require.Contains(t, w, "COALESCE(cache_hit_type, '') = ''")
	require.Contains(t, w, "(rl.status_code >= $3")
	require.Contains(t, w, "rl.model_used = $4 OR rl.model_used = $5")
	require.Contains(t, w, "tc.tool_name = $6")
	require.Len(t, args, 6)
	require.Equal(t, int64(400), args[2])
	require.Equal(t, "gpt-4o", args[3])
	require.Equal(t, "claude-3", args[4])
	require.Equal(t, "bash", args[5])
}

// The tool EXISTS subquery MUST reference the outer row as rl.*: an
// unqualified request_id/org_id would bind to tool_calls' own columns and
// turn the existence test into an org-blind always-true.
func TestYQLWhere_ToolExistsIsOrgScoped(t *testing.T) {
	rq, err := ParseYQL("tool = bash")
	require.NoError(t, err)
	w, _ := requestListWhere(RequestListFilters{OrgID: "org-1", Query: rq})
	require.Contains(t, w,
		"EXISTS (SELECT 1 FROM tool_calls tc WHERE tc.request_id = rl.request_id AND tc.org_id = rl.org_id AND tc.tool_name = $2)")
	require.NotContains(t, w, "tc.request_id = request_id")

	rq, err = ParseYQL("tool is empty")
	require.NoError(t, err)
	w, _ = requestListWhere(RequestListFilters{OrgID: "org-1", Query: rq})
	require.Contains(t, w, "NOT EXISTS (SELECT 1 FROM tool_calls tc WHERE tc.request_id = rl.request_id AND tc.org_id = rl.org_id)")
}

func TestYQLWhere_FragmentsPerKind(t *testing.T) {
	cases := []struct {
		name  string
		query string
		sql   string
	}{
		{"text equals", "model = gpt-4o", "rl.model_used = $2"},
		{"text not equals", "model != gpt-4o", "rl.model_used <> $2"},
		{"contains", "error ~ timeout", "COALESCE(rl.error, '') ILIKE '%' || $2 || '%'"},
		{"not contains", "error !~ timeout", "NOT (COALESCE(rl.error, '') ILIKE '%' || $2 || '%')"},
		{"text empty", "task is empty", "(rl.task_id IS NULL OR rl.task_id = '')"},
		{"text not empty", "task is not empty", "(rl.task_id IS NOT NULL AND rl.task_id <> '')"},
		{"number range", "latency >= 1000", "COALESCE(rl.duration_ms, 0) >= $2"},
		{"nullable number", "retries >= 2", "rl.retry_count >= $2"},
		{"nullable empty", "ttft is empty", "rl.first_token_ms IS NULL"},
		{"number in", "status in (500, 502)", "(rl.status_code = $2 OR rl.status_code = $3)"},
		{"number not in", "status not in (500)", "NOT (rl.status_code = $2)"},
		{"tokens", "tokens > 10000", "(COALESCE(rl.tokens_in, 0) + COALESCE(rl.tokens_out, 0)) > $2"},
		{"cache miss", "cache = miss", "COALESCE(rl.cache_hit_type, '') = ''"},
		{"cache exact", "cache = exact", "rl.cache_hit_type = $2"},
		{"cache in", "cache in (exact, miss)", "(rl.cache_hit_type = $2 OR COALESCE(rl.cache_hit_type, '') = '')"},
		{"agent text compare", "agent = 00000000-0000-0000-0000-000000000001", "rl.agent_id::text = $2"},
		{"session text compare", "session = 00000000-0000-0000-0000-000000000002", "rl.session_id::text = $2"},
		{"body search", "text ~ boom", "COALESCE(rl.upstream_request::text, '') ILIKE '%' || $2 || '%'"},
		{"request id", "request = req-9", "rl.request_id = $2"},
		{"not group", "not (status >= 400 or status = 301)", "NOT (rl.status_code >= $2 OR rl.status_code = $3)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rq, err := ParseYQL(tc.query)
			require.NoError(t, err)
			w, _ := requestListWhere(RequestListFilters{OrgID: "org-1", Query: rq})
			require.Contains(t, w, tc.sql)
		})
	}
}

func TestQueryOrder_SQL(t *testing.T) {
	rq, err := ParseYQL("order by cost desc")
	require.NoError(t, err)
	require.Equal(t,
		"COALESCE(rl.cost_in_usd, 0) DESC, rl.created_at DESC, rl.request_id",
		rq.Order.sql())

	rq, err = ParseYQL("order by ttft desc")
	require.NoError(t, err)
	require.Equal(t,
		"rl.first_token_ms DESC NULLS LAST, rl.created_at DESC, rl.request_id",
		rq.Order.sql())

	rq, err = ParseYQL("order by created desc")
	require.NoError(t, err)
	require.Equal(t, "rl.created_at DESC, rl.request_id", rq.Order.sql())
}

func TestParseYQL_Labels(t *testing.T) {
	cases := []struct {
		input string
		sql   string
		args  []string
	}{
		{`label.issue = "PAY-123"`, "(rl.labels @> jsonb_build_object($1::text, $2::text))", []string{"issue", "PAY-123"}},
		{`label.issue != "PAY-123"`, "((rl.labels ->> $1::text) <> $2::text)", []string{"issue", "PAY-123"}},
		{`label.git.repo ~ "payments"`, "(COALESCE((rl.labels ->> $1::text), '') ILIKE '%' || $2 || '%')", []string{"git.repo", "payments"}},
		{`label.git.repo !~ "payments"`, "(NOT (COALESCE((rl.labels ->> $1::text), '') ILIKE '%' || $2 || '%'))", []string{"git.repo", "payments"}},
		{`label.ci.job_name in ("lint", "review")`, "((rl.labels @> jsonb_build_object($1::text, $2::text) OR rl.labels @> jsonb_build_object($3::text, $4::text)))", []string{"ci.job_name", "lint", "ci.job_name", "review"}},
		{`label.ci.job_name not in ("lint")`, "(NOT (rl.labels @> jsonb_build_object($1::text, $2::text)))", []string{"ci.job_name", "lint"}},
		{"label.issue is empty", "((rl.labels ->> $1::text) IS NULL)", []string{"issue"}},
		{"label.issue is not empty", "((rl.labels ->> $1::text) IS NOT NULL)", []string{"issue"}},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			rq, err := ParseYQL(tc.input)
			require.NoError(t, err)
			frag, args := rq.whereSQL(nil)
			require.Equal(t, tc.sql, frag)
			require.Equal(t, tc.args, stringifyArgs(args))
		})
	}
	quoted, err := ParseYQL(`label.issue = "PAY'1"`)
	require.NoError(t, err)
	frag, args := quoted.whereSQL(nil)
	require.NotContains(t, frag, "PAY")
	require.Equal(t, []string{"issue", "PAY'1"}, stringifyArgs(args))

	for _, bad := range []string{`label.a'b = "x"`, "label.a;drop = x", "label. = x"} {
		_, err := ParseYQL(bad)
		require.Error(t, err, bad)
	}
	_, err = ParseYQL("order by label.issue")
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot order by label")
	_, err = ParseYQL("nope = 1")
	require.Error(t, err)
	require.Contains(t, err.Error(), "label.<key>")
}

func stringifyArgs(args []interface{}) []string {
	out := make([]string, len(args))
	for i, arg := range args {
		out[i] = fmt.Sprint(arg)
	}
	return out
}
