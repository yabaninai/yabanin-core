package adminstore

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/labels"
)

// YQL (Yabanin Query Language) is the Jira-JQL-like filter language of the
// request explorer. A query is a boolean expression over request-log fields,
// optionally with an ORDER BY tail:
//
//	query   := orExpr ["order" "by" field [("asc"|"desc")]]
//	orExpr  := andExpr ("or" andExpr)*
//	andExpr := unary ("and" unary)*
//	unary   := "not" unary | "(" orExpr ")" | clause
//	clause  := field op value
//	        | field "in" "(" value ("," value)* ")"
//	        | field "not" "in" "(" ... ")"
//	        | field "is" ["not"] ("empty"|"null")
//	op      := "=" "==" "!=" ">" ">=" "<" "<=" "~" "!~"
//
// Values are bare words (gpt-4o, 400, -24h, 2026-09-29, uuids) or quoted
// strings ("claude 3.5"). Datetimes accept RFC3339, YYYY-MM-DD,
// YYYY-MM-DDTHH:MM, "now" and relative offsets (-30m, -24h, -7d, -4w).
// Keywords are case-insensitive; field names accept the aliases below.
//
// Compilation is injection-proof by construction: every user value becomes a
// placeholder, column expressions come only from the yqlFields registry, and
// ORDER BY directions are the literals ASC/DESC. Nothing user-typed is ever
// interpolated into SQL text.

// MaxYQLLen bounds the accepted query length so a pathological input cannot
// generate unbounded SQL.
const MaxYQLLen = 2000

// maxYQLListLen bounds the number of values in an `in (...)` list.
const maxYQLListLen = 40

// yqlKind classifies a field's comparison semantics.
type yqlKind int

const (
	yqlText   yqlKind = iota // string comparison / ILIKE
	yqlNumber                // numeric ranges; float input allowed
	yqlTime                  // timestamptz comparisons
	yqlCache                 // cache_hit_type enum: exact|semantic|miss
	yqlTool                  // EXISTS over org-scoped tool_calls
	yqlBody                  // content search over error + snapshots
	yqlLabel                 // jsonb label.<key> on request_logs.labels
)

// yqlFieldSpec describes one filterable field. col is the rl-qualified SQL
// expression; the rl alias is guaranteed by requestListWhere callers.
type yqlFieldSpec struct {
	name      string
	col       string
	kind      yqlKind
	nullable  bool // "is empty" is allowed
	orderable bool
	labelKey  string // set for yqlLabel
}

// yqlFields is the whitelist of filterable/orderable columns plus aliases.
// The canonical name (spec.name) is what the AST stores and serializes.
var yqlFields = map[string]*yqlFieldSpec{
	"request":         {name: "request", col: "rl.request_id", kind: yqlText, orderable: true},
	"request_id":      {name: "request", col: "rl.request_id", kind: yqlText, orderable: true},
	"model":           {name: "model", col: "rl.model_used", kind: yqlText, orderable: true},
	"model_used":      {name: "model", col: "rl.model_used", kind: yqlText, orderable: true},
	"model_requested": {name: "model_requested", col: "rl.model_requested", kind: yqlText, nullable: true, orderable: true},
	"status":          {name: "status", col: "rl.status_code", kind: yqlNumber, orderable: true},
	"status_code":     {name: "status", col: "rl.status_code", kind: yqlNumber, orderable: true},
	"cost":            {name: "cost", col: "COALESCE(rl.cost_in_usd, 0)", kind: yqlNumber, orderable: true},
	"cost_usd":        {name: "cost", col: "COALESCE(rl.cost_in_usd, 0)", kind: yqlNumber, orderable: true},
	"tokens":          {name: "tokens", col: "(COALESCE(rl.tokens_in, 0) + COALESCE(rl.tokens_out, 0))", kind: yqlNumber, orderable: true},
	"tokens_in":       {name: "tokens_in", col: "COALESCE(rl.tokens_in, 0)", kind: yqlNumber, orderable: true},
	"tokens_out":      {name: "tokens_out", col: "COALESCE(rl.tokens_out, 0)", kind: yqlNumber, orderable: true},
	"latency":         {name: "latency", col: "COALESCE(rl.duration_ms, 0)", kind: yqlNumber, orderable: true},
	"duration":        {name: "latency", col: "COALESCE(rl.duration_ms, 0)", kind: yqlNumber, orderable: true},
	"duration_ms":     {name: "latency", col: "COALESCE(rl.duration_ms, 0)", kind: yqlNumber, orderable: true},
	"ttft":            {name: "ttft", col: "rl.first_token_ms", kind: yqlNumber, nullable: true, orderable: true},
	"first_token_ms":  {name: "ttft", col: "rl.first_token_ms", kind: yqlNumber, nullable: true, orderable: true},
	"retries":         {name: "retries", col: "rl.retry_count", kind: yqlNumber, nullable: true, orderable: true},
	"retry_count":     {name: "retries", col: "rl.retry_count", kind: yqlNumber, nullable: true, orderable: true},
	"attempts":        {name: "attempts", col: "rl.attempt_count", kind: yqlNumber, nullable: true, orderable: true},
	"attempt_count":   {name: "attempts", col: "rl.attempt_count", kind: yqlNumber, nullable: true, orderable: true},
	"task":            {name: "task", col: "rl.task_id", kind: yqlText, nullable: true, orderable: true},
	"task_id":         {name: "task", col: "rl.task_id", kind: yqlText, nullable: true, orderable: true},
	// agent_id is a uuid column; compare through ::text so an invalid uuid
	// value can never surface as a 500 from a failed cast.
	"agent":    {name: "agent", col: "rl.agent_id::text", kind: yqlText, nullable: true, orderable: true},
	"agent_id": {name: "agent", col: "rl.agent_id::text", kind: yqlText, nullable: true, orderable: true},
	// session chronology). SQL NULL on untagged rows keeps != / not in
	// honest empties — the same semantics the agent cases already pin.
	"session":    {name: "session", col: "rl.session_id::text", kind: yqlText, nullable: true, orderable: true},
	"session_id": {name: "session", col: "rl.session_id::text", kind: yqlText, nullable: true, orderable: true},
	"cache":      {name: "cache", col: "rl.cache_hit_type", kind: yqlCache, nullable: true, orderable: true},
	"cache_hit":  {name: "cache", col: "rl.cache_hit_type", kind: yqlCache, nullable: true, orderable: true},
	// tool is the org-scoped EXISTS over tool_calls; "is empty" = no calls.
	"tool":       {name: "tool", kind: yqlTool, nullable: true},
	"tool_name":  {name: "tool", kind: yqlTool, nullable: true},
	"error":      {name: "error", col: "rl.error", kind: yqlText, nullable: true, orderable: true},
	"created":    {name: "created", col: "rl.created_at", kind: yqlTime, orderable: true},
	"created_at": {name: "created", col: "rl.created_at", kind: yqlTime, orderable: true},
	"text":       {name: "text", kind: yqlBody},
}

// yqlFieldNames lists the canonical field names for error messages.
var yqlFieldNames = func() []string {
	seen := map[string]bool{}
	var names []string
	for _, spec := range yqlFields {
		if !seen[spec.name] {
			seen[spec.name] = true
			names = append(names, spec.name)
		}
	}
	sort.Strings(names)
	return names
}()

// yqlOpsFor returns the operators valid for a kind (empty/not-empty excluded;
// nullable-gated separately).
func yqlOpsFor(kind yqlKind) map[string]bool {
	switch kind {
	case yqlText, yqlLabel:
		return map[string]bool{"=": true, "!=": true, "~": true, "!~": true, "in": true, "not in": true}
	case yqlNumber:
		return map[string]bool{"=": true, "!=": true, ">": true, ">=": true, "<": true, "<=": true, "in": true, "not in": true}
	case yqlTime:
		return map[string]bool{"=": true, ">": true, ">=": true, "<": true, "<=": true}
	case yqlCache:
		return map[string]bool{"=": true, "!=": true, "in": true, "not in": true}
	case yqlTool:
		return map[string]bool{"=": true, "!=": true, "~": true, "!~": true}
	case yqlBody:
		return map[string]bool{"~": true, "!~": true}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AST

// RequestQuery is a parsed, validated YQL expression. It is carried on
// RequestListFilters and compiled into the shared list/count/stats WHERE
// clauses; the stats query ignores Order.
type RequestQuery struct {
	root  yqlNode
	Order *QueryOrder
}

// QueryOrder is the ORDER BY tail of a YQL query.
type QueryOrder struct {
	Field string // canonical field name (never user-raw)
	Desc  bool
}

// sql renders the ORDER BY expression. Ordering is always deterministic:
// non-primary keys get created_at DESC + request_id tiebreakers.
func (o *QueryOrder) sql() string {
	spec := yqlFields[o.Field]
	frag := spec.col + " ASC"
	if o.Desc {
		frag = spec.col + " DESC"
		if spec.nullable {
			frag += " NULLS LAST"
		}
	}
	if spec.name == "created" {
		return frag + ", rl.request_id"
	}
	return frag + ", rl.created_at DESC, rl.request_id"
}

type yqlNode interface {
	compile(c *yqlCompiler) string
	String() string
}

type yqlBinary struct {
	op   string // "AND" | "OR"
	l, r yqlNode
}

func (n *yqlBinary) compile(c *yqlCompiler) string {
	l, r := n.l.compile(c), n.r.compile(c)
	if _, ok := n.l.(*yqlBinary); ok {
		l = "(" + l + ")"
	}
	if _, ok := n.r.(*yqlBinary); ok {
		r = "(" + r + ")"
	}
	return l + " " + n.op + " " + r
}

func (n *yqlBinary) String() string {
	l, r := n.l.String(), n.r.String()
	if _, ok := n.l.(*yqlBinary); ok {
		l = "(" + l + ")"
	}
	if _, ok := n.r.(*yqlBinary); ok {
		r = "(" + r + ")"
	}
	return l + " " + n.op + " " + r
}

type yqlNot struct{ child yqlNode }

func (n *yqlNot) compile(c *yqlCompiler) string { return "NOT (" + n.child.compile(c) + ")" }
func (n *yqlNot) String() string                { return "NOT (" + n.child.String() + ")" }

// yqlClause is `field op value(s)`. values has one entry for scalar ops and
// the full list for in/not-in. op is one of
// = != > >= < <= ~ !~ in "not in" empty "not empty".
type yqlClause struct {
	field  *yqlFieldSpec
	op     string
	values []yqlValue
}

type yqlValue struct {
	raw  string
	num  float64
	when time.Time // yqlTime only
}

func (cl *yqlClause) compile(c *yqlCompiler) string {
	switch cl.field.kind {
	case yqlText:
		return c.compileText(cl)
	case yqlNumber:
		return c.compileNumber(cl)
	case yqlTime:
		return c.compileTime(cl)
	case yqlCache:
		return c.compileCache(cl)
	case yqlTool:
		return c.compileTool(cl)
	case yqlBody:
		return c.compileBody(cl)
	case yqlLabel:
		return c.compileLabel(cl)
	}
	panic("yql: unreachable field kind")
}

func (cl *yqlClause) String() string {
	switch cl.op {
	case "empty":
		return cl.field.name + " is empty"
	case "not empty":
		return cl.field.name + " is not empty"
	case "in", "not in":
		vals := make([]string, len(cl.values))
		for i, v := range cl.values {
			vals[i] = yqlQuote(v.raw)
		}
		return cl.field.name + " " + cl.op + " (" + strings.Join(vals, ", ") + ")"
	default:
		return cl.field.name + " " + cl.op + " " + yqlQuote(cl.values[0].raw)
	}
}

// yqlQuote renders a value for String(); word-safe values stay bare so
// round-trips stay readable.
func yqlQuote(raw string) string {
	if raw != "" && yqlWordRe.MatchString(raw) {
		return raw
	}
	return `"` + strings.ReplaceAll(raw, `"`, `'`) + `"`
}

// ---------------------------------------------------------------------------
// Lexer

type yqlTokenKind int

const (
	tokWord yqlTokenKind = iota
	tokString
	tokOp
	tokLParen
	tokRParen
	tokComma
	tokEOF
)

type yqlToken struct {
	kind yqlTokenKind
	text string
	pos  int
}

// yqlWordRe matches bare-word values (models, uuids, dates, relative times).
var yqlWordRe = regexp.MustCompile(`^[A-Za-z0-9_.:+/@-]+$`)

func yqlLex(s string) ([]yqlToken, error) {
	var toks []yqlToken
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			toks = append(toks, yqlToken{tokLParen, "(", i})
			i++
		case c == ')':
			toks = append(toks, yqlToken{tokRParen, ")", i})
			i++
		case c == ',':
			toks = append(toks, yqlToken{tokComma, ",", i})
			i++
		case c == '=':
			if i+1 < len(s) && s[i+1] == '=' { // tolerate Jira's "=="? no: matchExpr style
				toks = append(toks, yqlToken{tokOp, "==", i})
				i += 2
			} else {
				toks = append(toks, yqlToken{tokOp, "=", i})
				i++
			}
		case c == '!':
			if i+1 < len(s) && s[i+1] == '=' {
				toks = append(toks, yqlToken{tokOp, "!=", i})
				i += 2
			} else if i+1 < len(s) && s[i+1] == '~' {
				toks = append(toks, yqlToken{tokOp, "!~", i})
				i += 2
			} else {
				return nil, &YQLError{pos: i, input: s, msg: "unexpected '!' (use != or !~)"}
			}
		case c == '>' || c == '<':
			if i+1 < len(s) && s[i+1] == '=' {
				toks = append(toks, yqlToken{tokOp, string(c) + "=", i})
				i += 2
			} else {
				toks = append(toks, yqlToken{tokOp, string(c), i})
				i++
			}
		case c == '~':
			toks = append(toks, yqlToken{tokOp, "~", i})
			i++
		case c == '"' || c == '\'':
			j := strings.IndexByte(s[i+1:], c)
			if j < 0 {
				return nil, &YQLError{pos: i, input: s, msg: "unterminated string"}
			}
			toks = append(toks, yqlToken{tokString, s[i+1 : i+1+j], i})
			i += j + 2
		case yqlWordRe.MatchString(string(c)):
			j := i
			for j < len(s) && yqlWordRe.MatchString(string(s[j])) {
				j++
			}
			toks = append(toks, yqlToken{tokWord, s[i:j], i})
			i = j
		default:
			return nil, &YQLError{pos: i, input: s, msg: fmt.Sprintf("unexpected character %q", string(c))}
		}
	}
	toks = append(toks, yqlToken{tokEOF, "", len(s)})
	return toks, nil
}

// ---------------------------------------------------------------------------
// Parser

var yqlKeywords = map[string]bool{
	"and": true, "or": true, "not": true, "in": true, "is": true,
	"empty": true, "null": true, "order": true, "by": true,
	"asc": true, "desc": true,
}

// YQLError is a user-facing parse/compile error. It carries the position so
// the explorer can highlight the offending token; handlers map it to 400.
type YQLError struct {
	pos   int
	input string
	msg   string
}

func (e *YQLError) Error() string {
	return fmt.Sprintf("YQL: %s at position %d", e.msg, e.pos)
}

// Position is the byte offset of the offending token.
func (e *YQLError) Position() int { return e.pos }

// yqlNoQuery is the shared "no query" result ParseYQL returns for empty and
// whitespace-only input: a non-nil zero-value query whose whereSQL is an
// empty fragment and whose Order is nil — a no-op everywhere a query is
// consumed, so callers need no nil distinction beyond the pointer.
var yqlNoQuery = &RequestQuery{}

// ParseYQL parses and validates a YQL query. An empty (or whitespace-only)
// string returns yqlNoQuery — "no query". Every syntactic, field, operator
// and value check happens here so downstream SQL compilation cannot fail.
func ParseYQL(s string) (*RequestQuery, error) {
	if s == "" {
		return yqlNoQuery, nil
	}
	if len(s) > MaxYQLLen {
		return nil, &YQLError{pos: 0, input: s, msg: fmt.Sprintf("query too long (max %d characters)", MaxYQLLen)}
	}
	toks, err := yqlLex(s)
	if err != nil {
		return nil, err
	}
	p := &yqlParser{toks: toks, input: s}
	root, hasExpr, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	var order *QueryOrder
	if p.peekWord("order") {
		p.next()
		if !p.peekWord("by") {
			return nil, p.errHere("expected 'by' after 'order'")
		}
		p.next()
		order, err = p.parseOrderField()
		if err != nil {
			return nil, err
		}
	}
	if tok := p.next(); tok.kind != tokEOF {
		return nil, &YQLError{pos: tok.pos, input: s, msg: "unexpected trailing input"}
	}
	if !hasExpr && order == nil {
		return yqlNoQuery, nil // whitespace-only: treated as "no query"
	}
	rq := &RequestQuery{root: root, Order: order}
	rq.whereSQL(nil) // dry-run: parse-time guarantee that the tree compiles
	return rq, nil
}

type yqlParser struct {
	toks  []yqlToken
	pos   int
	input string
}

func (p *yqlParser) next() yqlToken {
	tok := p.toks[p.pos]
	if tok.kind != tokEOF {
		p.pos++
	}
	return tok
}

func (p *yqlParser) peek() yqlToken { return p.toks[p.pos] }

// peekWord reports whether the current token is the given keyword
// (case-insensitive).
func (p *yqlParser) peekWord(word string) bool {
	tok := p.peek()
	return tok.kind == tokWord && strings.EqualFold(tok.text, word)
}

// peekWordAt reports whether the token n positions ahead is the keyword.
func (p *yqlParser) peekWordAt(n int, word string) bool {
	idx := p.pos + n
	if idx >= len(p.toks) {
		return false
	}
	tok := p.toks[idx]
	return tok.kind == tokWord && strings.EqualFold(tok.text, word)
}

func (p *yqlParser) errAt(tok yqlToken, msg string) error {
	return &YQLError{pos: tok.pos, input: p.input, msg: msg}
}

func (p *yqlParser) errHere(msg string) error {
	return &YQLError{pos: p.peek().pos, input: p.input, msg: msg}
}

// parseOr parses `andExpr ("or" andExpr)*`. The bool reports whether an
// expression was present at all (false only at expression end — EOF or the
// "order" tail — the empty-query case, distinct from any error).
func (p *yqlParser) parseOr() (yqlNode, bool, error) {
	left, lok, err := p.parseAnd()
	if err != nil {
		return nil, false, err
	}
	for p.peekWord("or") {
		p.next()
		right, rok, err := p.parseAnd()
		if err != nil {
			return nil, false, err
		}
		if !rok {
			return nil, false, p.errHere("expected an expression after 'or'")
		}
		left = &yqlBinary{op: "OR", l: left, r: right}
		lok = true
	}
	return left, lok, nil
}

func (p *yqlParser) parseAnd() (yqlNode, bool, error) {
	left, lok, err := p.parseUnary()
	if err != nil {
		return nil, false, err
	}
	for p.peekWord("and") {
		p.next()
		right, rok, err := p.parseUnary()
		if err != nil {
			return nil, false, err
		}
		if !rok {
			return nil, false, p.errHere("expected an expression after 'and'")
		}
		if lok {
			left = &yqlBinary{op: "AND", l: left, r: right}
		} else {
			left = right
		}
		lok = true
	}
	return left, lok, nil
}

// parseUnary returns ok=false at expression end: EOF or an "order" tail.
// Callers inside and/or loops turn that into an error (dangling operator).
func (p *yqlParser) parseUnary() (yqlNode, bool, error) {
	if p.peekWord("not") {
		p.next()
		child, cok, err := p.parseUnary()
		if err != nil {
			return nil, false, err
		}
		if !cok {
			return nil, false, p.errHere("expected an expression after 'not'")
		}
		return &yqlNot{child: child}, true, nil
	}
	if p.peek().kind == tokLParen {
		p.next()
		node, ok, err := p.parseOr()
		if err != nil {
			return nil, false, err
		}
		if !ok {
			return nil, false, p.errHere("expected an expression after '('")
		}
		if tok := p.next(); tok.kind != tokRParen {
			return nil, false, p.errAt(tok, "expected ')'")
		}
		return node, true, nil
	}
	if p.peek().kind == tokEOF || p.peekWord("order") {
		return nil, false, nil
	}
	node, err := p.parseClause()
	if err != nil {
		return nil, false, err
	}
	return node, true, nil
}

func (p *yqlParser) parseClause() (yqlNode, error) {
	tok := p.next()
	if tok.kind != tokWord {
		return nil, p.errAt(tok, "expected a field name")
	}
	if yqlKeywords[strings.ToLower(tok.text)] {
		return nil, p.errAt(tok, fmt.Sprintf("unexpected keyword %q", strings.ToLower(tok.text)))
	}
	spec, ok := resolveYQLField(tok.text)
	if spec == nil && strings.HasPrefix(strings.ToLower(tok.text), "label.") {
		return nil, p.errAt(tok, "invalid label key")
	}
	if !ok {
		return nil, p.errAt(tok, fmt.Sprintf("unknown field %q (available: %s, label.<key>)", tok.text, strings.Join(yqlFieldNames, ", ")))
	}

	// `field is [not] empty|null`
	if p.peekWord("is") {
		p.next()
		negated := false
		if p.peekWord("not") {
			p.next()
			negated = true
		}
		kw := p.next()
		if kw.kind != tokWord || (kw.text != "empty" && !strings.EqualFold(kw.text, "null")) {
			return nil, p.errAt(kw, "expected 'empty' or 'null' after 'is'")
		}
		if !spec.nullable {
			return nil, p.errAt(tok, fmt.Sprintf("field %q cannot be empty", spec.name))
		}
		op := "empty"
		if negated {
			op = "not empty"
		}
		return &yqlClause{field: spec, op: op}, nil
	}

	// `field [not] in (v, ...)`
	if p.peekWord("not") && p.peekWordAt(1, "in") {
		p.next()
		p.next()
		values, err := p.parseList(spec)
		if err != nil {
			return nil, err
		}
		return &yqlClause{field: spec, op: "not in", values: values}, nil
	}
	if p.peekWord("in") {
		p.next()
		values, err := p.parseList(spec)
		if err != nil {
			return nil, err
		}
		return &yqlClause{field: spec, op: "in", values: values}, nil
	}

	// scalar operator
	opTok := p.next()
	if opTok.kind != tokOp {
		return nil, p.errAt(opTok, fmt.Sprintf("expected an operator after %q (= != > >= < <= ~ !~ in)", spec.name))
	}
	op := opTok.text
	if op == "==" {
		op = "="
	}
	if !yqlOpsFor(spec.kind)[op] {
		return nil, p.errAt(opTok, fmt.Sprintf("operator %q is not supported for field %q", op, spec.name))
	}
	value, err := p.parseValue(spec)
	if err != nil {
		return nil, err
	}
	return &yqlClause{field: spec, op: op, values: []yqlValue{value}}, nil
}

func (p *yqlParser) parseList(spec *yqlFieldSpec) ([]yqlValue, error) {
	if tok := p.next(); tok.kind != tokLParen {
		return nil, p.errAt(tok, "expected '(' after 'in'")
	}
	var values []yqlValue
	for {
		if p.peek().kind == tokRParen {
			if len(values) == 0 {
				return nil, p.errHere("empty 'in' list")
			}
			break
		}
		v, err := p.parseValue(spec)
		if err != nil {
			return nil, err
		}
		values = append(values, v)
		if len(values) > maxYQLListLen {
			return nil, p.errHere(fmt.Sprintf("'in' list too long (max %d values)", maxYQLListLen))
		}
		tok := p.next()
		if tok.kind == tokRParen {
			break
		}
		if tok.kind != tokComma {
			return nil, p.errAt(tok, "expected ',' or ')' in list")
		}
	}
	return values, nil
}

// parseValue lexes one value and validates it against the field kind.
func (p *yqlParser) parseValue(spec *yqlFieldSpec) (yqlValue, error) {
	tok := p.next()
	if tok.kind != tokString && tok.kind != tokWord {
		return yqlValue{}, p.errAt(tok, "expected a value")
	}
	if tok.kind == tokWord && yqlKeywords[strings.ToLower(tok.text)] {
		return yqlValue{}, p.errAt(tok, fmt.Sprintf("keyword %q cannot be a value", strings.ToLower(tok.text)))
	}
	v := yqlValue{raw: tok.text}
	switch spec.kind {
	case yqlNumber:
		n, err := strconv.ParseFloat(tok.text, 64)
		if err != nil {
			return yqlValue{}, p.errAt(tok, fmt.Sprintf("field %q expects a number, got %q", spec.name, tok.text))
		}
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return yqlValue{}, p.errAt(tok, fmt.Sprintf("field %q expects a finite number", spec.name))
		}
		if n < 0 {
			return yqlValue{}, p.errAt(tok, fmt.Sprintf("field %q expects a non-negative number", spec.name))
		}
		v.num = n
	case yqlTime:
		when, err := yqlParseTime(tok.text, time.Now())
		if err != nil {
			return yqlValue{}, p.errAt(tok, err.Error())
		}
		v.when = when
	case yqlCache:
		val := strings.ToLower(tok.text)
		if val != "exact" && val != "semantic" && val != "miss" {
			return yqlValue{}, p.errAt(tok, "field \"cache\" expects exact, semantic or miss")
		}
		v.raw = val
	}
	return v, nil
}

func (p *yqlParser) parseOrderField() (*QueryOrder, error) {
	tok := p.next()
	if tok.kind != tokWord {
		return nil, p.errAt(tok, "expected a field name after 'order by'")
	}
	if yqlKeywords[strings.ToLower(tok.text)] {
		return nil, p.errAt(tok, fmt.Sprintf("unexpected keyword %q", strings.ToLower(tok.text)))
	}
	spec, ok := resolveYQLField(tok.text)
	if spec == nil && strings.HasPrefix(strings.ToLower(tok.text), "label.") {
		return nil, p.errAt(tok, "invalid label key")
	}
	if !ok {
		return nil, p.errAt(tok, fmt.Sprintf("unknown field %q (available: %s, label.<key>)", tok.text, strings.Join(yqlFieldNames, ", ")))
	}
	if spec.kind == yqlLabel {
		return nil, p.errAt(tok, "cannot order by label")
	}
	if !spec.orderable {
		return nil, p.errAt(tok, fmt.Sprintf("field %q cannot be used for ordering", spec.name))
	}
	desc := false
	if p.peekWord("desc") {
		p.next()
		desc = true
	} else if p.peekWord("asc") {
		p.next()
	}
	return &QueryOrder{Field: spec.name, Desc: desc}, nil
}

// yqlRelRe matches relative time offsets: -30m, -24h, -7d, -4w.
var yqlRelRe = regexp.MustCompile(`^-(\d+)([smhdw])$`)

// yqlParseTime accepts RFC3339, YYYY-MM-DD, YYYY-MM-DDTHH:MM, "now" and
// relative offsets. Times without a zone are UTC.
func yqlParseTime(raw string, now time.Time) (time.Time, error) {
	if strings.EqualFold(raw, "now") {
		return now, nil
	}
	if m := yqlRelRe.FindStringSubmatch(raw); m != nil {
		n, _ := strconv.Atoi(m[1])
		var d time.Duration
		switch m[2] {
		case "s":
			d = time.Duration(n) * time.Second
		case "m":
			d = time.Duration(n) * time.Minute
		case "h":
			d = time.Duration(n) * time.Hour
		case "d":
			d = time.Duration(n) * 24 * time.Hour
		case "w":
			d = time.Duration(n) * 7 * 24 * time.Hour
		}
		return now.Add(-d), nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04", "2006-01-02"} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid datetime %q (use RFC3339, YYYY-MM-DD or -24h)", raw)
}

// ---------------------------------------------------------------------------
// SQL compilation

// yqlCompiler accumulates args and renders placeholders continuing the
// numbering of the enclosing filter list ($1 = org, then the flat filters,
// then the YQL fragment).
type yqlCompiler struct {
	args []interface{}
}

func (c *yqlCompiler) ph(v interface{}) string {
	c.args = append(c.args, v)
	return "$" + strconv.Itoa(len(c.args))
}

// whereSQL compiles the query into a parenthesized SQL boolean expression,
// seeded with (and extending) the given args. An order-only query returns an
// empty fragment. The dry-run at the end of ParseYQL guarantees compilation
// cannot fail here.
func (rq *RequestQuery) whereSQL(args []interface{}) (string, []interface{}) {
	if rq.root == nil {
		return "", args
	}
	c := &yqlCompiler{args: args}
	return "(" + rq.root.compile(c) + ")", c.args
}

// numArg sends integral numbers as int64 (clean pgx mapping for int columns).
func numArg(v yqlValue) interface{} {
	if v.num == math.Trunc(v.num) && math.Abs(v.num) < 1e15 {
		return int64(v.num)
	}
	return v.num
}

func resolveYQLField(text string) (*yqlFieldSpec, bool) {
	if spec, ok := yqlFields[strings.ToLower(text)]; ok {
		return spec, true
	}
	lower := strings.ToLower(text)
	if !strings.HasPrefix(lower, "label.") {
		return nil, false
	}
	key, ok := labels.NormalizeKey(lower[len("label."):])
	if !ok {
		return nil, false
	}
	return &yqlFieldSpec{
		name: "label." + key, kind: yqlLabel, nullable: true, labelKey: key,
	}, true
}

func (c *yqlCompiler) compileLabel(cl *yqlClause) string {
	switch cl.op {
	case "in", "not in":
		arms := make([]string, len(cl.values))
		for i, v := range cl.values {
			arms[i] = "rl.labels @> jsonb_build_object(" + c.ph(cl.field.labelKey) + "::text, " + c.ph(v.raw) + "::text)"
		}
		joined := "(" + strings.Join(arms, " OR ") + ")"
		if cl.op == "not in" {
			return "NOT " + joined
		}
		return joined
	}
	key := c.ph(cl.field.labelKey) + "::text"
	col := "(rl.labels ->> " + key + ")"
	switch cl.op {
	case "=":
		return "rl.labels @> jsonb_build_object(" + key + ", " + c.ph(cl.values[0].raw) + "::text)"
	case "!=":
		return col + " <> " + c.ph(cl.values[0].raw) + "::text"
	case "~":
		return "COALESCE(" + col + ", '') ILIKE '%' || " + c.ph(cl.values[0].raw) + " || '%'"
	case "!~":
		return "NOT (COALESCE(" + col + ", '') ILIKE '%' || " + c.ph(cl.values[0].raw) + " || '%')"
	case "empty":
		return col + " IS NULL"
	case "not empty":
		return col + " IS NOT NULL"
	}
	panic("yql: unreachable label op " + cl.op)
}

func (c *yqlCompiler) compileText(cl *yqlClause) string {
	col := cl.field.col
	switch cl.op {
	case "=":
		return col + " = " + c.ph(cl.values[0].raw)
	case "!=":
		return col + " <> " + c.ph(cl.values[0].raw)
	case "~":
		return "COALESCE(" + col + ", '') ILIKE '%' || " + c.ph(cl.values[0].raw) + " || '%'"
	case "!~":
		return "NOT (COALESCE(" + col + ", '') ILIKE '%' || " + c.ph(cl.values[0].raw) + " || '%')"
	case "in":
		arms := make([]string, len(cl.values))
		for i, v := range cl.values {
			arms[i] = col + " = " + c.ph(v.raw)
		}
		return "(" + strings.Join(arms, " OR ") + ")"
	case "not in":
		arms := make([]string, len(cl.values))
		for i, v := range cl.values {
			arms[i] = col + " = " + c.ph(v.raw)
		}
		return "NOT (" + strings.Join(arms, " OR ") + ")"
	case "empty":
		return "(" + col + " IS NULL OR " + col + " = '')"
	case "not empty":
		return "(" + col + " IS NOT NULL AND " + col + " <> '')"
	}
	panic("yql: unreachable text op " + cl.op)
}

func (c *yqlCompiler) compileNumber(cl *yqlClause) string {
	col := cl.field.col
	switch cl.op {
	case "=", "!=":
		sqlOp := "="
		if cl.op == "!=" {
			sqlOp = "<>"
		}
		return col + " " + sqlOp + " " + c.ph(numArg(cl.values[0]))
	case ">", ">=", "<", "<=":
		return col + " " + cl.op + " " + c.ph(numArg(cl.values[0]))
	case "in", "not in":
		arms := make([]string, len(cl.values))
		for i, v := range cl.values {
			arms[i] = col + " = " + c.ph(numArg(v))
		}
		joined := "(" + strings.Join(arms, " OR ") + ")"
		if cl.op == "not in" {
			return "NOT " + joined
		}
		return joined
	case "empty":
		return col + " IS NULL"
	case "not empty":
		return col + " IS NOT NULL"
	}
	panic("yql: unreachable number op " + cl.op)
}

func (c *yqlCompiler) compileTime(cl *yqlClause) string {
	// "=" on timestamps is exact-match; ranges are the intended use.
	return cl.field.col + " " + cl.op + " " + c.ph(cl.values[0].when) + "::timestamptz"
}

func (c *yqlCompiler) compileCache(cl *yqlClause) string {
	// arm renders one list value; "miss" means "no cache hit recorded".
	arm := func(v yqlValue) string {
		if v.raw == "miss" {
			return "COALESCE(rl.cache_hit_type, '') = ''"
		}
		return "rl.cache_hit_type = " + c.ph(v.raw)
	}
	switch cl.op {
	case "=", "!=":
		frag := arm(cl.values[0])
		if cl.op == "!=" {
			return "NOT (" + frag + ")"
		}
		return frag
	case "in", "not in":
		arms := make([]string, len(cl.values))
		for i, v := range cl.values {
			arms[i] = arm(v)
		}
		frag := "(" + strings.Join(arms, " OR ") + ")"
		if cl.op == "not in" {
			return "NOT " + frag
		}
		return frag
	case "empty":
		return arm(yqlValue{raw: "miss"})
	case "not empty":
		return "NOT (" + arm(yqlValue{raw: "miss"}) + ")"
	}
	panic("yql: unreachable cache op " + cl.op)
}

// yqlToolExists is the org-scoped existence test over tool_calls. The outer
// references MUST stay rl-qualified: unqualified request_id/org_id inside the
// subquery would bind to tool_calls' own columns and become always-true.
const yqlToolExists = "EXISTS (SELECT 1 FROM tool_calls tc WHERE tc.request_id = rl.request_id AND tc.org_id = rl.org_id"

func (c *yqlCompiler) compileTool(cl *yqlClause) string {
	nameCond := func(like bool) string {
		if like {
			return yqlToolExists + " AND tc.tool_name ILIKE '%' || " + c.ph(cl.values[0].raw) + " || '%')"
		}
		return yqlToolExists + " AND tc.tool_name = " + c.ph(cl.values[0].raw) + ")"
	}
	switch cl.op {
	case "=":
		return nameCond(false)
	case "~":
		return nameCond(true)
	case "!=":
		return "NOT " + nameCond(false)
	case "!~":
		return "NOT " + nameCond(true)
	case "empty":
		return "NOT " + yqlToolExists + ")"
	case "not empty":
		return yqlToolExists + ")"
	}
	panic("yql: unreachable tool op " + cl.op)
}

// compileBody mirrors the flat ContentSearch (q) clause: a case-insensitive
// substring match over the stored error text and the redacted/truncated
// upstream request and response snapshots.
func (c *yqlCompiler) compileBody(cl *yqlClause) string {
	n := c.ph(cl.values[0].raw)
	trio := "(COALESCE(rl.error, '') ILIKE '%' || " + n + " || '%' OR " +
		"COALESCE(rl.upstream_request::text, '') ILIKE '%' || " + n + " || '%' OR " +
		"COALESCE(rl.response::text, '') ILIKE '%' || " + n + " || '%')"
	if cl.op == "!~" {
		return "NOT " + trio
	}
	return trio
}

// hasBodySearch reports whether a parsed YQL expression inspects payload text.
func (rq *RequestQuery) hasBodySearch() bool {
	if rq == nil {
		return false
	}
	return yqlNodeHasBody(rq.root)
}

func yqlNodeHasBody(node yqlNode) bool {
	switch n := node.(type) {
	case *yqlClause:
		return n.field.kind == yqlBody
	case *yqlBinary:
		return yqlNodeHasBody(n.l) || yqlNodeHasBody(n.r)
	case *yqlNot:
		return yqlNodeHasBody(n.child)
	default:
		return false
	}
}
