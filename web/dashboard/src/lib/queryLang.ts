// YQL (Yabanin Query Language) — the client mirror of pkg/adminstore/yql.go.
// The server is the authority; this module exists purely for UX: instant
// validation (no round-trip), removable chips, an add-filter builder and a
// canonical serializer whose output the server re-parses identically.
//
// Grammar (kept in lockstep with the Go parser — divergence is a bug):
//
//   query   := orExpr ["order" "by" field [("asc"|"desc")]]
//   orExpr  := andExpr ("or" andExpr)*
//   andExpr := unary ("and" unary)*
//   unary   := "not" unary | "(" orExpr ")" | clause
//   clause  := field op value
//            | field "in" "(" value ("," value)* ")"
//            | field "not" "in" "(" ... ")"
//            | field "is" ["not"] ("empty"|"null")
//   op      := "=" "==" "!=" ">" ">=" "<" "<=" "~" "!~"

export const YQL_MAX_LEN = 2000
export const YQL_MAX_LIST = 40

export type FieldKind = 'text' | 'number' | 'time' | 'cache' | 'tool' | 'body'

export interface YqlFieldMeta {
  name: string
  kind: FieldKind
  nullable: boolean
  orderable: boolean
  aliases: string[]
}

// Canonical field registry (order = picker order). Mirrors yqlFields in Go.
export const YQL_FIELDS: YqlFieldMeta[] = [
  { name: 'request', kind: 'text', nullable: false, orderable: true, aliases: ['request_id'] },
  { name: 'created', kind: 'time', nullable: false, orderable: true, aliases: ['created_at'] },
  { name: 'model', kind: 'text', nullable: false, orderable: true, aliases: ['model_used'] },
  { name: 'model_requested', kind: 'text', nullable: true, orderable: true, aliases: [] },
  { name: 'status', kind: 'number', nullable: false, orderable: true, aliases: ['status_code'] },
  { name: 'cost', kind: 'number', nullable: false, orderable: true, aliases: ['cost_usd'] },
  { name: 'tokens', kind: 'number', nullable: false, orderable: true, aliases: [] },
  { name: 'tokens_in', kind: 'number', nullable: false, orderable: true, aliases: [] },
  { name: 'tokens_out', kind: 'number', nullable: false, orderable: true, aliases: [] },
  { name: 'latency', kind: 'number', nullable: false, orderable: true, aliases: ['duration', 'duration_ms'] },
  { name: 'ttft', kind: 'number', nullable: true, orderable: true, aliases: ['first_token_ms'] },
  { name: 'retries', kind: 'number', nullable: true, orderable: true, aliases: ['retry_count'] },
  { name: 'attempts', kind: 'number', nullable: true, orderable: true, aliases: ['attempt_count'] },
  { name: 'task', kind: 'text', nullable: true, orderable: true, aliases: ['task_id'] },
  { name: 'agent', kind: 'text', nullable: true, orderable: true, aliases: ['agent_id'] },
  { name: 'cache', kind: 'cache', nullable: true, orderable: true, aliases: ['cache_hit', 'cache_hit_type'] },
  { name: 'tool', kind: 'tool', nullable: true, orderable: false, aliases: ['tool_name'] },
  { name: 'error', kind: 'text', nullable: true, orderable: true, aliases: [] },
  { name: 'text', kind: 'body', nullable: false, orderable: false, aliases: [] },
]

const FIELD_BY_KEY: Map<string, YqlFieldMeta> = (() => {
  const map = new Map<string, YqlFieldMeta>()
  for (const f of YQL_FIELDS) {
    map.set(f.name, f)
    for (const a of f.aliases) map.set(a, f)
  }
  return map
})()

const LABEL_KEY = /^[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)*$/

function labelField(raw: string): YqlFieldMeta | null {
  const lower = raw.toLowerCase()
  if (!lower.startsWith('label.')) return null
  const key = lower.slice('label.'.length)
  if (!LABEL_KEY.test(key)) return null
  return { name: `label.${key}`, kind: 'text', nullable: true, orderable: false, aliases: [] }
}

export type YqlOp = '=' | '!=' | '>' | '>=' | '<' | '<=' | '~' | '!~' | 'in' | 'not in' | 'empty' | 'not empty'

export interface YqlClause {
  kind: 'clause'
  field: string
  op: YqlOp
  values: string[]
}

export interface YqlBinary {
  kind: 'binary'
  op: 'AND' | 'OR'
  left: YqlNode
  right: YqlNode
}

export interface YqlNot {
  kind: 'not'
  child: YqlNode
}

export type YqlNode = YqlClause | YqlBinary | YqlNot

export interface YqlOrder {
  field: string
  desc: boolean
}

export type YqlParse =
  | { ok: true; root: YqlNode | null; order: YqlOrder | null; canonical: string }
  | { ok: false; error: string; pos: number }

// ---------------------------------------------------------------------------
// Lexer (mirrors yqlLex)

const WORD_RE = /^[A-Za-z0-9_.:+/@-]+$/

type TokenKind = 'word' | 'string' | 'op' | 'lparen' | 'rparen' | 'comma' | 'eof'
interface Token { kind: TokenKind; text: string; pos: number }

function lex(input: string): { tokens: Token[] } | { error: string; pos: number } {
  const tokens: Token[] = []
  let i = 0
  while (i < input.length) {
    const c = input[i]
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') { i++; continue }
    if (c === '(') { tokens.push({ kind: 'lparen', text: '(', pos: i++ }); continue }
    if (c === ')') { tokens.push({ kind: 'rparen', text: ')', pos: i++ }); continue }
    if (c === ',') { tokens.push({ kind: 'comma', text: ',', pos: i++ }); continue }
    if (c === '=') {
      if (input[i + 1] === '=') { tokens.push({ kind: 'op', text: '==', pos: i }); i += 2 } else { tokens.push({ kind: 'op', text: '=', pos: i++ }) }
      continue
    }
    if (c === '!') {
      if (input[i + 1] === '=') { tokens.push({ kind: 'op', text: '!=', pos: i }); i += 2 }
      else if (input[i + 1] === '~') { tokens.push({ kind: 'op', text: '!~', pos: i }); i += 2 }
      else return { error: "unexpected '!' (use != or !~)", pos: i }
      continue
    }
    if (c === '>' || c === '<') {
      if (input[i + 1] === '=') { tokens.push({ kind: 'op', text: c + '=', pos: i }); i += 2 } else { tokens.push({ kind: 'op', text: c, pos: i++ }) }
      continue
    }
    if (c === '~') { tokens.push({ kind: 'op', text: '~', pos: i++ }); continue }
    if (c === '"' || c === "'") {
      const end = input.indexOf(c, i + 1)
      if (end < 0) return { error: 'unterminated string', pos: i }
      tokens.push({ kind: 'string', text: input.slice(i + 1, end), pos: i })
      i = end + 1
      continue
    }
    if (WORD_RE.test(c)) {
      let j = i
      while (j < input.length && WORD_RE.test(input[j])) j++
      tokens.push({ kind: 'word', text: input.slice(i, j), pos: i })
      i = j
      continue
    }
    return { error: `unexpected character "${c}"`, pos: i }
  }
  tokens.push({ kind: 'eof', text: '', pos: input.length })
  return { tokens }
}

const KEYWORDS = new Set(['and', 'or', 'not', 'in', 'is', 'empty', 'null', 'order', 'by', 'asc', 'desc'])

// ---------------------------------------------------------------------------
// Value validation (mirrors parseValue / yqlParseTime)

const NUM_RE = /^\d+(\.\d+)?([eE][+-]?\d+)?$/
const REL_RE = /^-(\d+)([smhdw])$/
const DATE_RE = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})?)?$/

function validateValue(field: YqlFieldMeta, raw: string): string | null {
  switch (field.kind) {
    case 'number':
      if (!NUM_RE.test(raw)) return `field "${field.name}" expects a number, got "${raw}"`
      return null
    case 'cache': {
      const v = raw.toLowerCase()
      if (v !== 'exact' && v !== 'semantic' && v !== 'miss') return 'field "cache" expects exact, semantic or miss'
      return null
    }
    case 'time':
      if (!/^now$/i.test(raw) && !REL_RE.test(raw) && !DATE_RE.test(raw)) {
        return `invalid datetime "${raw}" (use RFC3339, YYYY-MM-DD or -24h)`
      }
      return null
    default:
      return null
  }
}

// opsForField lists the operators the builder UI offers for a field.
export function opsForField(field: YqlFieldMeta): YqlOp[] {
  switch (field.kind) {
    case 'text': return ['=', '!=', '~', '!~', 'in', 'not in', 'empty', 'not empty']
    case 'number': return ['=', '!=', '>', '>=', '<', '<=', 'in', 'not in', ...(field.nullable ? (['empty', 'not empty'] as YqlOp[]) : [])]
    case 'time': return ['>=', '<=', '>', '<', '=']
    case 'cache': return ['=', '!=', 'in', 'not in', 'empty', 'not empty']
    case 'tool': return ['=', '!=', '~', '!~', 'empty', 'not empty']
    case 'body': return ['~', '!~']
  }
}

function opAllowed(field: YqlFieldMeta, op: YqlOp): boolean {
  return opsForField(field).includes(op)
}

// ---------------------------------------------------------------------------
// Parser (mirrors the Go recursive descent)

class Parser {
  private pos = 0
  // Explicit field (no constructor parameter property): this module must stay
  // erasable-TS-only so `node --test --experimental-strip-types` can run the
  // parity tests without a transpiler.
  private readonly tokens: Token[]
  constructor(tokens: Token[]) {
    this.tokens = tokens
  }

  private next(): Token { return this.tokens[this.pos++] }
  private peek(): Token { return this.tokens[this.pos] }
  private peekIsWord(word: string, offset = 0): boolean {
    const tok = this.tokens[this.pos + offset]
    return !!tok && tok.kind === 'word' && tok.text.toLowerCase() === word
  }
  private err(msg: string, pos?: number): { error: string; pos: number } {
    // peek() can sit past the array after the last token is consumed — the
    // trailing eof token is always a valid position anchor.
    const anchor = this.tokens[this.pos] ?? this.tokens[this.tokens.length - 1]
    return { error: msg, pos: pos ?? anchor.pos }
  }

  parse(): { root: YqlNode | null; order: YqlOrder | null } | { error: string; pos: number } {
    const root = this.parseOr()
    if ('error' in root) return root
    let order: YqlOrder | null = null
    if (this.peekIsWord('order')) {
      this.next()
      if (!this.peekIsWord('by')) return this.err("expected 'by' after 'order'")
      this.next()
      const ord = this.parseOrderField()
      if ('error' in ord) return ord
      order = ord
    }
    const tail = this.next()
    if (tail.kind !== 'eof') return this.err('unexpected trailing input', tail.pos)
    if (!root.root && !order) return { root: null, order: null } // whitespace-only
    return { root: root.root, order }
  }

  private parseOr(): { root: YqlNode | null } | { error: string; pos: number } {
    const left = this.parseAnd()
    if ('error' in left) return left
    let node = left.root
    while (this.peekIsWord('or')) {
      this.next()
      const right = this.parseAnd()
      if ('error' in right) return right
      if (!right.root) return this.err("expected an expression after 'or'")
      node = { kind: 'binary', op: 'OR', left: node ?? right.root, right: right.root }
    }
    return { root: node }
  }

  private parseAnd(): { root: YqlNode | null } | { error: string; pos: number } {
    const left = this.parseUnary()
    if ('error' in left) return left
    let node = left.root
    while (this.peekIsWord('and')) {
      this.next()
      const right = this.parseUnary()
      if ('error' in right) return right
      if (!right.root) return this.err("expected an expression after 'and'")
      node = node
        ? { kind: 'binary', op: 'AND', left: node, right: right.root }
        : right.root
    }
    return { root: node }
  }

  private parseUnary(): { root: YqlNode | null } | { error: string; pos: number } {
    if (this.peekIsWord('not')) {
      this.next()
      const child = this.parseUnary()
      if ('error' in child) return child
      if (!child.root) return this.err("expected an expression after 'not'")
      return { root: { kind: 'not', child: child.root } }
    }
    if (this.peek().kind === 'lparen') {
      this.next()
      const inner = this.parseOr()
      if ('error' in inner) return inner
      if (!inner.root) return this.err("expected an expression after '('")
      if (this.next().kind !== 'rparen') return this.err("expected ')'")
      return { root: inner.root }
    }
    if (this.peek().kind === 'eof' || this.peekIsWord('order')) return { root: null }
    return this.parseClause()
  }

  private parseClause(): { root: YqlNode } | { error: string; pos: number } {
    const tok = this.next()
    if (tok.kind !== 'word') return this.err('expected a field name', tok.pos)
    const lower = tok.text.toLowerCase()
    if (KEYWORDS.has(lower)) return this.err(`unexpected keyword "${lower}"`, tok.pos)
    const field = FIELD_BY_KEY.get(lower) ?? labelField(tok.text)
    if (!field && lower.startsWith('label.')) return this.err('invalid label key', tok.pos)
    if (!field) return this.err(`unknown field "${tok.text}" (available: label.<key>)`, tok.pos)

    if (this.peekIsWord('is')) {
      this.next()
      let negated = false
      if (this.peekIsWord('not')) { this.next(); negated = true }
      const kw = this.next()
      if (kw.kind !== 'word' || (kw.text !== 'empty' && kw.text.toLowerCase() !== 'null')) {
        return this.err("expected 'empty' or 'null' after 'is'", kw.pos)
      }
      if (!field.nullable) return this.err(`field "${field.name}" cannot be empty`, tok.pos)
      return { root: { kind: 'clause', field: field.name, op: negated ? 'not empty' : 'empty', values: [] } }
    }

    if (this.peekIsWord('not') && this.peekIsWord('in', 1)) {
      this.next(); this.next()
      const list = this.parseList(field)
      if ('error' in list) return list
      return { root: { kind: 'clause', field: field.name, op: 'not in', values: list.values } }
    }
    if (this.peekIsWord('in')) {
      this.next()
      const list = this.parseList(field)
      if ('error' in list) return list
      return { root: { kind: 'clause', field: field.name, op: 'in', values: list.values } }
    }

    const opTok = this.next()
    if (opTok.kind !== 'op') {
      return this.err(`expected an operator after "${field.name}" (= != > >= < <= ~ !~ in)`, opTok.pos)
    }
    const op = (opTok.text === '==' ? '=' : opTok.text) as YqlOp
    if (!opAllowed(field, op)) {
      return this.err(`operator "${op}" is not supported for field "${field.name}"`, opTok.pos)
    }
    const value = this.parseValue(field)
    if ('error' in value) return value
    return { root: { kind: 'clause', field: field.name, op, values: [value.value] } }
  }

  private parseList(field: YqlFieldMeta): { values: string[] } | { error: string; pos: number } {
    if (this.next().kind !== 'lparen') return this.err("expected '(' after 'in'")
    const values: string[] = []
    for (;;) {
      if (this.peek().kind === 'rparen') {
        if (values.length === 0) return this.err("empty 'in' list")
        break
      }
      const v = this.parseValue(field)
      if ('error' in v) return v
      values.push(v.value)
      if (values.length > YQL_MAX_LIST) return this.err(`'in' list too long (max ${YQL_MAX_LIST} values)`)
      const tok = this.next()
      if (tok.kind === 'rparen') break
      if (tok.kind !== 'comma') return this.err("expected ',' or ')' in list", tok.pos)
    }
    return { values }
  }

  private parseValue(field: YqlFieldMeta): { value: string } | { error: string; pos: number } {
    const tok = this.next()
    if (tok.kind !== 'string' && tok.kind !== 'word') return this.err('expected a value', tok.pos)
    if (tok.kind === 'word' && KEYWORDS.has(tok.text.toLowerCase())) {
      return this.err(`keyword "${tok.text.toLowerCase()}" cannot be a value`, tok.pos)
    }
    if (field.kind === 'cache') {
      const v = tok.text.toLowerCase()
      if (v !== 'exact' && v !== 'semantic' && v !== 'miss') {
        return { error: 'field "cache" expects exact, semantic or miss', pos: tok.pos }
      }
      return { value: v }
    }
    const invalid = validateValue(field, tok.text)
    if (invalid) return { error: invalid, pos: tok.pos }
    return { value: tok.text }
  }

  private parseOrderField(): YqlOrder | { error: string; pos: number } {
    const tok = this.next()
    if (tok.kind !== 'word') return this.err('expected a field name after "order by"', tok.pos)
    const lower = tok.text.toLowerCase()
    if (KEYWORDS.has(lower)) return this.err(`unexpected keyword "${lower}"`, tok.pos)
    const field = FIELD_BY_KEY.get(lower) ?? labelField(tok.text)
    if (!field && lower.startsWith('label.')) return this.err('invalid label key', tok.pos)
    if (!field) return this.err(`unknown field "${tok.text}" (available: label.<key>)`, tok.pos)
    if (field.name.startsWith('label.')) return this.err('cannot order by label', tok.pos)
    if (!field.orderable) return this.err(`field "${field.name}" cannot be used for ordering`, tok.pos)
    let desc = false
    if (this.peekIsWord('desc')) { this.next(); desc = true }
    else if (this.peekIsWord('asc')) { this.next() }
    return { field: field.name, desc }
  }
}

// ---------------------------------------------------------------------------
// Serializer (canonical form — the string sent to the server)

export function quoteYqlValue(raw: string): string {
  if (raw !== '' && WORD_RE.test(raw)) return raw
  return `"${raw.replace(/"/g, "'")}"`
}

function clauseToString(cl: YqlClause): string {
  switch (cl.op) {
    case 'empty': return `${cl.field} is empty`
    case 'not empty': return `${cl.field} is not empty`
    case 'in': case 'not in':
      return `${cl.field} ${cl.op} (${cl.values.map(quoteYqlValue).join(', ')})`
    default:
      return `${cl.field} ${cl.op} ${quoteYqlValue(cl.values[0])}`
  }
}

/** Canonical single-clause label (chips, add-filter preview). */
export { clauseToString }

export function nodeToString(node: YqlNode): string {
  switch (node.kind) {
    case 'clause': return clauseToString(node)
    case 'not': return `NOT (${nodeToString(node.child)})`
    case 'binary': {
      const left = node.left.kind === 'binary' ? `(${nodeToString(node.left)})` : nodeToString(node.left)
      const right = node.right.kind === 'binary' ? `(${nodeToString(node.right)})` : nodeToString(node.right)
      return `${left} ${node.op} ${right}`
    }
  }
}

export function serializeYQL(root: YqlNode | null, order: YqlOrder | null): string {
  const parts: string[] = []
  if (root) parts.push(nodeToString(root))
  if (order) parts.push(orderToString(order))
  return parts.join(' ')
}

/** Canonical order-by label ("order by field [desc]"). */
export function orderToString(order: YqlOrder): string {
  return `order by ${order.field}${order.desc ? ' desc' : ''}`
}

// ---------------------------------------------------------------------------
// Public API

export function parseYQL(input: string): YqlParse {
  const trimmed = input.trim()
  if (trimmed === '') return { ok: true, root: null, order: null, canonical: '' }
  if (input.length > YQL_MAX_LEN) {
    return { ok: false, error: `query too long (max ${YQL_MAX_LEN} characters)`, pos: 0 }
  }
  const lexed = lex(input)
  if ('error' in lexed) return { ok: false, error: lexed.error, pos: lexed.pos }
  const parsed = new Parser(lexed.tokens).parse()
  if ('error' in parsed) return { ok: false, error: parsed.error, pos: parsed.pos }
  return { ok: true, root: parsed.root, order: parsed.order, canonical: serializeYQL(parsed.root, parsed.order) }
}

// flattenAnd splits a root into top-level AND-ed leaf clauses (chip rows) and
// the remaining subtree (rendered as one grouped chip). Anything that is not
// an AND-chain yields a single grouped chip.
export function flattenAnd(root: YqlNode | null): { leaves: YqlClause[]; rest: YqlNode | null } {
  if (!root) return { leaves: [], rest: null }
  if (root.kind === 'clause') return { leaves: [root], rest: null }
  if (root.kind !== 'binary' || root.op !== 'AND') return { leaves: [], rest: root }
  const left = flattenAnd(root.left)
  const right = flattenAnd(root.right)
  return { leaves: [...left.leaves, ...right.leaves], rest: left.rest && right.rest
    ? { kind: 'binary', op: 'AND', left: left.rest, right: right.rest }
    : (left.rest ?? right.rest) }
}

// rebuildFromLeaves reconstitutes an AND chain after chip removal/edit.
export function rebuildFromLeaves(leaves: YqlClause[], rest: YqlNode | null): YqlNode | null {
  const nodes: YqlNode[] = [...leaves, ...(rest ? [rest] : [])]
  if (nodes.length === 0) return null
  return nodes.reduce((acc: YqlNode, n): YqlNode => (
    { kind: 'binary' as const, op: 'AND' as const, left: acc, right: n }
  ))
}

// appendClause adds `clause` to a query string as a top-level AND (the common
// builder action); returns the new canonical text.
export function appendClause(text: string, clause: YqlClause, order: YqlOrder | null): string {
  const parsed = parseYQL(text)
  const root = parsed.ok ? parsed.root : null
  const next = root ? { kind: 'binary' as const, op: 'AND' as const, left: root, right: clause } : clause
  return serializeYQL(next, order)
}

export function removeLeaf(text: string, index: number): string {
  const parsed = parseYQL(text)
  if (!parsed.ok) return text
  const { leaves, rest } = flattenAnd(parsed.root)
  const order = parsed.order
  if (index < 0 || index >= leaves.length) return text
  const nextLeaves = leaves.filter((_, i) => i !== index)
  return serializeYQL(rebuildFromLeaves(nextLeaves, rest), order)
}

export function fieldMeta(name: string): YqlFieldMeta | undefined {
  return FIELD_BY_KEY.get(name)
}
