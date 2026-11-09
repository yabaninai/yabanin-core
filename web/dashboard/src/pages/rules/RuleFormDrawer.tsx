import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { EXPR_FIELDS, validateMatchExpr } from '../../lib/matchExpr'
import { ApiError } from '../../api/transport'
import {
  createRoutingRule, updateRoutingRule, previewRoutingRule,
  type RoutingRule, type RulePreviewResponse, type RulePreviewSample,
} from '../../api/rules'
import { FormDrawer } from '../../components/astra/FormDrawer'
import { ALL_OPS, appendClause, buildClause, isListOp, showsError, visibleIssues } from './helpers'

// one FormDrawer holds the constructor, the raw expression text and the
// AUX-19 server preview, expanded by default. Contract carried over from
// ASTR-08 / AUX-19:
//   * the expression language is the gateway's own (pkg/rulesengine) and the
//     client linter only mirrors it; the server preview stays the single
//     arbiter of a verdict;
//   * D-18: validation feedback appears only after the operator typed
//     (visibleIssues gate) — an untouched or emptied field is never red;
//     the submit path re-checks and throws, so an invalid draft still
//     cannot be saved (inline error, drawer stays open).

// AUX-19: request-side sample fields for the server preview. org_id is NOT
// among them — the org scope is the admin session's trusted header, so the
// verdict always describes what the gateway would really do.
const PREVIEW_SAMPLE_FIELDS = ['model_requested', 'session_id', 'client_ip', 'user_agent'] as const

export interface RuleDraftPrefill {
  match_expr: string
  target_model: string
  priority?: number
}

export interface RuleFormDrawerProps {
  open: boolean
  /** The rule being edited; null = create. */
  editing: RoutingRule | null
  /** ADL-04 draft from the quality screen (create mode only). */
  prefill?: RuleDraftPrefill | null
  /** The org the rule belongs to (the committed global scope). */
  orgId: string
  /** Best-effort registry slice for the target autocomplete. */
  models: string[]
  onClose: () => void
  /** Called after a successful create/update (the page reloads the list). */
  onSaved: (created: boolean) => void
  /** Any field edit clears the draft banner's provenance on the page. */
  onFieldEdit?: () => void
}

const EMPTY_SAMPLE: RulePreviewSample = {
  model_requested: '', session_id: '', client_ip: '', user_agent: '',
}

export function RuleFormDrawer({ open, editing, prefill, orgId, models, onClose, onSaved, onFieldEdit }: RuleFormDrawerProps) {
  const { t } = useTranslation()
  const [matchExpr, setMatchExpr] = useState('')
  const [targetModel, setTargetModel] = useState('')
  const [priority, setPriority] = useState(100)
  const [builderField, setBuilderField] = useState<string>('model_requested')
  const [builderOp, setBuilderOp] = useState<string>(' starts_with ')
  const [builderValue, setBuilderValue] = useState('')
  // AUX-19: the sample for the SERVER-side preview (org scope rides the
  // trusted session header — deliberately not an input here).
  const [previewSample, setPreviewSample] = useState<RulePreviewSample>({ ...EMPTY_SAMPLE })
  const [previewBusy, setPreviewBusy] = useState(false)
  const [previewResult, setPreviewResult] = useState<RulePreviewResponse | null>(null)
  const [previewError, setPreviewError] = useState<{ invalid: boolean; message: string } | null>(null)

  // Fresh form per open: create starts empty (or from the ADL-04 draft),
  // edit starts from the loaded row.
  useEffect(() => {
    if (!open) return
    setPreviewResult(null)
    setPreviewError(null)
    setPreviewSample({ ...EMPTY_SAMPLE })
    if (editing) {
      setMatchExpr(editing.match_expr)
      setTargetModel(editing.target_model)
      setPriority(editing.priority)
      return
    }
    setMatchExpr(prefill?.match_expr ?? '')
    setTargetModel(prefill?.target_model ?? '')
    setPriority(prefill?.priority ?? 100)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, editing])

  // D-18: the linter always computes; the UI only SHOWS after input.
  const linterIssues = useMemo(() => validateMatchExpr(matchExpr, t), [matchExpr, t])
  const shown = visibleIssues(matchExpr, linterIssues)
  const blocking = showsError(matchExpr, linterIssues)

  // AUX-19: a stale verdict is worse than none — any edit to the draft or
  // the sample clears the last server answer.
  const resetPreview = () => { setPreviewResult(null); setPreviewError(null) }
  const edit = (apply: () => void) => {
    apply()
    onFieldEdit?.()
    resetPreview()
  }

  const submit = async () => {
    if (!matchExpr.trim()) throw new Error(t('rules.exprRequired'))
    // Full linter regardless of the D-18 display gate: an invalid draft
    // never reaches the API (the server would reject it anyway).
    const all = validateMatchExpr(matchExpr, t)
    if (all.some(i => i.level === 'error')) throw new Error(t('rules.fixErrorsFirst'))
    if (!targetModel.trim()) throw new Error(t('rules.targetRequired'))
    if (editing) {
      await updateRoutingRule(editing.id, {
        match_expr: matchExpr.trim(),
        target_model: targetModel.trim(),
        priority,
      })
      onSaved(false)
      return
    }
    await createRoutingRule(orgId, matchExpr.trim(), targetModel.trim(), priority)
    onSaved(true)
  }

  // AUX-19: the honest server verdict — the draft + sample go to
  // POST /api/rules/preview (the same evaluator snapshot the gateway
  // compiles). The button is NOT gated by the client linter: the server is
  // the only arbiter and a malformed expression comes back as a
  // machine-readable 400 the UI renders as "never matches".
  const runPreview = async () => {
    if (!matchExpr.trim() || previewBusy) return
    setPreviewBusy(true)
    resetPreview()
    try {
      const resp = await previewRoutingRule({
        match_expr: matchExpr.trim(),
        target_model: targetModel.trim(),
        priority,
        samples: [{
          model_requested: previewSample.model_requested ?? '',
          session_id: previewSample.session_id ?? '',
          client_ip: previewSample.client_ip ?? '',
          user_agent: previewSample.user_agent ?? '',
        }],
      })
      setPreviewResult(resp)
    } catch (err: unknown) {
      const invalid = err instanceof ApiError && err.code === 'invalid_match_expression'
      setPreviewError({ invalid, message: err instanceof Error ? err.message : String(err) })
    } finally {
      setPreviewBusy(false)
    }
  }

  return (
    <FormDrawer
      open={open}
      kind={t('rules.title')}
      title={editing ? t('rules.editTitle') : t('rules.createTitle')}
      submitLabel={editing ? t('common.save') : t('rules.createRule')}
      onClose={onClose}
      onSubmit={submit}
    >
      {/* Short evaluation-order explanation: visible, not hidden in
          a details block — this is the one fact operators must know. */}
      <p className="text-xs text-[color:var(--astra-text-muted)]">{t('rules.orderHint')}</p>

      <div>
        <label className="mb-1 block text-xs font-medium text-[color:var(--astra-text-muted)]" htmlFor="rf-expr">
          {t('rules.matchExpression')}
        </label>
        <input
          id="rf-expr"
          value={matchExpr}
          onChange={e => edit(() => setMatchExpr(e.target.value))}
          placeholder={t('rules.matchExprPlaceholder')}
          aria-invalid={blocking || undefined}
          aria-describedby="rf-expr-help"
          className={`control min-w-0 max-w-full font-mono text-xs ${blocking ? 'border-[color:var(--astra-danger)]' : ''}`}
        />
        {/* D-18: neutral guidance while the field is empty — no error. */}
        <div id="rf-expr-help" role="status" className="mt-1">
          {shown.length === 0 ? (
            <p className="text-[11px] text-[color:var(--astra-text-muted)]">{t('rules.builderEmpty')}</p>
          ) : (
            <ul className="flex flex-col gap-0.5">
              {shown.map(i => (
                <li key={i.message} className="text-[11px]" style={{ color: i.level === 'error' ? 'var(--astra-danger)' : 'var(--astra-warning)' }}>
                  <span aria-hidden="true">{i.level === 'error' ? '✕ ' : '△ '}</span>
                  {i.message}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      {/* Constructor: field / operator / value → one grammar-shaped clause. */}
      <div className="flex flex-wrap items-end gap-2 border-t border-[color:var(--astra-rule)] pt-3">
        <label className="flex flex-col gap-1 text-xs">
          <span className="text-[color:var(--astra-text-muted)]">{t('rules.field')}</span>
          <select value={builderField} onChange={e => setBuilderField(e.target.value)} className="control w-auto py-1 font-mono text-xs">
            {EXPR_FIELDS.map(f => <option key={f} value={f}>{f}</option>)}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-xs">
          <span className="text-[color:var(--astra-text-muted)]">{t('rules.operator')}</span>
          <select value={builderOp} onChange={e => setBuilderOp(e.target.value)} className="control w-auto py-1 font-mono text-xs">
            {ALL_OPS.map(op => <option key={op} value={op}>{op.trim()}</option>)}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-xs">
          <span className="text-[color:var(--astra-text-muted)]">{t('rules.value')}</span>
          <input
            value={builderValue}
            onChange={e => setBuilderValue(e.target.value)}
            placeholder={isListOp(builderOp) ? t('rules.valueListPlaceholder') : t('rules.valueSinglePlaceholder')}
            list={builderField === 'model_requested' ? 'rf-model-options' : undefined}
            className="control w-44 py-1 font-mono text-xs"
          />
        </label>
        <button
          type="button"
          onClick={() => edit(() => setMatchExpr(cur => appendClause(cur, buildClause(builderField, builderOp, builderValue))))}
          disabled={!builderValue.trim()}
          className="btn-secondary !px-3 !py-1.5 !text-xs"
        >
          {t('rules.insertClause')}
        </button>
        {matchExpr.trim() !== '' && (
          <button
            type="button"
            onClick={() => edit(() => setMatchExpr(''))}
            className="btn-secondary !px-3 !py-1.5 !text-xs"
          >
            {t('rules.clear')}
          </button>
        )}
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div>
          <label className="mb-1 block text-xs font-medium text-[color:var(--astra-text-muted)]" htmlFor="rf-target">
            {t('rules.targetModel')}
          </label>
          <input
            id="rf-target"
            value={targetModel}
            onChange={e => edit(() => setTargetModel(e.target.value))}
            placeholder={t('rules.targetModelPlaceholder')}
            list="rf-model-options"
            className="control w-full font-mono text-xs"
          />
          <datalist id="rf-model-options">
            {models.map(m => <option key={m} value={m} />)}
          </datalist>
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-[color:var(--astra-text-muted)]" htmlFor="rf-priority">
            {t('rules.priority')}
          </label>
          <input
            id="rf-priority"
            type="number"
            value={priority}
            onChange={e => edit(() => setPriority(Number(e.target.value)))}
            className="control w-full"
          />
        </div>
      </div>

      {/* Server preview — expanded by default: the verdict is
          the primary thing to see before saving a routing change. */}
      <section className="rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule)] p-3" aria-label={t('rules.previewTitle')}>
        <p className="text-xs font-semibold text-[color:var(--astra-ink)]">{t('rules.previewTitle')}</p>
        <p className="mt-1 text-[11px] text-[color:var(--astra-text-muted)]">{t('rules.previewHint')}</p>
        <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2">
          {PREVIEW_SAMPLE_FIELDS.map(f => (
            <label key={f} className="flex flex-col gap-1 text-xs">
              <span className="font-medium" style={{ fontFamily: 'var(--astra-font-code)' }}>{f}</span>
              <input
                className="control"
                value={previewSample[f] ?? ''}
                onChange={e => { setPreviewSample(s => ({ ...s, [f]: e.target.value })); resetPreview() }}
                aria-label={f}
                style={{ fontFamily: 'var(--astra-font-code)' }}
              />
            </label>
          ))}
        </div>
        <button
          type="button"
          onClick={() => void runPreview()}
          disabled={!matchExpr.trim() || !targetModel.trim() || previewBusy}
          className="btn-secondary mt-2 !px-3 !py-1.5 !text-xs"
        >
          {previewBusy ? t('rules.previewRunning') : t('rules.previewRun')}
        </button>
        {previewError && (
          <p className="mt-2 text-sm font-medium" style={{ color: 'var(--astra-danger)' }} role="status">
            <span aria-hidden="true">✕ </span>
            {previewError.invalid ? t('rules.previewInvalid') : previewError.message}
          </p>
        )}
        {previewResult && previewResult.results.length > 0 && (() => {
          const r = previewResult.results[0]!
          const color = r.matched ? 'var(--astra-success)' : 'var(--astra-text-muted)'
          const label = r.matched
            ? t('rules.previewMatchedTarget', { target: r.effective_model })
            : t('rules.previewNoMatch')
          return (
            <div role="status" className="mt-2">
              <p className="text-sm font-medium" style={{ color }}>
                <span aria-hidden="true">{r.matched ? '● ' : '○ '}</span>
                {label}
              </p>
              {r.terms.length > 0 && (
                <ul className="mt-1 flex flex-col gap-0.5 text-xs text-[color:var(--astra-text-muted)]">
                  {r.terms.map((term, i) => (
                    <li key={i} className="break-all font-mono">
                      <span aria-hidden="true" style={{ color: term.matched ? 'var(--astra-success)' : 'inherit' }}>
                        {term.matched ? '✓' : '✗'}
                      </span>{' '}
                      {term.field} {term.operator} {term.value} → {term.actual}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )
        })()}
      </section>

      <details>
        <summary className="cursor-pointer text-xs font-medium text-[color:var(--astra-text-muted)]">{t('rules.syntaxReference')}</summary>
        <div className="mt-2 flex flex-col gap-2 text-xs text-[color:var(--astra-text-muted)]">
          <p>{t('rules.syntaxIntro')}</p>
          <pre className="overflow-x-auto rounded-[length:var(--astra-radius-control)] bg-[color:var(--astra-surface-muted)] p-2 font-mono text-[11px] leading-relaxed">{`model_requested starts_with "gpt-4"
model_requested in gpt-4,gpt-4o && org_id != acme
client_ip == 10.0.0.1 || user_agent contains opencode`}</pre>
          <p>{t('rules.syntaxOutcome')}</p>
        </div>
      </details>
    </FormDrawer>
  )
}
