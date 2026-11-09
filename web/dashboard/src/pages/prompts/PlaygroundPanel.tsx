import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { getPrompt, listPartials, type Prompt, type PromptDetail as PromptDetailData, type PromptLabelName } from '../../api/prompts'
import { useScopedQuery } from '../../hooks/useScopedQuery'
import { StateNotice } from '../../components/astra/StateNotice'
import {
  buildChatCurl, extractTemplateVars, extractPartialRefs, renderTemplateClient,
  type TemplateRenderResult,
} from '../../lib/promptRender'

// template; {{var}} placeholders auto-detect the variable fields;
// {{partials.name}} references resolve from the org partials. Render is
// CLIENT-SIDE ONLY (the same one-pass semantics as the server's
// RenderTemplate) and explicitly labeled preview-only — no model call is
// made from here. "Copy as curl" builds a ready /v1/chat/completions command
// whose system message is the rendered template; the API key stays a shell
// variable the operator owns (the UI never handles credentials).

export function PlaygroundPanel({ org, prompts }: { org: string; prompts: Prompt[] }) {
  const { t } = useTranslation()
  const [promptId, setPromptId] = useState('')

  useEffect(() => {
    if (promptId === '' && prompts.length > 0) setPromptId(prompts[0]!.id)
    if (promptId !== '' && !prompts.some(p => p.id === promptId)) setPromptId('')
  }, [prompts, promptId])

  const detailFetcher = useCallback(
    async (signal: AbortSignal) => getPrompt(org, promptId, { signal }),
    [org, promptId],
  )
  const detail = useScopedQuery<PromptDetailData>({
    key: `playground|${org}|${promptId}`,
    org,
    enabled: promptId !== '',
    fetcher: detailFetcher,
  })

  const partialsFetcher = useCallback(async (signal: AbortSignal) => listPartials(org, { signal }), [org])
  const partials = useScopedQuery({
    key: `playground-partials|${org}`,
    org,
    fetcher: partialsFetcher,
  })

  const versions = useMemo(() => detail.data?.versions ?? [], [detail.data])
  const labels = useMemo(() => detail.data?.labels ?? [], [detail.data])

  const [labelName, setLabelName] = useState<PromptLabelName | ''>('')
  const effectiveLabel: PromptLabelName | '' = labelName !== '' && labels.some(l => l.label === labelName)
    ? labelName
    : (labels.find(l => l.label === 'draft') ?? labels[0])?.label ?? ''

  const labeledVersion = effectiveLabel
    ? labels.find(l => l.label === effectiveLabel)?.version ?? null
    : null
  // Without any label binding the playground falls back to the latest version
  // and says so (the draft label normally exists — createPrompt binds it).
  const resolved: PromptDetailData['versions'][number] | null =
    versions.find(v => v.version === labeledVersion) ?? versions[0] ?? null
  const template = resolved?.template ?? ''

  const varNames = useMemo(() => extractTemplateVars(template), [template])
  const partialRefs = useMemo(() => extractPartialRefs(template), [template])

  const [varValues, setVarValues] = useState<Record<string, string>>({})
  useEffect(() => { setVarValues({}) }, [template])

  const [rendered, setRendered] = useState<TemplateRenderResult | null>(null)
  const render = () => {
    const partialMap: Record<string, string> = {}
    for (const ref of partialRefs) {
      partialMap[ref] = (partials.data ?? []).find(p => p.name === ref)?.body ?? ''
    }
    setRendered(renderTemplateClient(template, varValues, partialMap))
  }

  const [gatewayUrl, setGatewayUrl] = useState('')
  const [model, setModel] = useState('')
  const [userText, setUserText] = useState('')
  useEffect(() => {
    const params = (resolved?.params ?? null) as Record<string, unknown> | null
    setModel(typeof params?.model === 'string' ? params.model : '')
  }, [resolved])

  const curl = useMemo(() => {
    if (!rendered?.ok) return ''
    return buildChatCurl({ baseUrl: gatewayUrl, model: model.trim(), system: rendered.text, user: userText })
  }, [rendered, gatewayUrl, model, userText])

  const missingPartials = partialRefs.filter(ref => !(partials.data ?? []).some(p => p.name === ref))

  const [copied, setCopied] = useState(false)
  const copiedTimer = useRef<ReturnType<typeof setTimeout>>()
  useEffect(() => () => clearTimeout(copiedTimer.current), [])
  const copyCurl = async () => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(curl)
      } else {
        const ta = document.createElement('textarea')
        ta.value = curl
        ta.style.position = 'fixed'
        ta.style.opacity = '0'
        document.body.appendChild(ta)
        ta.select()
        document.execCommand('copy')
        document.body.removeChild(ta)
      }
      setCopied(true)
      clearTimeout(copiedTimer.current)
      copiedTimer.current = setTimeout(() => setCopied(false), 1500)
    } catch {
      // Clipboard denied — the command stays visible for manual selection.
    }
  }

  if (prompts.length === 0) {
    return <StateNotice state="empty" message={t('prompts.playgroundEmpty')} />
  }

  const control = 'control w-full'

  return (
    <div className="flex flex-col gap-4">
      <div className="card flex flex-col gap-4 p-4">
        <div className="grid gap-3 md:grid-cols-2">
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('prompts.playgroundPrompt')}</span>
            <select className={control} value={promptId} onChange={e => { setPromptId(e.target.value); setRendered(null) }}>
              {prompts.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('prompts.playgroundLabel')}</span>
            <select
              className={control}
              value={effectiveLabel}
              onChange={e => { setLabelName(e.target.value as PromptLabelName); setRendered(null) }}
              disabled={labels.length === 0}
            >
              {labels.length === 0
                ? <option value="">{t('prompts.playgroundNoLabels')}</option>
                : labels.map(l => <option key={l.label} value={l.label}>{t('prompts.playgroundLabelOption', { label: l.label, version: l.version })}</option>)}
            </select>
          </label>
        </div>

        {detail.error && <StateNotice state="error" message={detail.error} />}
        {labels.length === 0 && !detail.loading && (
          <p className="text-sm text-[color:var(--astra-text-muted)]">{t('prompts.playgroundLatestFallback', { version: resolved?.version ?? 0 })}</p>
        )}

        {varNames.length > 0 && (
          <div className="flex flex-col gap-2">
            <span className="text-sm text-[color:var(--astra-text-muted)]">{t('prompts.playgroundVars')}</span>
            <div className="grid gap-3 md:grid-cols-2">
              {varNames.map(name => (
                <label key={name} className="flex flex-col gap-1 text-sm">
                  <span className="font-mono text-xs text-[color:var(--astra-ink)]">{`{{${name}}}`}</span>
                  <input
                    className={control}
                    value={varValues[name] ?? ''}
                    onChange={e => setVarValues(prev => ({ ...prev, [name]: e.target.value }))}
                    spellCheck={false}
                  />
                </label>
              ))}
            </div>
          </div>
        )}

        {partialRefs.length > 0 && (
          <p className="text-xs text-[color:var(--astra-text-muted)]">
            {missingPartials.length === 0
              ? t('prompts.playgroundPartialsOk', { names: partialRefs.join(', ') })
              : t('prompts.playgroundPartialsMissing', { names: missingPartials.join(', ') })}
          </p>
        )}

        <div className="flex flex-wrap items-center gap-3">
          <button type="button" className="btn-primary" onClick={render} disabled={template === ''}>
            {t('prompts.playgroundRender')}
          </button>
          <span className="inline-flex items-center gap-1 rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] px-2 py-1 text-xs text-[color:var(--astra-text-muted)]">
            {t('prompts.playgroundPreviewOnly')}
          </span>
          {resolved && (
            <span className="text-sm text-[color:var(--astra-text-muted)]">
              {t('prompts.playgroundResolvedVersion', { version: resolved.version })}
            </span>
          )}
        </div>

        {rendered && (rendered.ok ? (
          <div className="flex flex-col gap-1">
            <span className="text-sm text-[color:var(--astra-text-muted)]">{t('prompts.playgroundRendered')}</span>
            <pre
              data-testid="playground-render-output"
              className="max-h-[40vh] overflow-auto rounded-[length:var(--astra-radius-panel)] border border-[color:var(--astra-rule)] bg-[color:var(--astra-surface-muted)] p-3 font-mono text-xs whitespace-pre-wrap text-[color:var(--astra-ink)]"
            >
              {rendered.text}
            </pre>
          </div>
        ) : (
          <p role="alert" className="text-sm" style={{ color: 'var(--astra-danger)' }}>
            {t('prompts.playgroundRenderFailed')}: {rendered.error}
          </p>
        ))}
      </div>

      <div className="card flex flex-col gap-3 p-4">
        <span className="text-sm font-medium text-[color:var(--astra-ink)]">{t('prompts.playgroundCurlTitle')}</span>
        <p className="text-xs text-[color:var(--astra-text-muted)]">{t('prompts.playgroundCurlHint')}</p>
        <div className="grid gap-3 md:grid-cols-3">
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('prompts.playgroundGatewayUrl')}</span>
            <input
              className={control}
              value={gatewayUrl}
              onChange={e => setGatewayUrl(e.target.value)}
              placeholder="https://gateway.example.test"
              spellCheck={false}
            />
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('prompts.playgroundModel')}</span>
            <input className={control} value={model} onChange={e => setModel(e.target.value)} spellCheck={false} />
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('prompts.playgroundUserMessage')}</span>
            <input className={control} value={userText} onChange={e => setUserText(e.target.value)} />
          </label>
        </div>
        {curl !== '' && (
          <pre
            data-testid="playground-curl-output"
            className="max-h-[30vh] overflow-auto rounded-[length:var(--astra-radius-panel)] border border-[color:var(--astra-rule)] bg-[color:var(--astra-surface-muted)] p-3 font-mono text-xs whitespace-pre-wrap text-[color:var(--astra-ink)]"
          >
            {curl}
          </pre>
        )}
        <div>
          <button
            type="button"
            className="btn-secondary"
            disabled={curl === ''}
            aria-label={t('prompts.playgroundCurlCopyAria')}
            onClick={copyCurl}
          >
            {copied ? t('common.copied') : t('prompts.playgroundCurlCopy')}
          </button>
        </div>
      </div>
    </div>
  )
}
