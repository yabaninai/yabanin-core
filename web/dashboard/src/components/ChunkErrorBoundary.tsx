import { Component, ReactNode } from 'react'
import { withTranslation, WithTranslation } from 'react-i18next'

// Astra app shell (ASTR-06): an error boundary around lazy page chunks.
// A failed chunk (network hiccup, deploy race) shows a recoverable notice
// instead of a blank screen; the page can be re-attempted without a full
// browser reload of the shell.
//
// keeps `withTranslation` because error boundaries cannot use hooks.

interface Props extends WithTranslation {
  children: ReactNode
  /** Changing this key remounts the boundary (retry without page reload). */
  retryKey?: number
}

interface State {
  error: Error | null
}

class ChunkErrorBoundaryBase extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidUpdate(prev: Props) {
    // A retry (new key) clears the previous failure.
    if (prev.retryKey !== this.props.retryKey && this.state.error) {
      this.setState({ error: null })
    }
  }

  componentDidCatch(error: Error) {
    // Keep it observable but free of sensitive data (message only).
    console.error(this.props.t('chunkError.logTitle'), error.message)
  }

  render() {
    if (this.state.error) {
      const { t } = this.props
      return (
        <div role="alert" className="mx-auto my-10 max-w-lg border border-dashed border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] px-5 py-6">
          <p className="flex items-center gap-2 text-sm font-medium text-[color:var(--astra-ink)]">
            <span aria-hidden="true" className="text-[color:var(--astra-danger)]">✕</span>
            {t('chunkError.title')}
          </p>
          <p className="mt-1 text-sm text-[color:var(--astra-text-muted)]">
            {t('chunkError.message')}
          </p>
          <div className="mt-3 flex gap-2">
            <button
              type="button"
              onClick={() => this.setState({ error: null })}
              className="btn-primary"
            >
              {t('chunkError.retry')}
            </button>
            <button
              type="button"
              onClick={() => { window.location.hash = 'overview'; this.setState({ error: null }) }}
              className="btn-secondary"
            >
              {t('chunkError.overview')}
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}

export const ChunkErrorBoundary = withTranslation()(ChunkErrorBoundaryBase)
