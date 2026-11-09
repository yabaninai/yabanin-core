// PostHog CTA events (2026-09-14). Pageviews are handled by the snippet in
// docusaurus.config.ts; this helper is for the handful of explicit,
// named events on the landing page — nothing else is captured.
type PostHogLike = { capture: (event: string, props?: Record<string, unknown>) => void }

type PostHogGlobal = PostHogLike & { _i?: unknown }

function ph(): PostHogLike | undefined {
  if (typeof window === 'undefined') return undefined
  const p = (window as unknown as { posthog?: PostHogGlobal }).posthog
  return p && typeof p.capture === 'function' ? p : undefined
}

/** Fire a named CTA event; silently no-op while the SDK loads or on DNT. */
export function track(event: string, props?: Record<string, unknown>): void {
  try {
    ph()?.capture(event, props)
  } catch {
    // analytics must never break the page
  }
}
