import { useEffect, type RefObject } from 'react'

// EntityDrawer, FormDrawer). Previously each surface kept its own copy of
// this logic; the contract is identical everywhere:
//   * on mount: remember the opener (document.activeElement) and move focus
//     to the panel's first focusable element;
//   * Tab / Shift+Tab cycle INSIDE the panel (av03 acceptance: focus never
//     reaches background controls);
//   * Escape calls `onEscape` (the surface decides what closing means);
//   * on unmount focus returns to the opener — or, when the opener is gone
//     (deep link, list re-render, pointer tap that never focused it), to the
//     nearest surviving ancestor's first focusable, and finally to the first
//     focusable in the admin content region. Never to <body>.

export const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

export function useFocusTrap(
  panelRef: RefObject<HTMLElement | null>,
  onEscape: () => void,
): void {
  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null
    const panel = panelRef.current
    panel?.querySelector<HTMLElement>(FOCUSABLE)?.focus()
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault()
        onEscape()
        return
      }
      if (event.key !== 'Tab' || !panel) return
      const focusable = Array.from(panel.querySelectorAll<HTMLElement>(FOCUSABLE))
      if (focusable.length === 0) return
      const first = focusable[0]
      const last = focusable[focusable.length - 1]
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first.focus()
      }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      // Restore to the opener when it is still connected and focusable at
      // all; else walk up to the nearest surviving container (a list row may
      // have remounted around the trigger); else the page content region.
      // A <body> opener (deep link, touch tap) never counts as an opener —
      // restore into the content region instead.
      if (opener instanceof HTMLElement && opener.isConnected && opener !== document.body) {
        opener.focus()
        return
      }
      let host: HTMLElement | null = opener && opener !== document.body ? opener.parentElement : null
      while (host && !host.isConnected) host = host.parentElement
      const root = host ?? document.getElementById('admin-content')
      root?.querySelector<HTMLElement>(FOCUSABLE)?.focus()
    }
    // Same arming contract as the dialogs this replaces: the escape callback
    // is a stable closure in every caller (state setters), like the previous
    // per-surface effects keyed on their onClose/onCancel.
  }, [onEscape, panelRef])
}
