import { useEffect, type RefObject } from 'react'

// Shared dismissal contract for the disclosure menus. While a menu is open:
//   * Escape closes it and returns focus to the toggle button;
//   * a pointer click outside the menu closes it — on `click`, not
//     `mousedown`: the popover extends the document's scrollable overflow,
//     and a mousedown-close collapses the document mid-click, shifting the
//     content under the pointer before mouseup (the click would land on the
//     wrong element — observed as a swallowed first click after a scroll).
//     Closing on click lets the first click LAND (the outside control's own
//     handler runs; the menu closes around it).
// The ARIA disclosure pattern (plain buttons inside, no menu roving) matches
// the «Виды ▾» saved-views menu.

export function useDisclosureDismiss(
  open: boolean,
  menuRef: RefObject<HTMLElement | null>,
  toggleRef: RefObject<HTMLElement | null>,
  close: () => void,
): void {
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return
      close()
      toggleRef.current?.focus()
    }
    const onDown = (e: MouseEvent | TouchEvent) => {
      if (!menuRef.current?.contains(e.target as Node)) close()
    }
    // Capture phase: by the time a bubble-phase document listener runs, the
    // click may already have mutated the DOM (e.g. an action-dialog confirm
    // unmounts itself in the same tick) and the detached target would be
    // misread as "outside". Capture sees the pristine tree.
    document.addEventListener('keydown', onKey, true)
    document.addEventListener('click', onDown, true)
    return () => {
      document.removeEventListener('keydown', onKey, true)
      document.removeEventListener('click', onDown, true)
    }
  }, [open, close, menuRef, toggleRef])
}
