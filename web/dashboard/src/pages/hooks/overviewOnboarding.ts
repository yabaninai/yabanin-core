// The onboarding checklist and the ✕ on the collapsed «Setup complete ✓»
// chip persist in localStorage, so an operator who closed them never sees
// the card again on this browser profile.

export const ONBOARDING_MEMORY_KEY = 'yabanin.onboarding.v1'

export interface OnboardingMemory {
  /** ✕ on the full checklist (setup still incomplete). */
  dismissed?: boolean
  /** ✕ on the collapsed done-chip. */
  doneDismissed?: boolean
}

export function parseOnboardingMemory(raw: string | null): OnboardingMemory {
  if (!raw) return {}
  try {
    const v = JSON.parse(raw) as OnboardingMemory
    const out: OnboardingMemory = {}
    if (v.dismissed === true) out.dismissed = true
    if (v.doneDismissed === true) out.doneDismissed = true
    return out
  } catch {
    return {}
  }
}

export function readOnboardingMemory(): OnboardingMemory {
  try {
    return parseOnboardingMemory(localStorage.getItem(ONBOARDING_MEMORY_KEY))
  } catch {
    return {} // private mode / non-browser — nothing remembered
  }
}

export function writeOnboardingMemory(next: OnboardingMemory): void {
  try {
    localStorage.setItem(ONBOARDING_MEMORY_KEY, JSON.stringify(next))
  } catch {
    // Private mode / tests — continuity is best-effort.
  }
}
