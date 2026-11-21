// CUI-02 first-run defect (2026-11-20): pure logic for the first-team-
// budget path. Kept JSX-free so node --test can import and pin the
// behavior directly (the component in FirstTeamBudget.tsx renders it).
//
// Reviewer correction (blocking early review): the default team CANNOT be
// inferred from the key list — creation permits an explicit non-default
// team (only an omitted team falls back server-side, crud.go:529), and
// list order is not default-team evidence. Every identity here is
// therefore the VERIFIED setup-key identity: a key row's team_id is the
// team THAT KEY bills to, set by the server at creation. The UI labels it
// "the team this key bills to", never "default team".

import type { APIKey } from '../../api/keys'

/** One resolvable setup-key → team binding (server-set team_id only). */
export interface SetupKeyTeamCandidate {
  keyId: string
  keyName: string
  teamId: string
}

// Only key rows that actually carry a server-set team_id are candidates;
// rows without one are skipped, never guessed for.
export function setupKeyTeamCandidates(keys: APIKey[]): SetupKeyTeamCandidate[] {
  const out: SetupKeyTeamCandidate[] = []
  for (const key of keys) {
    if (key.team_id) out.push({ keyId: key.id, keyName: key.name, teamId: key.team_id })
  }
  return out
}

// Auto-selection is allowed ONLY when exactly one key row carries a team.
// With two or more the operator must choose explicitly — an ordered list
// is never evidence of which key is the setup key (reordering must not
// change what would be written).
export function autoSelectedSetupKey(candidates: SetupKeyTeamCandidate[]): SetupKeyTeamCandidate | null {
  return candidates.length === 1 ? candidates[0] : null
}

/** What the section should render — one honest state, decided purely. */
export type FirstBudgetPhase =
  | { kind: 'hidden' } // rights loading, or no budgets.manage: nothing to act on
  | { kind: 'no-keys-perm' } // keys.manage missing: identity unresolvable, said so
  | { kind: 'error'; message: string } // a read failed: retry, never a silent blank
  | { kind: 'waiting' } // reads in flight
  | { kind: 'no-keys' } // no key row with a team yet
  | { kind: 'done' } // the selected team already has a budget row
  | { kind: 'ready' } // an explicit identity is available to confirm

export function firstBudgetPhase(args: {
  permsLoading: boolean
  canBudgets: boolean
  canKeys: boolean
  keysError: string
  budgetsError: string
  keys: APIKey[] | null
  budgetedIds: string[] | null
  selected: SetupKeyTeamCandidate | null
}): FirstBudgetPhase {
  if (args.permsLoading || !args.canBudgets) return { kind: 'hidden' }
  if (!args.canKeys) return { kind: 'no-keys-perm' }
  if (args.keysError) return { kind: 'error', message: args.keysError }
  if (args.budgetsError) return { kind: 'error', message: args.budgetsError }
  if (args.keys === null || args.budgetedIds === null) return { kind: 'waiting' }
  if (setupKeyTeamCandidates(args.keys).length === 0) return { kind: 'no-keys' }
  if (args.selected && args.budgetedIds.includes(args.selected.teamId)) return { kind: 'done' }
  return { kind: 'ready' }
}
