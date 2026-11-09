// (v(n) ↔ v(n+1)) — the contract's "diff computed client-side first; no
// backend change needed". Pure string work, no YAML opinion: the server
// stays the validator; this only shows what changed between two stored
// version documents.

export interface DiffLine {
  type: 'same' | 'add' | 'del'
  text: string
}

/** Classic LCS line diff (documents are small; O(n·m) is fine here and
    keeps the output stable and reviewable). */
export function diffLines(a: string, b: string): DiffLine[] {
  const left = a.split('\n')
  const right = b.split('\n')
  const n = left.length
  const m = right.length
  // lcs[i][j] = LCS length of left[i:] vs right[j:]
  const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0))
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i][j] = left[i] === right[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1])
    }
  }
  const out: DiffLine[] = []
  let i = 0
  let j = 0
  while (i < n && j < m) {
    if (left[i] === right[j]) {
      out.push({ type: 'same', text: left[i] })
      i++
      j++
    } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
      out.push({ type: 'del', text: left[i] })
      i++
    } else {
      out.push({ type: 'add', text: right[j] })
      j++
    }
  }
  while (i < n) out.push({ type: 'del', text: left[i++] })
  while (j < m) out.push({ type: 'add', text: right[j++] })
  return out
}

export interface DiffSummary {
  added: number
  removed: number
  unchanged: number
}

export function diffSummary(lines: DiffLine[]): DiffSummary {
  const s = { added: 0, removed: 0, unchanged: 0 }
  for (const l of lines) {
    if (l.type === 'add') s.added++
    else if (l.type === 'del') s.removed++
    else s.unchanged++
  }
  return s
}
