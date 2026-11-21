import { useCallback, useEffect, useRef, useState } from 'react'
import { fetchLabelKeys } from '../api/analytics'

export function useRequestLabelKeys(org: string) {
  const [labelKeys, setLabelKeys] = useState<string[]>([])
  const generation = useRef(0)
  const controller = useRef<AbortController | null>(null)

  const refreshLabels = useCallback(async (next: { from: string; to: string }) => {
    const ticket = ++generation.current
    controller.current?.abort()
    const ctrl = new AbortController()
    controller.current = ctrl
    try {
      const rows = await fetchLabelKeys(org, next.from, next.to, { signal: ctrl.signal })
      if (generation.current === ticket) setLabelKeys(rows.map(row => row.key))
    } catch {
      if (generation.current === ticket) setLabelKeys([])
    }
  }, [org])

  const invalidate = useCallback(() => {
    generation.current++
    controller.current?.abort()
  }, [])

  useEffect(() => {
    setLabelKeys([])
    return invalidate
  }, [org, invalidate])

  return { labelKeys, refreshLabels }
}
