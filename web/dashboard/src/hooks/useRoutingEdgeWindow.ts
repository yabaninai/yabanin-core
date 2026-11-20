import { useLayoutEffect, useRef, useState } from 'react'
import type { EdgeWindow } from '../lib/routingEdgeWindow'

/** Keep a margin outside the scrollport so browsing within a tile needs no repaint. */
export function useRoutingEdgeWindow() {
  const canvas = useRef<SVGSVGElement>(null)
  const [window, setWindow] = useState<EdgeWindow | null>(null)
  useLayoutEffect(() => {
    const svg = canvas.current
    const port = svg?.parentElement
    if (!svg || !port) return
    const tile = 256
    const measure = () => {
      const x = port.getBoundingClientRect().left - svg.getBoundingClientRect().left
      const left = (Math.floor(x / tile) - 1) * tile
      const right = (Math.ceil((x + port.clientWidth) / tile) + 1) * tile
      setWindow(prev => prev?.left === left && prev.right === right ? prev : { left, right })
    }
    measure()
    const observer = new ResizeObserver(measure)
    observer.observe(port)
    port.addEventListener('scroll', measure, { passive: true })
    return () => {
      port.removeEventListener('scroll', measure)
      observer.disconnect()
    }
  }, [])
  return { canvas, window }
}
