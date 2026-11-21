import type { Point } from './routingGraph'

export interface EdgeWindow { left: number; right: number }

function segment(a: Point, b: Point) {
  return `M ${a.x} ${a.y} L ${b.x} ${b.y}`
}

/** Clip the painted stroke, retaining its original dash phase and target arrow. */
export function visibleEdge(a: Point, b: Point, window: EdgeWindow | null) {
  if (!window) return { d: segment(a, b), offset: 0, target: true }
  const min = Math.min(a.x, b.x), max = Math.max(a.x, b.x)
  if (max < window.left || min > window.right) return { d: '', offset: 0, target: false }
  if (min >= window.left && max <= window.right) return { d: segment(a, b), offset: 0, target: true }
  const dx = b.x - a.x, dy = b.y - a.y
  const left = (window.left - a.x) / dx, right = (window.right - a.x) / dx
  const start = Math.max(0, Math.min(left, right))
  const end = Math.min(1, Math.max(left, right))
  const at = (t: number) => ({ x: a.x + dx * t, y: a.y + dy * t })
  return { d: segment(at(start), at(end)), offset: start * Math.hypot(dx, dy), target: end === 1 }
}
