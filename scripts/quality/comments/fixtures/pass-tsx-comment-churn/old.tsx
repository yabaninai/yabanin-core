import { useState } from 'react'

// Card used on the overview; IMP-36 asked for the metric hint inline.
export function MetricCard({ label }: { label: string }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="metric-card">
      {/* The header toggles the details region. */}
      <button onClick={() => setOpen(!open)}>{label}</button>
      {open && <p className="metric-detail">detail</p>}
    </div>
  )
}
