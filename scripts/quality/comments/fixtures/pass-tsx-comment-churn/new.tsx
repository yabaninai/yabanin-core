import { useState } from 'react'

export function MetricCard({ label }: { label: string }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="metric-card">
      {/* The button toggles the details region. */}
      <button onClick={() => setOpen(!open)}>{label}</button>
      {open && <p className="metric-detail">detail</p>}
    </div>
  )
}
