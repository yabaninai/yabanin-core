// CSV serialization with correct quoting and formula-injection
// guarding. Every cell is quoted; internal quotes are doubled; CRLF row
// endings; a leading = + - @ (or tab/CR) gets a single-quote prefix so a
// spreadsheet does not execute the cell as a formula.

export function csvCell(raw: string | number): string {
  let s = String(raw)
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`
  return `"${s.replace(/"/g, '""')}"`
}

export function toCSV(headers: string[], rows: Array<Array<string | number>>): string {
  const lines = [headers.map(csvCell).join(','), ...rows.map(r => r.map(csvCell).join(','))]
  return lines.join('\r\n') + '\r\n'
}

export function downloadCSV(filename: string, csv: string) {
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  // Revoking synchronously can abort the download before the browser's
  // download manager has taken its reference (observed in headless
  // Chromium) — defer the cleanup to a macrotask.
  setTimeout(() => URL.revokeObjectURL(url), 0)
}
