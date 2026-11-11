// Fixture head state (receipt scenario): new file. borderlineTwelve scores
// cognitive 12 — inside the 11-15 review band and nothing else. Without a
// receipt the run exits 1 demanding a review receipt; a valid
// stronger-model receipt clears exactly this band.
export function borderlineTwelve(rows: string[]): number {
  let hits = 0;
  if (rows.length > 1) hits += 1;
  if (rows.length > 2) hits += 1;
  if (rows.length > 3) hits += 1;
  if (rows.length > 4) hits += 1;
  if (rows.length > 5) hits += 1;
  if (rows.length > 6) hits += 1;
  if (rows.length > 7) hits += 1;
  if (rows.length > 8) hits += 1;
  if (rows.length > 9) hits += 1;
  if (rows.length > 10) hits += 1;
  if (rows.length > 11) hits += 1;
  if (rows.length > 12) hits += 1;
  return hits;
}
