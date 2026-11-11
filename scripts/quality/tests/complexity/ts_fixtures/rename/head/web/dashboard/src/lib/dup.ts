// Fixture head state (rename): heavyOriginal survives untouched; heavyCopy
// is a byte-identical duplicate — added, duplicate_of set, blocks (16 > 15).
export function heavyOriginal(rows: string[]): number {
  let total = 0;
  if (rows.length > 1) total += 1;
  if (rows.length > 2) total += 1;
  if (rows.length > 3) total += 1;
  if (rows.length > 4) total += 1;
  if (rows.length > 5) total += 1;
  if (rows.length > 6) total += 1;
  if (rows.length > 7) total += 1;
  if (rows.length > 8) total += 1;
  if (rows.length > 9) total += 1;
  if (rows.length > 10) total += 1;
  if (rows.length > 11) total += 1;
  if (rows.length > 12) total += 1;
  if (rows.length > 13) total += 1;
  if (rows.length > 14) total += 1;
  if (rows.length > 15) total += 1;
  if (rows.length > 16) total += 1;
  return total;
}

export function heavyCopy(rows: string[]): number {
  let total = 0;
  if (rows.length > 1) total += 1;
  if (rows.length > 2) total += 1;
  if (rows.length > 3) total += 1;
  if (rows.length > 4) total += 1;
  if (rows.length > 5) total += 1;
  if (rows.length > 6) total += 1;
  if (rows.length > 7) total += 1;
  if (rows.length > 8) total += 1;
  if (rows.length > 9) total += 1;
  if (rows.length > 10) total += 1;
  if (rows.length > 11) total += 1;
  if (rows.length > 12) total += 1;
  if (rows.length > 13) total += 1;
  if (rows.length > 14) total += 1;
  if (rows.length > 15) total += 1;
  if (rows.length > 16) total += 1;
  return total;
}
