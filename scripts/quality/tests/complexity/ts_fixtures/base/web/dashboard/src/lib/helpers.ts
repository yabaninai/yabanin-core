// Fixture base state: legacyBody is renamed at head with an identical body
// (in-file move); portedAway moves verbatim to lib/moved.ts (cross-file move).
export function legacyBody(alpha: number): number {
  let total = alpha;
  if (alpha > 1) total += 1;
  if (alpha > 2) total += 2;
  return total;
}

export function portedAway(rows: string[]): number {
  let seen = 0;
  if (rows.length > 3) seen += 1;
  if (rows.length > 6) seen += 2;
  return seen;
}
