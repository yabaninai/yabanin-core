// Fixture head state: portedAway relocated verbatim from lib/helpers.ts;
// the analyzer must recognize the cross-file move and not re-flag it.
export function portedAway(rows: string[]): number {
  let seen = 0;
  if (rows.length > 3) seen += 1;
  if (rows.length > 6) seen += 2;
  return seen;
}
