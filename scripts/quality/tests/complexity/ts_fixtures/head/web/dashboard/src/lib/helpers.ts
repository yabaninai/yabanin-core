// Fixture head state: renamedBody carries legacyBody's exact body (fingerprint
// match, status moved, not re-flagged); portedAway has moved to moved.ts.
export function renamedBody(alpha: number): number {
  let total = alpha;
  if (alpha > 1) total += 1;
  if (alpha > 2) total += 2;
  return total;
}
