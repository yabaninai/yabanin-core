// Fixture base state (rename scenario): legacyHeavy scores cognitive 25
// (25 flat ifs). At head it is renamed to legacyHeavyRenamed with a
// reformatted-only body — the identical fingerprint must carry the debt as a
// moved body, never as a new blocking function.
export function legacyHeavy(steps: number): number {
  let total = 0;
  if (steps > 1) total += 1;
  if (steps > 2) total += 1;
  if (steps > 3) total += 1;
  if (steps > 4) total += 1;
  if (steps > 5) total += 1;
  if (steps > 6) total += 1;
  if (steps > 7) total += 1;
  if (steps > 8) total += 1;
  if (steps > 9) total += 1;
  if (steps > 10) total += 1;
  if (steps > 11) total += 1;
  if (steps > 12) total += 1;
  if (steps > 13) total += 1;
  if (steps > 14) total += 1;
  if (steps > 15) total += 1;
  if (steps > 16) total += 1;
  if (steps > 17) total += 1;
  if (steps > 18) total += 1;
  if (steps > 19) total += 1;
  if (steps > 20) total += 1;
  if (steps > 21) total += 1;
  if (steps > 22) total += 1;
  if (steps > 23) total += 1;
  if (steps > 24) total += 1;
  if (steps > 25) total += 1;
  return total;
}
