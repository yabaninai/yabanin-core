// Fixture base state: stableReformat (2) is reformatted at head — identical
// body AST, so the fingerprint stays stable: no changed entry at head.
export function stableReformat(values: number[]): number {
  let total = 0;
  if (values.length > 2) total += 1;
  if (values.length > 4) total += 2;
  return total;
}
