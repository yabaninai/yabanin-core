// Fixture base state: stableReformat (cognitive 2) is reformatted at head —
// different indentation/line breaks plus added comments, identical body AST.
// The body fingerprint must stay stable: no changed-function entry at head.
export function stableReformat(values: number[]): number {
  let total = 0;
  if (values.length > 2) total += 1;
  if (values.length > 4) total += 2;
  return total;
}
