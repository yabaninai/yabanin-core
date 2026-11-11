// Fixture (receipt scenario): identical at base and head; quietHelper (2)
// stays untouched debt so only lib/band.ts changes at head.
export function quietHelper(values: number[]): number {
  let total = 0;
  if (values.length > 1) total += 1;
  if (values.length > 2) total += 2;
  return total;
}
