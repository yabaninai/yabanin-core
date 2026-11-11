// Fixture (receipt scenario): identical at base and head. quietHelper
// (cognitive 2) stays untouched debt so the only changed function in this
// scenario is the review-band addition in lib/band.ts.
export function quietHelper(values: number[]): number {
  let total = 0;
  if (values.length > 1) total += 1;
  if (values.length > 2) total += 2;
  return total;
}
