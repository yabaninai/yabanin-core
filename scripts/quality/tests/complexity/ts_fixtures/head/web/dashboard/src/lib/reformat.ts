// Fixture head state: same stableReformat body as base, reformatted only
// (whitespace, line breaks, added comments). It must be measured at head
// (cognitive 2, untouched-debt bucket) yet produce no changed entry.
export function stableReformat(values: number[]): number {
  // indentation and comments differ from base on purpose
      let total = 0;
  if (values.length > 2)
        total += 1;
    // interleaved comment, removed by the fingerprint printer
  if (values.length > 4) total += 2;
      return total;
}
