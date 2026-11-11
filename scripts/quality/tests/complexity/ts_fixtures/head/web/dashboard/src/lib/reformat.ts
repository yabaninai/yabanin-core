// Fixture head state: stableReformat reformatted only (whitespace, line
// breaks, comments): measured (2) yet never a changed entry.
export function stableReformat(values: number[]): number {
  // indentation and comments differ from base on purpose
      let total = 0;
  if (values.length > 2)
        total += 1;
    // interleaved comment, removed by the fingerprint printer
  if (values.length > 4) total += 2;
      return total;
}
