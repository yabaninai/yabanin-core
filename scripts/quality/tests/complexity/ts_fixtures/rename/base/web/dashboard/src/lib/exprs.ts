// Fixture base state (rename): plain export + default export with identical
// low-complexity bodies; both are renamed across syntactic forms at head.
export function exprTarget(rows: string[]): number {
  let total = 0;
  if (rows.length > 2) total += 1;
  if (rows.length > 4) total += 2;
  return total;
}

export default function defaultTarget(rows: string[]): number {
  let total = 0;
  if (rows.length > 2) total += 1;
  if (rows.length > 4) total += 2;
  return total;
}
