// Fixture base state (rename scenario): a plain exported function and a
// default-exported function with identical low-complexity bodies. At head
// both are renamed across syntactic forms (function declaration -> const
// function expression, default export -> renamed arrow re-exported as
// default); identical bodies must be recognized as moves, not additions.
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
