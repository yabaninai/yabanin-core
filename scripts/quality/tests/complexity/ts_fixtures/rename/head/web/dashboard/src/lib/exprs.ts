// Fixture head state (rename): exprTarget -> const function expression;
// defaultTarget -> renamed default-exported arrow; identical bodies stay moves.
export const exprTargetMoved = function (rows: string[]): number {
  let total = 0;
  if (rows.length > 2) total += 1;
  if (rows.length > 4) total += 2;
  return total;
};

const renamedDefault = (rows: string[]): number => {
  let total = 0;
  if (rows.length > 2) total += 1;
  if (rows.length > 4) total += 2;
  return total;
};

export default renamedDefault;
