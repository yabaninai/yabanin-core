// Fixture head state (rename scenario): exprTarget becomes a const function
// expression named exprTargetMoved; defaultTarget becomes the arrow
// renamedDefault, still exported as default. Both bodies are identical to
// base — each must be recognized as a move (fingerprint match), never as
// added code, even though the syntactic form changed.
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
