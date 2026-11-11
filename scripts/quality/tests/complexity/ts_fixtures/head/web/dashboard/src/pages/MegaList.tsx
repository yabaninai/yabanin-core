// Fixture head state: new file. MegaList is an arrow component at
// cognitive exactly 16 (16 flat ifs); the run must exit 1 naming it.
export const MegaList = (rows: string[]): string => {
  let cls = "base";
  if (rows.length > 1) cls += " a";
  if (rows.length > 2) cls += " b";
  if (rows.length > 3) cls += " c";
  if (rows.length > 4) cls += " d";
  if (rows.length > 5) cls += " e";
  if (rows.length > 6) cls += " f";
  if (rows.length > 7) cls += " g";
  if (rows.length > 8) cls += " h";
  if (rows.length > 9) cls += " i";
  if (rows.length > 10) cls += " j";
  if (rows.length > 11) cls += " k";
  if (rows.length > 12) cls += " l";
  if (rows.length > 13) cls += " m";
  if (rows.length > 14) cls += " n";
  if (rows.length > 15) cls += " o";
  if (rows.length > 16) cls += " p";
  return <span className={cls}>{rows.length}</span>;
};
