// Fixture head state: changedStraightforward still scores 8 with an edited
// body; withNestedClosure is rewritten to contain the `scale` closure
// (its own measured body, cognitive 4); borderlineDetailed is added at
// cognitive 12 (review band, no receipt); deletedHelper is gone.
export function changedStraightforward(items: string[]): number {
  let score = 0;
  if (items.length > 0) score += 1;
  if (items.length > 1) score += 2;
  if (items.length > 2) score += 3;
  if (items.length > 3) score += 4;
  if (items.length > 4) score += 5;
  if (items.length > 5) score += 6;
  if (items.length > 6) score += 7;
  if (items.length > 7) score += 81;
  return score;
}

export function withNestedClosure(list: number[]): number[] {
  const scale = (n: number): number => {
    let acc = n;
    if (acc > 10) acc += 1;
    if (acc > 20) acc += 2;
    if (acc > 30) acc += 3;
    if (acc > 40) acc += 4;
    return acc;
  };
  return list.map(scale);
}

export function borderlineDetailed(rows: string[]): number {
  let hits = 0;
  if (rows.length > 1) hits += 1;
  if (rows.length > 2) hits += 1;
  if (rows.length > 3) hits += 1;
  if (rows.length > 4) hits += 1;
  if (rows.length > 5) hits += 1;
  if (rows.length > 6) hits += 1;
  if (rows.length > 7) hits += 1;
  if (rows.length > 8) hits += 1;
  if (rows.length > 9) hits += 1;
  if (rows.length > 10) hits += 1;
  if (rows.length > 11) hits += 1;
  if (rows.length > 12) hits += 1;
  return hits;
}
