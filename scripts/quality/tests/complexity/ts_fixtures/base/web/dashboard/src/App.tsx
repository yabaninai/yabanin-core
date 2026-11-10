// Fixture base state: three changed-function scenarios live here.
// changedStraightforward scores cognitive 8 at base; deletedHelper is removed
// at head; withNestedClosure (cognitive 2) gains a nested closure at head.
export function changedStraightforward(items: string[]): number {
  let score = 0;
  if (items.length > 0) score += 1;
  if (items.length > 1) score += 2;
  if (items.length > 2) score += 3;
  if (items.length > 3) score += 4;
  if (items.length > 4) score += 5;
  if (items.length > 5) score += 6;
  if (items.length > 6) score += 7;
  if (items.length > 7) score += 8;
  return score;
}

export function deletedHelper(value: number): number {
  return value * 2;
}

export function withNestedClosure(list: number[]): number[] {
  let trimmed = list;
  if (trimmed.length > 20) trimmed = trimmed.slice(0, 20);
  if (trimmed.length > 10) trimmed = trimmed.slice(0, 10);
  return trimmed;
}
