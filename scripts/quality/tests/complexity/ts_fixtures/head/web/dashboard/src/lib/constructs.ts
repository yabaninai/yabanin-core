// Fixture head state: added file pinning metric paths — routePlan 10
// (switch clauses + nested if), guardedParse 4 (catch), fetchScore 4, asyncLabel 3.
export function routePlan(code: string, size: number): string {
  let plan = "none";
  switch (code) {
    case "a":
      plan = "alpha";
      break;
    case "b":
      if (size > 10) {
        plan = "big";
      }
      break;
    case "c":
    case "d":
      plan = "grouped";
      break;
    default:
      plan = "fallback";
  }
  return plan;
}

export function guardedParse(raw: string): number {
  try {
    if (raw.length > 3) return 1;
    return 0;
  } catch (error) {
    const message = String(error);
    if (message.length > 0) return 2;
    return 3;
  }
}

export async function fetchScore(id: number): Promise<number> {
  let score = id;
  if (score > 10) {
    score -= 1;
  } else if (score > 5) {
    score -= 2;
  } else {
    score = 0;
  }
  const doubled = await Promise.resolve(score * 2);
  if (doubled > 100) return 100;
  return doubled;
}

export const asyncLabel = async (rows: string[]): Promise<string> => {
  let label = "none";
  for (const row of rows) {
    if (row.length > 3) label = row;
  }
  return label;
};
