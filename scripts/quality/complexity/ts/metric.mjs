// Cognitive-complexity metric for TypeScript/JavaScript function bodies.
//
// Sonar-style rules (full listing in README.md, "Metric rules"):
//   +1 x (1 + nesting) for if / loop / case clause / catch / ternary
//   +1 (flat) for else and each else-if link, each logical operator
//   (+1 flat) for labeled break/continue
// Nesting increases inside if/loop/switch/catch/ternary bodies.
// Deviation from Sonar, required by the differential gate design: nested
// function-likes add nothing to the enclosing score and are measured as
// their own bodies (no double counting).

const LOGICAL_OPERATORS = new Set([
  "AmpersandAmpersandToken",
  "BarBarToken",
  "QuestionQuestionToken",
]);
const LOOP_STATEMENTS = new Set([
  "ForStatement",
  "ForOfStatement",
  "ForInStatement",
  "WhileStatement",
  "DoStatement",
]);

export function cognitiveComplexity(ts, functionLike) {
  let score = 0;
  let nesting = 0;

  const increment = () => {
    score += 1 + nesting;
  };
  const inNested = (node) => {
    nesting += 1;
    walk(node);
    nesting -= 1;
  };

  function walkIf(node) {
    increment();
    walk(node.expression);
    inNested(node.thenStatement);
    let chain = node.elseStatement;
    while (chain) {
      if (ts.isIfStatement(chain)) {
        // else-if is a flat continuation of the same decision chain.
        score += 1;
        walk(chain.expression);
        inNested(chain.thenStatement);
        chain = chain.elseStatement;
      } else {
        score += 1;
        walk(chain);
        chain = undefined;
      }
    }
  }

  function walkLoop(node) {
    increment();
    for (const part of [node.initializer, node.expression, node.condition, node.incrementor]) {
      if (part) walk(part);
    }
    inNested(node.statement);
  }

  function walkSwitch(node) {
    walk(node.expression);
    nesting += 1;
    for (const clause of node.caseBlock.clauses) {
      if (ts.isCaseClause(clause)) increment();
      walk(clause);
    }
    nesting -= 1;
  }

  function walkLogical(node) {
    if (!LOGICAL_OPERATORS.has(ts.SyntaxKind[node.operatorToken.kind])) {
      descend(node);
      return;
    }
    // Sonar counts a run of n same-kind operators as n, which reduces to
    // counting each logical operator token once.
    score += 1;
    walk(node.left);
    walk(node.right);
  }

  const handlers = [
    [ts.isIfStatement, walkIf],
    [(n) => LOOP_STATEMENTS.has(ts.SyntaxKind[n.kind]), walkLoop],
    [ts.isSwitchStatement, walkSwitch],
    [ts.isConditionalExpression, (n) => {
      increment();
      walk(n.condition);
      inNested(n.whenTrue);
      inNested(n.whenFalse);
    }],
    [ts.isCatchClause, (n) => {
      increment();
      inNested(n.variableDeclaration);
      inNested(n.block);
    }],
    [ts.isBinaryExpression, walkLogical],
    [(n) => (ts.isBreakStatement(n) || ts.isContinueStatement(n)) && n.label,
      () => {
        score += 1;
      }],
  ];

  function descend(node) {
    ts.forEachChild(node, walk);
  }

  function walk(node) {
    if (!node || ts.isFunctionLike(node)) return; // closures are separate bodies
    for (const [matches, apply] of handlers) {
      if (matches(node)) {
        apply(node);
        return;
      }
    }
    descend(node);
  }

  walk(functionLike.body);
  return score;
}

export function classifyComplexity(score, limits) {
  if (score <= limits.okMax) return "ok";
  if (score <= limits.reviewMax) return "review";
  return "block";
}
