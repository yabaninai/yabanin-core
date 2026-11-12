// Function-body extraction over a parsed source file.
//
// Collects every measurable body: function declarations, class
// methods/constructors/accessors, function expressions, arrow functions
// (including closures nested inside other bodies) with a stable qualified
// name, a formatting-independent body identity (body_sha256) and its
// complexity.
import { createHash } from "node:crypto";

import { cognitiveComplexity } from "./metric.mjs";

export const MEASURED_EXTENSIONS = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"];

export function isMeasuredFile(path) {
  return MEASURED_EXTENSIONS.some((ext) => path.endsWith(ext));
}

function scriptKindFor(ts, fileName) {
  if (fileName.endsWith(".tsx")) return ts.ScriptKind.TSX;
  if (fileName.endsWith(".jsx")) return ts.ScriptKind.JSX;
  if (fileName.endsWith(".ts")) return ts.ScriptKind.TS;
  return ts.ScriptKind.JS;
}

function kindOf(ts, node) {
  if (ts.isFunctionDeclaration(node)) return "function";
  if (ts.isConstructorDeclaration(node)) return "constructor";
  if (ts.isGetAccessorDeclaration(node)) return "getter";
  if (ts.isSetAccessorDeclaration(node)) return "setter";
  if (ts.isMethodDeclaration(node)) return "method";
  if (ts.isFunctionExpression(node)) return "function-expression";
  if (ts.isArrowFunction(node)) return "arrow";
  return null;
}

function keyText(key) {
  if (!key) return "?";
  // Identifier/PrivateIdentifier/StringLiteral/NumericLiteral keys all
  // expose .text; ComputedPropertyName does not.
  if (typeof key.text === "string") return key.text;
  return "[computed]";
}

function roleOf(ownName) {
  if (/^use[A-Z]/.test(ownName)) return "hook";
  if (/^[A-Z]/.test(ownName)) return "component";
  return "function";
}

const CONTEXT_RULES = [
  [(ts, parent) => ts.isVariableDeclaration(parent), (_ts, parent) => keyText(parent.name)],
  [(ts, parent) => ts.isPropertyAssignment(parent) || ts.isPropertyDeclaration(parent), (_ts, parent) => keyText(parent.name)],
  [(ts, parent) => ts.isCallExpression(parent), (_ts, parent, _line) => `${calleeTail(_ts, parent)}~arg@L${_line}`],
];

function calleeTail(ts, parent) {
  const callee = parent.expression;
  if (ts.isPropertyAccessExpression(callee)) return callee.name.text;
  if (ts.isIdentifier(callee)) return callee.text;
  return "call";
}

function contextualName(ts, node, line) {
  const parent = node.parent;
  for (const [matches, nameOf] of CONTEXT_RULES) {
    if (parent && matches(ts, parent)) {
      return nameOf(ts, parent, line);
    }
  }
  return null;
}

function ownNameOf(ts, node, sf) {
  const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
  const self = node.name ? keyText(node.name) : null;
  if (self) return self;
  const contextual = contextualName(ts, node, line);
  if (contextual) return contextual;
  const kind = kindOf(ts, node);
  return `<anonymous-${kind}@L${line}>`;
}

export function parseAndCollect(ts, fileName, text) {
  const sf = ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true, scriptKindFor(ts, fileName));
  const diagnostics = sf.parseDiagnostics || [];
  if (diagnostics.length > 0) {
    const first = ts.flattenDiagnosticMessageText(diagnostics[0].messageText, " ");
    return { error: `${fileName}: ${first} (${diagnostics.length} parse diagnostics)` };
  }
  const printer = ts.createPrinter({ removeComments: true, newLine: ts.NewLineKind.LineFeed });
  const functions = [];
  const seen = new Map();

  function bodySha256(body) {
    const canonical = printer.printNode(ts.EmitHint.Unspecified, body, sf).replace(/\s+/g, " ").trim();
    return createHash("sha256").update(canonical).digest("hex");
  }

  function record(node, scope) {
    const own = ownNameOf(ts, node, sf);
    const qualified = [...scope, own].join("::");
    const ordinal = seen.get(qualified) || 0;
    seen.set(qualified, ordinal + 1);
    const unique = ordinal === 0 ? qualified : `${qualified}#${ordinal + 1}`;
    const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
    functions.push({
      name: unique,
      ownName: own,
      kind: kindOf(ts, node),
      role: roleOf(own),
      line,
      complexity: cognitiveComplexity(ts, node),
      body_sha256: bodySha256(node.body),
    });
    return own;
  }

  function visit(node, scope) {
    const kind = kindOf(ts, node);
    let childScope = scope;
    if (kind && node.body) {
      childScope = [...scope, record(node, scope)];
    } else if (ts.isClassLike(node)) {
      childScope = [...scope, node.name ? keyText(node.name) : "<anonymous-class>"];
    } else if (ts.isModuleDeclaration(node) && node.name) {
      childScope = [...scope, keyText(node.name)];
    }
    ts.forEachChild(node, (child) => visit(child, childScope));
  }

  visit(sf, []);
  return { functions, error: null };
}
