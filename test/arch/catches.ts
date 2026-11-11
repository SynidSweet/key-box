// KBOX-28: every catch rethrows, reports through the Audit or Notifier port, or returns an error result.
import ts from 'typescript';
import type { Violation } from './violation.ts';
import { lineOf, parse, visit } from './parse.ts';
import { readText, sourcesUnder } from './tree.ts';

const isFunctionLike = (n: ts.Node): boolean =>
  ts.isFunctionDeclaration(n) || ts.isFunctionExpression(n) || ts.isArrowFunction(n) || ts.isMethodDeclaration(n) || ts.isConstructorDeclaration(n) || ts.isGetAccessor(n) || ts.isSetAccessor(n);

/** `undefined`, `null` and `void x` carry no error: returning one is swallowing it. */
const isEmptyValue = (e: ts.Expression): boolean =>
  (ts.isIdentifier(e) && e.text === 'undefined') || e.kind === ts.SyntaxKind.NullKeyword || ts.isVoidExpression(e);

const isReport = (call: ts.CallExpression): boolean => {
  const callee = call.expression;
  if (!ts.isPropertyAccessExpression(callee)) return false;
  const owner = callee.expression.getText();
  return (callee.name.text === 'append' && /audit/i.test(owner)) || /notifier/i.test(owner);
};

const stripParens = (e: ts.Expression): ts.Expression => (ts.isParenthesizedExpression(e) ? stripParens(e.expression) : e);

/** For spotting a report call: `await audit.append(x)` and `void notifier.notify(x)` both report. */
const unwrap = (e: ts.Expression): ts.Expression =>
  ts.isParenthesizedExpression(e) || ts.isAwaitExpression(e) || ts.isVoidExpression(e) ? unwrap(e.expression) : e;

/** True when every way through the statement ends in a throw, a meaningful return or a report. */
function statementHandles(s: ts.Statement): boolean {
  if (ts.isThrowStatement(s)) return true;
  if (ts.isReturnStatement(s)) return s.expression !== undefined && !isEmptyValue(stripParens(s.expression));
  if (ts.isExpressionStatement(s)) {
    const e = unwrap(s.expression);
    return ts.isCallExpression(e) && isReport(e);
  }
  if (ts.isBlock(s)) return listHandles(s.statements);
  if (ts.isIfStatement(s)) return s.elseStatement !== undefined && statementHandles(s.thenStatement) && statementHandles(s.elseStatement);
  return false;
}

/** Statements run in order, so one that handles on every path settles the list; a condition alone does not. */
const listHandles = (statements: readonly ts.Statement[]): boolean => statements.some(statementHandles);

const handlesError = (block: ts.Block): boolean => listHandles(block.statements);

function promiseHandlerHandlesError(handler: ts.Expression): boolean {
  if (!ts.isArrowFunction(handler) && !ts.isFunctionExpression(handler)) return true;
  if (ts.isBlock(handler.body)) return handlesError(handler.body);
  const reported = unwrap(handler.body);
  return (ts.isCallExpression(reported) && isReport(reported)) || !isEmptyValue(stripParens(handler.body));
}

export async function checkCatches(root: string): Promise<Violation[]> {
  const found: Violation[] = [];
  for (const file of await sourcesUnder(root, 'src/', 'test/')) {
    const sf = parse(file, await readText(root, file));
    const silent = (node: ts.Node, what: string): void =>
      void found.push({ code: 'silent-catch', file, detail: `line ${lineOf(sf, node)}: ${what} neither rethrows, reports nor returns an error result` });
    visit(sf, (n) => {
      if (ts.isCatchClause(n) && !handlesError(n.block)) silent(n, 'catch');
      else if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && n.expression.name.text === 'catch') {
        const handler = n.arguments[0];
        if (handler !== undefined && !promiseHandlerHandlesError(handler)) silent(n, '.catch handler');
      }
    });
  }
  return found;
}
