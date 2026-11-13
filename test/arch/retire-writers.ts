// KBOX-51 step 10 as amended (revoke-proof), KBOX-62, KBOX-55: who may mark a generation `retired`. Only the proof watch (through the store's
// `retireProven`), a deletion (its ledger's batch write) and a box-made key's revoke (`boxRevoke`) do; step 10 (`revokeOld`) neither marks a
// generation retired nor deletes its value. Judged on the syntax tree of every source under src/.
import ts from 'typescript';
import type { Violation } from './violation.ts';
import { lineOf, parse, visit } from './parse.ts';
import { readText, sourcesUnder } from './tree.ts';

const ORCHESTRATOR = 'src/shell/orchestrator.ts';
/** The one function that may call `setGenStatus(…, 'retired')`: the revoke of a key the box makes itself (KBOX-55). */
const BOX_REVOKE = 'boxRevoke';
/** Step 10 of a rotation: it may neither retire nor delete a value. */
const STEP_TEN = 'revokeOld';
/** The store calls only the proof watch makes. */
const WATCH = 'src/shell/proof-watch.ts';
/** The stores whose SQL writes `retired`: the deletion's batch and the proof watch's retire. */
const SQL_WRITERS: ReadonlySet<string> = new Set(['src/shell/deletion-store.ts', 'src/shell/rotation-store.ts']);
const RETIRING_SQL = /status\s*=\s*'retired'/;

/** The name of the nearest named function or method around a node. */
function enclosingFunction(node: ts.Node): string | undefined {
  for (let at: ts.Node | undefined = node.parent; at !== undefined; at = at.parent) {
    if ((ts.isFunctionDeclaration(at) || ts.isMethodDeclaration(at)) && at.name !== undefined && ts.isIdentifier(at.name)) return at.name.text;
    if ((ts.isArrowFunction(at) || ts.isFunctionExpression(at)) && ts.isVariableDeclaration(at.parent) && ts.isIdentifier(at.parent.name)) return at.parent.name.text;
  }
  return undefined;
}

const calledName = (call: ts.CallExpression): string | undefined => (ts.isPropertyAccessExpression(call.expression) ? call.expression.name.text : ts.isIdentifier(call.expression) ? call.expression.text : undefined);
const hasRetiredArgument = (call: ts.CallExpression): boolean => call.arguments.some((a) => ts.isStringLiteralLike(a) && a.text === 'retired');

export async function checkRetireWriters(root: string): Promise<Violation[]> {
  const found: Violation[] = [];
  for (const file of (await sourcesUnder(root, 'src/')).filter((f) => f.endsWith('.ts'))) {
    const sf = parse(file, await readText(root, file));
    const refuse = (node: ts.Node, what: string): void => void found.push({ code: 'retire-writer', file, detail: `line ${lineOf(sf, node)}: ${what}` });
    visit(sf, (node) => {
      if (ts.isCallExpression(node)) {
        const name = calledName(node);
        const fn = enclosingFunction(node);
        if (name === 'setGenStatus' && hasRetiredArgument(node) && !(file === ORCHESTRATOR && fn === BOX_REVOKE)) refuse(node, `marks a generation retired in ${fn ?? 'top-level code'}`);
        if (name === 'retireProven' && file !== WATCH) refuse(node, 'retires a generation outside the proof watch');
        if (name === 'retire' && file === ORCHESTRATOR && fn === STEP_TEN) refuse(node, 'step 10 deletes a value');
      }
      if (ts.isStringLiteralLike(node) && RETIRING_SQL.test(node.text) && !SQL_WRITERS.has(file)) refuse(node, 'an SQL write that retires a generation');
    });
  }
  return found;
}
