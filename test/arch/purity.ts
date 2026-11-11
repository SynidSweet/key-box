// KBOX-28: pure core, layers, no import cycles; KBOX-35: the soft authenticator shares nothing with the verifier.
import ts from 'typescript';
import type { Violation } from './violation.ts';
import { importsOf, isRelative, parse, resolveRelative, visit, lineOf } from './parse.ts';
import { isSource, readTextIfPresent, sourcesUnder, walk } from './tree.ts';

const FORBIDDEN_IN_PURE = new Set(['fs', 'net', 'http', 'http2', 'https', 'tls', 'dns', 'os', 'child_process', 'sqlite', 'worker_threads']);
const moduleName = (spec: string): string => (spec.startsWith('node:') ? spec.slice(5) : spec).split('/')[0] ?? '';

const GLOBAL_ONLY = new Set(['setTimeout', 'setInterval', 'fetch', 'process']);
const GLOBAL_OBJECTS = new Set(['globalThis', 'global', 'self', 'window']);
const isCryptoDraw = (name: string): boolean => name === 'randomBytes' || name === 'randomUUID' || name === 'randomInt' || name.startsWith('generateKey');

/** True when the identifier only names a property or member and so reads nothing. */
function isMemberName(id: ts.Identifier): boolean {
  const p = id.parent;
  return (
    ((ts.isPropertyAssignment(p) || ts.isPropertySignature(p) || ts.isMethodSignature(p) || ts.isMethodDeclaration(p) || ts.isPropertyDeclaration(p) || ts.isEnumMember(p)) && p.name === id) ||
    (ts.isQualifiedName(p) && p.right === id) ||
    (ts.isBindingElement(p) && p.propertyName === id)
  );
}

function globalsIn(file: string, sf: ts.SourceFile): Violation[] {
  const found: Violation[] = [];
  const at = (node: ts.Node, what: string): void => void found.push({ code: 'pure-global', file, detail: `line ${lineOf(sf, node)}: ${what}` });
  const isNamed = (e: ts.Expression, name: string): boolean => ts.isIdentifier(e) && e.text === name;
  const keyIs = (e: ts.ElementAccessExpression, key: string): boolean => ts.isStringLiteralLike(e.argumentExpression) && e.argumentExpression.text === key;
  visit(sf, (n) => {
    if (ts.isPropertyAccessExpression(n) && isNamed(n.expression, 'Date') && n.name.text === 'now') at(n, 'Date.now');
    else if (ts.isElementAccessExpression(n) && isNamed(n.expression, 'Date') && keyIs(n, 'now')) at(n, 'Date.now');
    else if (ts.isPropertyAccessExpression(n) && isNamed(n.expression, 'Math') && n.name.text === 'random') at(n, 'Math.random');
    else if (ts.isElementAccessExpression(n) && isNamed(n.expression, 'Math') && keyIs(n, 'random')) at(n, 'Math.random');
    else if (ts.isNewExpression(n) && isNamed(n.expression, 'Date') && (n.arguments === undefined || n.arguments.length === 0)) at(n, 'new Date() reads the clock');
    else if (ts.isCallExpression(n) && isNamed(n.expression, 'Date')) at(n, 'Date() reads the clock');
    else if (ts.isIdentifier(n) && (GLOBAL_ONLY.has(n.text) || isCryptoDraw(n.text)) && !isMemberName(n)) {
      const p = n.parent;
      if (ts.isPropertyAccessExpression(p) && p.name === n) {
        if (isCryptoDraw(n.text) || (ts.isIdentifier(p.expression) && GLOBAL_OBJECTS.has(p.expression.text))) at(n, n.text);
      } else at(n, n.text);
    }
  });
  return found;
}

export async function checkPure(root: string): Promise<Violation[]> {
  const found: Violation[] = [];
  for (const file of await sourcesUnder(root, 'src/pure/')) {
    const sf = parse(file, (await readTextIfPresent(root, file)) ?? '');
    for (const ref of importsOf(sf)) {
      if (ref.spec === null) found.push({ code: 'pure-import', file, detail: `line ${ref.line}: a ${ref.kind} import with a computed specifier` });
      else if (FORBIDDEN_IN_PURE.has(moduleName(ref.spec))) found.push({ code: 'pure-import', file, detail: `line ${ref.line}: '${ref.spec}'` });
    }
    found.push(...globalsIn(file, sf));
  }
  return found;
}

export async function checkLayers(root: string): Promise<Violation[]> {
  const found: Violation[] = [];
  for (const file of await sourcesUnder(root, 'src/ports/', 'src/pure/')) {
    for (const ref of importsOf(parse(file, (await readTextIfPresent(root, file)) ?? ''))) {
      if (ref.spec === null || !isRelative(ref.spec)) continue;
      const target = resolveRelative(file, ref.spec);
      if (target.startsWith('src/shell/') || target.startsWith('src/platforms/')) {
        found.push({ code: 'layer-import', file, detail: `line ${ref.line}: imports ${target}` });
      }
    }
  }
  return found;
}

/** Root-relative files each file in `files` names with a relative specifier (every import form). */
async function graphOf(root: string, files: readonly string[]): Promise<Map<string, string[]>> {
  const edges = new Map<string, string[]>();
  for (const file of files) {
    const targets = importsOf(parse(file, (await readTextIfPresent(root, file)) ?? ''))
      .flatMap((ref) => (ref.spec !== null && isRelative(ref.spec) ? [resolveRelative(file, ref.spec)] : []))
    edges.set(file, targets);
  }
  return edges;
}

/** Tarjan's strongly connected components; a component of two or more files, or a file naming itself, is a cycle. */
function cyclesIn(edges: ReadonlyMap<string, readonly string[]>): string[][] {
  let counter = 0;
  const index = new Map<string, number>();
  const low = new Map<string, number>();
  const onStack = new Set<string>();
  const stack: string[] = [];
  const cycles: string[][] = [];
  const connect = (v: string): void => {
    index.set(v, counter);
    low.set(v, counter);
    counter += 1;
    stack.push(v);
    onStack.add(v);
    for (const w of edges.get(v) ?? []) {
      if (!index.has(w)) {
        connect(w);
        low.set(v, Math.min(low.get(v) ?? 0, low.get(w) ?? 0));
      } else if (onStack.has(w)) low.set(v, Math.min(low.get(v) ?? 0, index.get(w) ?? 0));
    }
    if (low.get(v) !== index.get(v)) return;
    const component: string[] = [];
    for (let w = stack.pop(); w !== undefined; w = stack.pop()) {
      onStack.delete(w);
      component.push(w);
      if (w === v) break;
    }
    if (component.length > 1 || (edges.get(v) ?? []).includes(v)) cycles.push(component.sort());
  };
  for (const v of edges.keys()) if (!index.has(v)) connect(v);
  return cycles;
}

export async function checkCycles(root: string): Promise<Violation[]> {
  const files = await sourcesUnder(root, 'src/');
  const known = new Set(files);
  const edges = new Map([...(await graphOf(root, files))].map(([file, targets]): [string, string[]] => [file, targets.filter((t) => known.has(t))]));
  return cyclesIn(edges).map((cycle): Violation => ({ code: 'import-cycle', file: cycle[0] ?? '', detail: cycle.join(' -> ') }));
}

const VERIFIER_FILES = ['src/pure/webauthn', 'src/pure/cose', 'src/pure/challenge'];
const withoutExtension = (path: string): string => path.replace(/\.(ts|js)$/, '');

/** Everything a kit file can reach through relative imports must exclude the verifier's own modules. */
export async function checkKitIndependence(root: string): Promise<Violation[]> {
  const all = (await walk(root)).filter(isSource);
  const edges = await graphOf(root, all);
  const found: Violation[] = [];
  const reachedFrom = new Map<string, string>();
  const queue = all.filter((f) => f.startsWith('test/kit/') && !/\.test\.(ts|js)$/.test(f));
  for (const start of queue) reachedFrom.set(start, start);
  for (let file = queue.shift(); file !== undefined; file = queue.shift()) {
    for (const target of edges.get(file) ?? []) {
      if (VERIFIER_FILES.includes(withoutExtension(target))) {
        found.push({ code: 'kit-shares-verifier', file, detail: `reaches ${target} (from kit file ${reachedFrom.get(file) ?? file})` });
      }
      if (!reachedFrom.has(target)) {
        reachedFrom.set(target, reachedFrom.get(file) ?? file);
        queue.push(target);
      }
    }
  }
  return found;
}

