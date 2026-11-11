// KBOX-6: kb-install writes under no path but the spec's: /opt/keybox/releases (and releases/<H>.tmp), /opt/keybox/current
// (and current.tmp), /etc/keybox/trust.json (and trust.json.tmp), /etc/keybox/codes, /var/lib/keybox-install and staging.
// Every node:fs call that writes, in every module src/cli/kb-install.ts reaches, must take each path it writes from one of
// the six members of the installer's `paths` that name them, or from a directory descriptor it holds (`/proc/self/fd/<n>/`),
// traced through constants, `join`, template literals, local functions and the call sites of a parameter. A path taken
// from a parameter of a function kb-install never calls is not judged; a function handed on as a value is, and
// a path the check cannot trace is refused.
import ts from 'typescript';
import type { Violation } from './violation.ts';
import { importsOf, isRelative, lineOf, parse, resolveRelative, visit } from './parse.ts';
import { readTextIfPresent } from './tree.ts';

const ENTRY = 'src/cli/kb-install.ts';
/** The members of InstallPaths that name the places the spec lets kb-install write. */
const ROOTS = new Set(['releases', 'current', 'trustFile', 'codesDir', 'results', 'staging']);
const FS_MODULES = new Set(['node:fs', 'fs', 'node:fs/promises', 'fs/promises']);
/** Each fs function that writes, and which of its arguments are paths it writes. */
const WRITES: Readonly<Record<string, readonly number[]>> = {
  writeFileSync: [0], appendFileSync: [0], mkdirSync: [0], mkdtempSync: [0], renameSync: [0, 1], rmSync: [0], rmdirSync: [0], unlinkSync: [0],
  symlinkSync: [1], linkSync: [1], copyFileSync: [1], cpSync: [1], chmodSync: [0], lchmodSync: [0], chownSync: [0], lchownSync: [0],
  truncateSync: [0], utimesSync: [0], lutimesSync: [0], createWriteStream: [0], writeFile: [0], appendFile: [0], mkdir: [0], mkdtemp: [0],
  rename: [0, 1], rm: [0], rmdir: [0], unlink: [0], symlink: [1], link: [1], copyFile: [1], cp: [1], chmod: [0], chown: [0], truncate: [0], utimes: [0],
};
const OPENS = new Set(['openSync', 'open']);
const READ_ONLY_FLAGS = new Set(['r', 'rs', 'sr']);
const WRITE_FLAG = /\bO_(WRONLY|RDWR|CREAT|APPEND|TRUNC)\b/;
const DEPTH = 12;

interface Module {
  readonly file: string;
  readonly sf: ts.SourceFile;
  /** Local name of an fs import, to the fs function it is; namespace imports map to ''. */
  readonly fsNames: ReadonlyMap<string, string>;
}

async function reachable(root: string): Promise<Module[]> {
  const modules: Module[] = [];
  const queue = [ENTRY];
  const seen = new Set(queue);
  for (let file = queue.shift(); file !== undefined; file = queue.shift()) {
    const text = await readTextIfPresent(root, file);
    if (text === undefined) continue;
    const sf = parse(`/${file}`, text);
    const fsNames = new Map<string, string>();
    for (const statement of sf.statements) {
      if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier) || !FS_MODULES.has(statement.moduleSpecifier.text)) continue;
      const clause = statement.importClause;
      if (clause?.name !== undefined) fsNames.set(clause.name.text, '');
      const bindings = clause?.namedBindings;
      if (bindings !== undefined && ts.isNamespaceImport(bindings)) fsNames.set(bindings.name.text, '');
      if (bindings !== undefined && ts.isNamedImports(bindings)) for (const el of bindings.elements) fsNames.set(el.name.text, (el.propertyName ?? el.name).text);
    }
    modules.push({ file, sf, fsNames });
    for (const ref of importsOf(sf)) {
      if (ref.spec === null || !isRelative(ref.spec) || ref.kind === 'type' || ref.kind === 'import-type') continue;
      const target = resolveRelative(file, ref.spec);
      if (!seen.has(target)) {
        seen.add(target);
        queue.push(target);
      }
    }
  }
  return modules;
}

/** The fs function a call reaches (`writeFileSync(...)` or `fs.writeFileSync(...)`), or undefined. */
function fsCallee(m: Module, call: ts.CallExpression): string | undefined {
  const callee = call.expression;
  if (ts.isIdentifier(callee)) {
    const name = m.fsNames.get(callee.text);
    return name === undefined || name === '' ? undefined : name;
  }
  if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression) && m.fsNames.get(callee.expression.text) === '') return callee.name.text;
  return undefined;
}

/** The argument positions a call writes to; an open counts unless its flags are read-only. */
function writtenArgs(name: string, call: ts.CallExpression, sf: ts.SourceFile): readonly number[] {
  if (OPENS.has(name)) {
    const flags = call.arguments[1];
    if (flags === undefined) return [];
    if (ts.isStringLiteral(flags)) return READ_ONLY_FLAGS.has(flags.text) ? [] : [0];
    const text = flags.getText(sf);
    return WRITE_FLAG.test(text) || !/\bO_RDONLY\b/.test(text) ? [0] : [];
  }
  return WRITES[name] ?? [];
}

const strip = (node: ts.Expression): ts.Expression => {
  let e = node;
  while (ts.isParenthesizedExpression(e) || ts.isAsExpression(e) || ts.isNonNullExpression(e) || ts.isSatisfiesExpression(e)) e = e.expression;
  return e;
};

/** The name a function is called by: a function declaration's, or the const it is assigned to. */
function functionName(fn: ts.SignatureDeclaration): string | undefined {
  if (ts.isFunctionDeclaration(fn)) return fn.name?.text;
  if ((ts.isArrowFunction(fn) || ts.isFunctionExpression(fn)) && ts.isVariableDeclaration(fn.parent) && ts.isIdentifier(fn.parent.name)) return fn.parent.name.text;
  return undefined;
}

function returnsOf(fn: ts.SignatureDeclaration): ts.Expression[] {
  if (ts.isArrowFunction(fn) && !ts.isBlock(fn.body)) return [fn.body];
  const out: ts.Expression[] = [];
  const body = 'body' in fn ? fn.body : undefined;
  if (body === undefined || !ts.isBlock(body as ts.Node)) return out;
  visit(body as ts.Node, (n) => {
    if (ts.isReturnStatement(n) && n.expression !== undefined) out.push(n.expression);
  });
  return out;
}

class Tracer {
  private readonly calls = new Map<string, { readonly m: Module; readonly call: ts.CallExpression }[]>();
  /** Names used as a value somewhere (not in callee position, not where declared): such a function may be called anywhere. */
  private readonly handedOn = new Set<string>();

  private readonly checker: ts.TypeChecker;

  private readonly modules: readonly Module[];

  constructor(modules: readonly Module[]) {
    this.modules = modules;
    // A program over these modules alone, for scope-correct name lookup; imports stay unresolved and are matched by name.
    const options: ts.CompilerOptions = { noResolve: true, noLib: true, allowJs: true, types: [], target: ts.ScriptTarget.ES2023, module: ts.ModuleKind.ESNext };
    const byName = new Map(modules.map((m) => [m.sf.fileName, m.sf]));
    const host = ts.createCompilerHost(options);
    host.getSourceFile = (name) => byName.get(name);
    host.fileExists = (name) => byName.has(name);
    host.readFile = () => undefined;
    host.getCurrentDirectory = () => '/';
    this.checker = ts.createProgram([...byName.keys()], options, host).getTypeChecker();
    for (const m of modules)
      visit(m.sf, (n) => {
        if (ts.isCallExpression(n) && ts.isIdentifier(n.expression)) this.calls.set(n.expression.text, [...(this.calls.get(n.expression.text) ?? []), { m, call: n }]);
        if (ts.isIdentifier(n) && !this.isCalleeOrDeclaration(n)) this.handedOn.add(n.text);
      });
  }

  private isCalleeOrDeclaration(id: ts.Identifier): boolean {
    const p = id.parent;
    if (ts.isCallExpression(p) && p.expression === id) return true;
    if ((ts.isVariableDeclaration(p) || ts.isFunctionDeclaration(p) || ts.isParameter(p) || ts.isImportSpecifier(p) || ts.isExportSpecifier(p) || ts.isBindingElement(p)) && p.name === id) return true;
    if (ts.isPropertyAccessExpression(p) && p.name === id) return true;
    return (ts.isPropertyAssignment(p) || ts.isPropertySignature(p) || ts.isMethodDeclaration(p)) && p.name === id;
  }

  /** True when `node` names a path under one of the roots, by every route the check can trace. */
  rooted(m: Module, node: ts.Expression, depth = 0): boolean {
    if (depth > DEPTH) return false;
    const e = strip(node);
    if (ts.isPropertyAccessExpression(e)) {
      if (ts.isIdentifier(e.expression) && e.expression.text === 'paths' && ROOTS.has(e.name.text)) return true;
      return this.member(m, e.expression, e.name.text, depth + 1);
    }
    if (ts.isTemplateExpression(e)) {
      if (e.head.text.startsWith('/proc/self/fd/')) return true;
      const first = e.templateSpans[0];
      return e.head.text === '' && first !== undefined && this.rooted(m, first.expression, depth + 1);
    }
    if (ts.isCallExpression(e)) return this.call(m, e, depth + 1);
    if (ts.isIdentifier(e)) return this.identifier(m, e, depth + 1);
    return false;
  }

  private call(m: Module, e: ts.CallExpression, depth: number): boolean {
    const callee = e.expression;
    const [first, ...rest] = e.arguments;
    if (ts.isIdentifier(callee) && callee.text === 'join') {
      const climbs = rest.some((a) => (ts.isStringLiteral(a) || ts.isNoSubstitutionTemplateLiteral(a)) && a.text.split('/').includes('..'));
      return first !== undefined && !climbs && this.rooted(m, first, depth);
    }
    // Buffer.from(path) and Buffer.concat([path, name]) keep the path they start with.
    if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression) && callee.expression.text === 'Buffer') {
      if (callee.name.text === 'from') return first !== undefined && this.rooted(m, first, depth);
      if (callee.name.text === 'concat' && first !== undefined && ts.isArrayLiteralExpression(first)) {
        const head = first.elements[0];
        return head !== undefined && !ts.isSpreadElement(head) && this.rooted(m, head, depth);
      }
      return false;
    }
    if (!ts.isIdentifier(callee)) return false;
    const fns = this.functionsNamed(m, callee.text);
    return fns.length > 0 && fns.every((fn) => {
      const returned = returnsOf(fn);
      return returned.length > 0 && returned.every((r) => this.rooted(m, r, depth));
    });
  }

  /** A local function's declarations by name, in this module or (by name) in another module kb-install reaches. */
  private functionsNamed(m: Module, name: string): ts.SignatureDeclaration[] {
    const out: ts.SignatureDeclaration[] = [];
    for (const mod of [m, ...this.modules.filter((x) => x !== m)]) {
      visit(mod.sf, (n) => {
        if (ts.isFunctionDeclaration(n) && n.name?.text === name) out.push(n);
        if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.name.text === name && n.initializer !== undefined && (ts.isArrowFunction(n.initializer) || ts.isFunctionExpression(n.initializer))) out.push(n.initializer);
      });
      if (out.length > 0) return out;
    }
    return out;
  }

  /** What a name is declared as, by the compiler's scope rules: consts and parameters only. */
  private declarations(id: ts.Identifier): ts.Node[] {
    return (this.checker.getSymbolAtLocation(id)?.declarations ?? []).filter((d) => ts.isVariableDeclaration(d) || ts.isParameter(d));
  }

  private identifier(m: Module, id: ts.Identifier, depth: number): boolean {
    const decls = this.declarations(id);
    return decls.length > 0 && decls.every((d) => (ts.isVariableDeclaration(d) ? d.initializer !== undefined && this.rooted(m, d.initializer, depth) : ts.isParameter(d) && this.parameter(d, (arg, at) => this.rooted(at, arg, depth))));
  }

  /** `x.member` where x is a const object literal or a parameter: the member as given there. */
  private member(m: Module, of: ts.Expression, member: string, depth: number): boolean {
    if (!ts.isIdentifier(of)) return false;
    const decls = this.declarations(of);
    const fromLiteral = (at: Module, value: ts.Expression | undefined): boolean => {
      if (value === undefined) return false;
      const v = strip(value);
      if (!ts.isObjectLiteralExpression(v)) return false;
      const prop = v.properties.find((p) => p.name !== undefined && ts.isIdentifier(p.name) && p.name.text === member);
      if (prop === undefined) return false;
      if (ts.isPropertyAssignment(prop)) return this.rooted(at, prop.initializer, depth);
      return ts.isShorthandPropertyAssignment(prop) && this.rooted(at, prop.name, depth);
    };
    return decls.length > 0 && decls.every((d) => (ts.isVariableDeclaration(d) ? fromLiteral(m, d.initializer) : ts.isParameter(d) && this.parameter(d, (arg, at) => fromLiteral(at, arg))));
  }

  /** Every call site of the parameter's function passes an argument `ok` accepts; a function never called is never judged. */
  private parameter(p: ts.ParameterDeclaration, ok: (arg: ts.Expression, at: Module) => boolean): boolean {
    const fn = p.parent;
    const name = functionName(fn);
    if (name === undefined || this.handedOn.has(name)) return false;
    const index = fn.parameters.indexOf(p);
    return (this.calls.get(name) ?? []).every(({ m, call }) => {
      const arg = call.arguments[index];
      return arg !== undefined && ok(arg, m);
    });
  }

  findings(): Violation[] {
    const found: Violation[] = [];
    for (const m of this.modules)
      visit(m.sf, (n) => {
        if (!ts.isCallExpression(n)) return;
        const name = fsCallee(m, n);
        if (name === undefined) return;
        for (const index of writtenArgs(name, n, m.sf)) {
          const arg = n.arguments[index];
          if (arg === undefined || !this.rooted(m, arg)) found.push({ code: 'install-write-path', file: m.file, detail: `line ${lineOf(m.sf, n)}: ${name} writes ${arg === undefined ? 'no path' : arg.getText(m.sf)}, which is not under a path kb-install may write` });
        }
      });
    return found;
  }
}

export async function checkInstallWrites(root: string): Promise<Violation[]> {
  return new Tracer(await reachable(root)).findings();
}
