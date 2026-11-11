// KBOX-6: kb-install writes under no path but the spec's: /opt/keybox/releases (and releases/<H>.tmp), /opt/keybox/current
// (and current.tmp), /etc/keybox/trust.json (and trust.json.tmp), /etc/keybox/codes, /var/lib/keybox-install and staging.
// Every node:fs call that writes, in every module src/cli/kb-install.ts reaches, must take each path it writes from one of
// the six members of the installer's `paths` that name them, traced through constants, `join`, template literals, local
// functions and the call sites of a parameter. A path taken from a parameter of a function kb-install never calls is not
// judged; a function handed on as a value is, and a path the check cannot trace is refused. An fs write function is
// followed through an alias (`const w = writeFileSync`, `w = writeFileSync`, `const { writeFileSync: w } = fs`); handed
// on any other way (an argument, an array, an object) it is refused. A `let` that is assigned again is not traced.
// Descriptors: Node has no openat, so a write beneath a held directory goes through a `/proc/self/fd/<n>/` path. Such a
// path is built in ONE module, src/shell/safe-open.ts; anywhere else a `/proc/self/fd/` template is refused. Its writers
// (DESCRIPTOR_WRITES) are judged at their callers: each descriptor they are given must come from `openDirectory` of a path
// kb-install may write. Every export of that module that writes must be declared there.
// Processes: only src/shell/systemd.ts (systemctl and the release self-check) may use node:child_process.
import ts from 'typescript';
import type { Violation } from './violation.ts';
import { importsOf, isRelative, lineOf, parse, resolveRelative, visit } from './parse.ts';
import { readTextIfPresent } from './tree.ts';

const ENTRY = 'src/cli/kb-install.ts';
/** The members of InstallPaths that name the places the spec lets kb-install write. */
const ROOTS = new Set(['releases', 'current', 'trustFile', 'codesDir', 'results', 'staging']);
const FS_MODULES = new Set(['node:fs', 'fs', 'node:fs/promises', 'fs/promises']);
const PROCESS_MODULES = new Set(['node:child_process', 'child_process']);
/** The one module of kb-install that may start a process. */
const PROCESS_MODULE = 'src/shell/systemd.ts';
/** The one module that builds `/proc/self/fd/<n>/` paths and writes beneath held descriptors. */
const DESCRIPTOR_MODULE = 'src/shell/safe-open.ts';
/** Its exports that write beneath a descriptor they are given, and which of their arguments are those descriptors. */
const DESCRIPTOR_WRITES: Readonly<Record<string, readonly number[]>> = { removeAt: [0], trashIn: [0] };
/** Its exports that open a descriptor, each of the path it is given (argument 0). */
const DESCRIPTOR_OPENS = new Set(['openDirectory']);
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
  /** Local name of an fs import or of an alias of one, to the fs function it is; namespaces (`* as fs`, the default
   * import, `promises`) map to ''. */
  readonly fsNames: ReadonlyMap<string, string>;
  /** Local name of an import from DESCRIPTOR_MODULE, to the export it is. */
  readonly descriptorNames: ReadonlyMap<string, string>;
  /** The lines that import node:child_process, in any form. */
  readonly processImports: readonly number[];
}

/** What an expression names among the fs imports: an fs function, '' for a namespace, or undefined. */
function fsRef(fsNames: ReadonlyMap<string, string>, node: ts.Expression): string | undefined {
  const e = strip(node);
  if (ts.isIdentifier(e)) return fsNames.get(e.text);
  if (ts.isPropertyAccessExpression(e) && fsRef(fsNames, e.expression) === '') return e.name.text === 'promises' ? '' : e.name.text;
  return undefined;
}

/** Adds every alias of an fs import (`const w = writeFileSync`, `w = fs.writeFileSync`, `const { writeFileSync: w } = fs`),
 * by name, until no new one appears. */
function addAliases(sf: ts.SourceFile, fsNames: Map<string, string>): void {
  const add = (name: string, to: string): boolean => {
    if (fsNames.get(name) === to) return false;
    fsNames.set(name, to);
    return true;
  };
  for (let changed = true; changed; ) {
    changed = false;
    visit(sf, (n) => {
      if (ts.isVariableDeclaration(n) && n.initializer !== undefined) {
        const to = fsRef(fsNames, n.initializer);
        if (to === undefined) return;
        if (ts.isIdentifier(n.name)) changed = add(n.name.text, to) || changed;
        if (ts.isObjectBindingPattern(n.name) && to === '')
          for (const el of n.name.elements) {
            const from = el.propertyName ?? el.name;
            if (ts.isIdentifier(el.name) && ts.isIdentifier(from)) changed = add(el.name.text, from.text === 'promises' ? '' : from.text) || changed;
          }
      }
      if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(n.left)) {
        const to = fsRef(fsNames, n.right);
        if (to !== undefined) changed = add(n.left.text, to) || changed;
      }
    });
  }
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
      if (bindings !== undefined && ts.isNamedImports(bindings))
        for (const el of bindings.elements) {
          const name = (el.propertyName ?? el.name).text;
          fsNames.set(el.name.text, name === 'promises' ? '' : name);
        }
    }
    addAliases(sf, fsNames);
    const refs = importsOf(sf);
    const processImports = refs.filter((r) => r.spec !== null && PROCESS_MODULES.has(r.spec) && r.kind !== 'type' && r.kind !== 'import-type').map((r) => r.line);
    const descriptorNames = new Map<string, string>();
    for (const statement of sf.statements) {
      if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier) || !isRelative(statement.moduleSpecifier.text)) continue;
      if (resolveRelative(file, statement.moduleSpecifier.text) !== DESCRIPTOR_MODULE || statement.importClause?.isTypeOnly === true) continue;
      const bindings = statement.importClause?.namedBindings;
      if (bindings !== undefined && ts.isNamedImports(bindings)) for (const el of bindings.elements) descriptorNames.set(el.name.text, (el.propertyName ?? el.name).text);
    }
    modules.push({ file, sf, fsNames, descriptorNames, processImports });
    for (const ref of refs) {
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

/** The fs function a call reaches (`writeFileSync(...)`, `fs.writeFileSync(...)` or an alias of either), or undefined. */
function fsCallee(m: Module, call: ts.CallExpression): string | undefined {
  const name = fsRef(m.fsNames, call.expression);
  return name === undefined || name === '' ? undefined : name;
}

/** True for an fs function that writes or opens. */
const writesOrOpens = (name: string): boolean => name in WRITES || OPENS.has(name);

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

const isCallee = (n: ts.Node): boolean => ts.isCallExpression(n.parent) && n.parent.expression === n;
const isImportName = (n: ts.Node): boolean => ts.isImportSpecifier(n.parent) || ts.isImportClause(n.parent) || ts.isNamespaceImport(n.parent);

/** The variable an assignment or an increment changes (`x = …`, `x += …`, `x++`), if it is a plain name. */
function assignedName(n: ts.Node): ts.Identifier | undefined {
  if (ts.isBinaryExpression(n) && n.operatorToken.kind >= ts.SyntaxKind.FirstAssignment && n.operatorToken.kind <= ts.SyntaxKind.LastAssignment) return ts.isIdentifier(n.left) ? n.left : undefined;
  if ((ts.isPrefixUnaryExpression(n) || ts.isPostfixUnaryExpression(n)) && (n.operator === ts.SyntaxKind.PlusPlusToken || n.operator === ts.SyntaxKind.MinusMinusToken)) return ts.isIdentifier(n.operand) ? n.operand : undefined;
  return undefined;
}

/** Where an fs reference may stand without being handed on: called, or as the value of an alias the scan resolved. */
function resolvedUse(n: ts.Node): boolean {
  const p = n.parent;
  if (isCallee(n)) return true;
  if (ts.isVariableDeclaration(p) && p.initializer === n) return true;
  return ts.isBinaryExpression(p) && p.operatorToken.kind === ts.SyntaxKind.EqualsToken && p.right === n && ts.isIdentifier(p.left);
}

/** An fs function that writes or opens (or an fs namespace) used as a value anywhere but a call or a resolved alias. */
function handedOnFs(m: Module, n: ts.Node): boolean {
  if (ts.isPropertyAccessExpression(n) && fsRef(m.fsNames, n.expression) === '') {
    const member = n.name.text === 'promises' ? '' : n.name.text;
    return (member === '' || writesOrOpens(member)) && !resolvedUse(n) && !(member === '' && ts.isPropertyAccessExpression(n.parent));
  }
  if (!ts.isIdentifier(n)) return false;
  const name = m.fsNames.get(n.text);
  if (name === undefined || (name !== '' && !writesOrOpens(name))) return false;
  const p = n.parent;
  if (isImportName(n) || ts.isTypeQueryNode(p) || resolvedUse(n)) return false;
  // A declaration's own name, a member name, an assignment's target: not a use of the import.
  if ((ts.isVariableDeclaration(p) || ts.isBindingElement(p)) && (p.name === n || ('propertyName' in p && p.propertyName === n))) return false;
  if (ts.isPropertyAccessExpression(p) && (p.name === n || name === '')) return false;
  if ((ts.isPropertyAssignment(p) || ts.isPropertySignature(p) || ts.isMethodDeclaration(p)) && p.name === n) return false;
  if (ts.isBinaryExpression(p) && p.left === n && p.operatorToken.kind === ts.SyntaxKind.EqualsToken) return false;
  // `const { writeFileSync: w } = fs`: the namespace is taken apart into resolved aliases.
  return !(name === '' && ts.isVariableDeclaration(p) && ts.isObjectBindingPattern(p.name));
}

/** The exports of DESCRIPTOR_MODULE that write, through themselves or a function of the module they call, and are not
 * declared in DESCRIPTOR_WRITES. */
function undeclaredWriters(m: Module): string[] {
  const fns = new Map<string, ts.Node>();
  const exported = new Set<string>();
  const isExported = (s: ts.Statement): boolean => ts.canHaveModifiers(s) && (ts.getModifiers(s) ?? []).some((x) => x.kind === ts.SyntaxKind.ExportKeyword);
  for (const s of m.sf.statements) {
    if (ts.isFunctionDeclaration(s) && s.name !== undefined) {
      fns.set(s.name.text, s);
      if (isExported(s)) exported.add(s.name.text);
    }
    if (ts.isVariableStatement(s))
      for (const d of s.declarationList.declarations)
        if (ts.isIdentifier(d.name) && d.initializer !== undefined) {
          fns.set(d.name.text, d.initializer);
          if (isExported(s)) exported.add(d.name.text);
        }
  }
  const writing = new Set<string>();
  for (let changed = true; changed; ) {
    changed = false;
    for (const [name, body] of fns) {
      if (writing.has(name)) continue;
      let writes = false;
      visit(body, (n) => {
        if (!ts.isCallExpression(n)) return;
        const fs = fsCallee(m, n);
        if ((fs !== undefined && writtenArgs(fs, n, m.sf).length > 0) || (ts.isIdentifier(n.expression) && writing.has(n.expression.text))) writes = true;
      });
      if (writes) {
        writing.add(name);
        changed = true;
      }
    }
  }
  return [...exported].filter((name) => writing.has(name) && !(name in DESCRIPTOR_WRITES));
}

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
  /** Variables assigned after their declaration: their initializer is not all they ever hold. */
  private readonly reassigned = new Set<ts.Symbol | ts.Node>();

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
        const target = assignedName(n);
        if (target !== undefined) this.reassigned.add(this.checker.getSymbolAtLocation(target) ?? target);
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
      // A descriptor's path names whatever directory the descriptor holds: only DESCRIPTOR_MODULE builds one, judged at its callers.
      if (e.head.text.startsWith('/proc/self/fd/')) return false;
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
    return this.traced(id, (value, at) => this.rooted(at, value, depth), m);
  }

  /** A name whose every value is accepted by `ok`: a variable never assigned again, by its initializer; a parameter, by the
   * argument at every call site of its function. */
  private traced(id: ts.Identifier, ok: (value: ts.Expression, at: Module) => boolean, m: Module): boolean {
    if (this.reassigned.has(this.checker.getSymbolAtLocation(id) ?? id)) return false;
    const decls = this.declarations(id);
    return decls.length > 0 && decls.every((d) => (ts.isVariableDeclaration(d) ? d.initializer !== undefined && ok(d.initializer, m) : ts.isParameter(d) && this.parameter(d, ok)));
  }

  /** True when `node` is a descriptor opened (DESCRIPTOR_OPENS) on a path under one of the roots, by every route traced. */
  descriptor(m: Module, node: ts.Expression, depth = 0): boolean {
    if (depth > DEPTH) return false;
    const e = strip(node);
    if (ts.isCallExpression(e) && ts.isIdentifier(e.expression) && DESCRIPTOR_OPENS.has(m.descriptorNames.get(e.expression.text) ?? '')) {
      const path = e.arguments[0];
      return path !== undefined && this.rooted(m, path, depth + 1);
    }
    return ts.isIdentifier(e) && this.traced(e, (value, at) => this.descriptor(at, value, depth + 1), m);
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
    const refuse = (m: Module, n: ts.Node, detail: string): void => void found.push({ code: 'install-write-path', file: m.file, detail: `line ${lineOf(m.sf, n)}: ${detail}` });
    for (const m of this.modules) {
      for (const line of m.file === PROCESS_MODULE ? [] : m.processImports) found.push({ code: 'install-write-path', file: m.file, detail: `line ${line}: node:child_process outside ${PROCESS_MODULE}: a process writes where no path can be traced` });
      const describing = m.file === DESCRIPTOR_MODULE;
      visit(m.sf, (n) => {
        if (handedOnFs(m, n)) refuse(m, n, `${n.getText(m.sf)} is an fs function that writes, handed on as a value: its writes cannot be traced`);
        if (!describing && ts.isIdentifier(n) && n.text in DESCRIPTOR_WRITES && m.descriptorNames.has(n.text) && !isCallee(n) && !isImportName(n)) refuse(m, n, `${n.text} writes beneath a descriptor and is handed on as a value`);
        if (!ts.isCallExpression(n)) return;
        const name = fsCallee(m, n);
        // DESCRIPTOR_MODULE writes only beneath the descriptors its callers hand it: those are judged at the call sites below.
        if (name !== undefined && !describing)
          for (const index of writtenArgs(name, n, m.sf)) {
            const arg = n.arguments[index];
            if (arg === undefined || !this.rooted(m, arg)) refuse(m, n, `${name} writes ${arg === undefined ? 'no path' : arg.getText(m.sf)}, which is not under a path kb-install may write`);
          }
        const writer = !describing && ts.isIdentifier(n.expression) ? m.descriptorNames.get(n.expression.text) : undefined;
        for (const index of writer === undefined ? [] : (DESCRIPTOR_WRITES[writer] ?? [])) {
          const arg = n.arguments[index];
          if (arg === undefined || !this.descriptor(m, arg)) refuse(m, n, `${writer} writes beneath ${arg === undefined ? 'no descriptor' : arg.getText(m.sf)}, which is not a descriptor opened on a path kb-install may write`);
        }
      });
      if (describing) for (const name of undeclaredWriters(m)) found.push({ code: 'install-write-path', file: m.file, detail: `${name} writes beneath a descriptor but is not in DESCRIPTOR_WRITES, so its callers go unjudged` });
    }
    return found;
  }
}

export async function checkInstallWrites(root: string): Promise<Violation[]> {
  return new Tracer(await reachable(root)).findings();
}
