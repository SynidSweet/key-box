// KBOX-27: what src/ may import, which syntax it may use, and the zero counts.
import { isBuiltin, stripTypeScriptTypes } from 'node:module';
import ts from 'typescript';
import type { Violation, ViolationCode } from './violation.ts';
import { importsOf, isRelative, lineOf, parse, visit } from './parse.ts';
import { isSource, readText, sourcesUnder, walk } from './tree.ts';

const DEV_PACKAGES = ['typescript', '@types/node'];
const isDevPackage = (spec: string): boolean => DEV_PACKAGES.some((name) => spec === name || spec.startsWith(`${name}/`));

export async function checkSourceImports(root: string): Promise<Violation[]> {
  const found: Violation[] = [];
  for (const file of await sourcesUnder(root, 'src/')) {
    for (const ref of importsOf(parse(file, await readText(root, file)))) {
      const at = (code: ViolationCode, detail: string): void => void found.push({ code, file, detail: `line ${ref.line}: ${detail}` });
      if (ref.spec === null) at('import-specifier', `a ${ref.kind} import whose specifier is not a string literal`);
      else if (ref.kind === 'require') at('import-specifier', `require('${ref.spec}'): src is ES modules`);
      else if (isDevPackage(ref.spec)) at('src-imports-dev-package', `'${ref.spec}' is a dev dependency and is not in the release`);
      else if (ref.spec.startsWith('node:')) {
        if (!isBuiltin(ref.spec)) at('import-specifier', `'${ref.spec}' is not a Node builtin`);
      } else if (isRelative(ref.spec)) {
        if (!/\.(ts|js)$/.test(ref.spec)) at('import-specifier', `'${ref.spec}' does not end in .ts or .js`);
      } else at('import-specifier', `'${ref.spec}' is neither a node: builtin nor a relative path`);
    }
  }
  return found;
}

const hasModifier = (node: ts.Node, kind: ts.SyntaxKind): boolean => ts.canHaveModifiers(node) && (ts.getModifiers(node) ?? []).some((m) => m.kind === kind);

/** Syntax Node's type stripping cannot erase, found in the tree so the report names the line. */
function runtimeSyntaxIn(file: string, sf: ts.SourceFile): Violation[] {
  const found: Violation[] = [];
  const at = (node: ts.Node, what: string): void => void found.push({ code: 'ts-runtime-syntax', file, detail: `line ${lineOf(sf, node)}: ${what}` });
  visit(sf, (n) => {
    if (ts.isEnumDeclaration(n) && !hasModifier(n, ts.SyntaxKind.DeclareKeyword)) at(n, 'enum');
    else if (ts.isModuleDeclaration(n) && !hasModifier(n, ts.SyntaxKind.DeclareKeyword) && (n.flags & ts.NodeFlags.Namespace) !== 0) at(n, 'namespace');
    else if (ts.isConstructorDeclaration(n) && n.parameters.some((p) => ts.isParameterPropertyDeclaration(p, n))) at(n, 'parameter property');
    else if (ts.isDecorator(n)) at(n, 'decorator');
    else if (ts.isExportAssignment(n) && n.isExportEquals === true) at(n, 'export =');
    else if (ts.isImportEqualsDeclaration(n)) at(n, 'import =');
  });
  return found;
}

/** The stripped text must keep every line and still parse as JavaScript. */
export function checkStrippedText(file: string, original: string, stripped: string): Violation[] {
  const found: Violation[] = [];
  const before = original.split('\n').length;
  const after = stripped.split('\n').length;
  if (before !== after) found.push({ code: 'strip-line-count', file, detail: `${before} lines became ${after}` });
  const reparsed = ts.transpileModule(stripped, {
    fileName: file.replace(/\.ts$/, '.js'),
    reportDiagnostics: true,
    compilerOptions: { allowJs: true, target: ts.ScriptTarget.ES2023 },
  });
  for (const d of reparsed.diagnostics ?? []) {
    found.push({ code: 'strip-reparse', file, detail: ts.flattenDiagnosticMessageText(d.messageText, ' ') });
  }
  return found;
}

type Stripped = { readonly stripped: string } | { readonly refusal: string };

function tryStrip(strip: (code: string) => string, text: string): Stripped {
  try {
    return { stripped: strip(text) };
  } catch (error) {
    return { refusal: error instanceof Error ? error.message : String(error) };
  }
}

export async function checkErasable(root: string, strip: (code: string) => string = stripTypeScriptTypes): Promise<Violation[]> {
  const found: Violation[] = [];
  for (const file of (await sourcesUnder(root, 'src/')).filter((f) => f.endsWith('.ts') && !f.endsWith('.d.ts'))) {
    const text = await readText(root, file);
    found.push(...runtimeSyntaxIn(file, parse(file, text)));
    const result = tryStrip(strip, text);
    if ('refusal' in result) found.push({ code: 'ts-runtime-syntax', file, detail: `the stripper refused it: ${result.refusal}` });
    else found.push(...checkStrippedText(file, text, result.stripped));
  }
  return found;
}

const COMMENT_MARKERS: [RegExp, ViolationCode][] = [
  [/@ts-ignore/, 'count-ts-ignore'],
  [/@ts-expect-error/, 'count-ts-expect-error'],
  [/@ts-nocheck/, 'count-ts-nocheck'],
  [/eslint-disable/, 'count-eslint-disable'],
  [/\bnoqa\b/, 'count-noqa'],
];
const JSDOC_ANY = /@(?:type|param|returns?|typedef|template|property|prop|callback)\b[^*]*\{[^}]*\bany\b/;

function commentsOf(sf: ts.SourceFile): string[] {
  const seen = new Set<number>();
  const comments: string[] = [];
  const add = (ranges: ts.CommentRange[] | undefined): void => {
    for (const range of ranges ?? []) {
      if (seen.has(range.pos)) continue;
      seen.add(range.pos);
      comments.push(sf.text.slice(range.pos, range.end));
    }
  };
  // Tokens too: a comment after `=` belongs to the `=` token, which forEachChild does not visit.
  const every = (n: ts.Node): void => {
    add(ts.getLeadingCommentRanges(sf.text, n.pos));
    add(ts.getTrailingCommentRanges(sf.text, n.end));
    for (const child of n.getChildren(sf)) every(child);
  };
  every(sf);
  return comments;
}

export async function checkZeroCounts(root: string): Promise<Violation[]> {
  const found: Violation[] = [];
  for (const file of (await walk(root)).filter(isSource)) {
    const sf = parse(file, await readText(root, file));
    const at = (code: ViolationCode, line: number, detail: string): void => void found.push({ code, file, detail: `line ${line}: ${detail}` });
    visit(sf, (n) => {
      if (n.kind === ts.SyntaxKind.AnyKeyword) at('count-any', lineOf(sf, n), 'any');
      else if (ts.isNonNullExpression(n)) at('count-non-null', lineOf(sf, n), 'non-null assertion');
    });
    const plainJs = !file.endsWith('.ts') && !file.endsWith('.mts') && !file.endsWith('.cts');
    for (const comment of commentsOf(sf)) {
      for (const [pattern, code] of COMMENT_MARKERS) if (pattern.test(comment)) at(code, 0, comment.trim().slice(0, 60));
      if (plainJs && JSDOC_ANY.test(comment)) at('count-any', 0, 'any in a JSDoc type');
    }
  }
  return found;
}
