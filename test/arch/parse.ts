// Parsing with the TypeScript compiler, and the one place that knows every way a file can name another.
import { posix } from 'node:path';
import ts from 'typescript';

export function parse(file: string, text: string): ts.SourceFile {
  const kind = file.endsWith('.js') || file.endsWith('.mjs') || file.endsWith('.cjs') ? ts.ScriptKind.JS : ts.ScriptKind.TS;
  return ts.createSourceFile(file, text, ts.ScriptTarget.ES2023, true, kind);
}

export function visit(node: ts.Node, fn: (n: ts.Node) => void): void {
  fn(node);
  ts.forEachChild(node, (child) => visit(child, fn));
}

export function lineOf(sf: ts.SourceFile, node: ts.Node): number {
  return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
}

export type ImportKind = 'static' | 'type' | 'export' | 'dynamic' | 'require' | 'import-type' | 'import-equals';

export interface ImportRef {
  /** null: the specifier is not a string literal. */
  readonly spec: string | null;
  readonly kind: ImportKind;
  readonly line: number;
}

const literalText = (node: ts.Node | undefined): string | null =>
  node !== undefined && (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) ? node.text : null;

/** Every import, re-export, dynamic import, require call and import type in the file. */
export function importsOf(sf: ts.SourceFile): ImportRef[] {
  const refs: ImportRef[] = [];
  visit(sf, (n) => {
    const line = lineOf(sf, n);
    if (ts.isImportDeclaration(n)) {
      const typeOnly = n.importClause?.isTypeOnly === true;
      refs.push({ spec: literalText(n.moduleSpecifier), kind: typeOnly ? 'type' : 'static', line });
    } else if (ts.isExportDeclaration(n) && n.moduleSpecifier !== undefined) {
      refs.push({ spec: literalText(n.moduleSpecifier), kind: 'export', line });
    } else if (ts.isImportEqualsDeclaration(n) && ts.isExternalModuleReference(n.moduleReference)) {
      refs.push({ spec: literalText(n.moduleReference.expression), kind: 'import-equals', line });
    } else if (ts.isCallExpression(n) && n.expression.kind === ts.SyntaxKind.ImportKeyword) {
      refs.push({ spec: literalText(n.arguments[0]), kind: 'dynamic', line });
    } else if (ts.isCallExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === 'require') {
      refs.push({ spec: literalText(n.arguments[0]), kind: 'require', line });
    } else if (ts.isImportTypeNode(n)) {
      const arg = ts.isLiteralTypeNode(n.argument) ? literalText(n.argument.literal) : null;
      refs.push({ spec: arg, kind: 'import-type', line });
    }
  });
  return refs;
}

export const isRelative = (spec: string): boolean => spec.startsWith('./') || spec.startsWith('../');

/** The root-relative path a relative specifier points at, whether or not the file exists. */
export function resolveRelative(fromFile: string, spec: string): string {
  return posix.normalize(posix.join(posix.dirname(fromFile), spec));
}
