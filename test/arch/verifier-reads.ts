// KBOX-58: a platform kit's or registry entry's `verifier` is read only through `verifierFor`, which asks whether it applies to the key. Any
// property access, element access or destructuring named `verifier` on a value typed PlatformKit or PlatformEntry (a Pick of either included)
// outside the kit builders is refused. Judged with the type checker, so a read through an alias or an optional chain is seen as well.
import { join } from 'node:path';
import ts from 'typescript';
import type { Violation } from './violation.ts';
import { lineOf, visit } from './parse.ts';
import { readTextIfPresent, sourcesUnder } from './tree.ts';

const MEMBER = 'verifier';
/** The interfaces whose `verifier` member only `verifierFor` may read. */
const KIT_TYPES: ReadonlySet<string> = new Set(['PlatformKit', 'PlatformEntry']);
/** Where `verifierFor` lives, and where a kit is built from an entry. */
const EXEMPT: ReadonlySet<string> = new Set(['src/shell/rotation-ports.ts', 'src/shell/platform-source.ts']);

/** The compiler options of the tree's tsconfig.json (a tree without one is judged with the strict defaults). */
async function optionsOf(root: string): Promise<ts.CompilerOptions> {
  const text = await readTextIfPresent(root, 'tsconfig.json');
  if (text === undefined) return { strict: true, allowImportingTsExtensions: true, noEmit: true };
  const parsed = ts.parseConfigFileTextToJson('tsconfig.json', text);
  if (parsed.error !== undefined) throw new Error(`tsconfig.json does not parse: ${ts.flattenDiagnosticMessageText(parsed.error.messageText, ' ')}`);
  return ts.convertCompilerOptionsFromJson((parsed.config as { compilerOptions?: unknown }).compilerOptions ?? {}, root).options;
}

/** True when the declaration is a member of an interface or a type literal named one of the kit types. */
function declaredOnKit(declaration: ts.Declaration): boolean {
  const owner = declaration.parent;
  if (ts.isInterfaceDeclaration(owner)) return KIT_TYPES.has(owner.name.text);
  return ts.isTypeLiteralNode(owner) && ts.isTypeAliasDeclaration(owner.parent) && KIT_TYPES.has(owner.parent.name.text);
}

/** Whether a value of this type holds the kit types' `verifier`: any member of a union, the type itself otherwise. */
function isKitTyped(type: ts.Type): boolean {
  const members = type.isUnion() ? type.types : [type];
  return members.some((t) => t.getProperty(MEMBER)?.declarations?.some(declaredOnKit) === true);
}

/** The value a node reads `verifier` from, when it reads it: `x.verifier`, `x['verifier']`, or `{ verifier } = x` / `{ verifier: v }: X`. */
function readFrom(node: ts.Node): ts.Node | undefined {
  if (ts.isPropertyAccessExpression(node) && node.name.text === MEMBER) return node.expression;
  if (ts.isElementAccessExpression(node) && ts.isStringLiteralLike(node.argumentExpression) && node.argumentExpression.text === MEMBER) return node.expression;
  if (ts.isBindingElement(node) && ts.isObjectBindingPattern(node.parent)) {
    const name = node.propertyName ?? node.name;
    if ((ts.isIdentifier(name) || ts.isStringLiteralLike(name)) && name.text === MEMBER) return node.parent;
  }
  return undefined;
}

export async function checkVerifierReads(root: string): Promise<Violation[]> {
  const files = (await sourcesUnder(root, 'src/')).filter((f) => f.endsWith('.ts'));
  const program = ts.createProgram(
    files.map((f) => join(root, f)),
    { ...(await optionsOf(root)), noEmit: true },
  );
  const checker = program.getTypeChecker();
  const found: Violation[] = [];
  for (const file of files) {
    if (EXEMPT.has(file)) continue;
    const sf = program.getSourceFile(join(root, file));
    if (sf === undefined) {
      found.push({ code: 'unreadable', file, detail: 'the program did not load the file' });
      continue;
    }
    visit(sf, (node) => {
      const from = readFrom(node);
      if (from !== undefined && isKitTyped(checker.getTypeAtLocation(from))) {
        found.push({ code: 'verifier-read', file, detail: `line ${lineOf(sf, node)}: reads a kit's verifier without verifierFor` });
      }
    });
  }
  return found;
}
