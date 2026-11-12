// One member of named interfaces may be read only in named files (KBOX-41's keyInfo; verifier-reads.ts is the same check written for KBOX-58's
// verifier before this one, kept as it is). Any property access, element access
// or destructuring of that member on a value whose type declares it on one of the interfaces (a Pick of one included) is refused outside the
// exempt files. Judged with the type checker, so a read through an alias or an optional chain is seen as well.
import { join } from 'node:path';
import ts from 'typescript';
import type { Violation, ViolationCode } from './violation.ts';
import { lineOf, visit } from './parse.ts';
import { readTextIfPresent, sourcesUnder } from './tree.ts';

export interface MemberRule {
  /** The member's name. */
  readonly member: string;
  /** The interfaces (or type aliases of a type literal) whose member only the exempt files may read. */
  readonly owners: ReadonlySet<string>;
  /** Tree-relative paths under src/ that may read it. */
  readonly exempt: ReadonlySet<string>;
  readonly code: ViolationCode;
  /** What a finding says, after its line number. */
  readonly says: string;
}

/** The compiler options of the tree's tsconfig.json (a tree without one is judged with the strict defaults). */
async function optionsOf(root: string): Promise<ts.CompilerOptions> {
  const text = await readTextIfPresent(root, 'tsconfig.json');
  if (text === undefined) return { strict: true, allowImportingTsExtensions: true, noEmit: true };
  const parsed = ts.parseConfigFileTextToJson('tsconfig.json', text);
  if (parsed.error !== undefined) throw new Error(`tsconfig.json does not parse: ${ts.flattenDiagnosticMessageText(parsed.error.messageText, ' ')}`);
  return ts.convertCompilerOptionsFromJson((parsed.config as { compilerOptions?: unknown }).compilerOptions ?? {}, root).options;
}

/** True when the declaration is a member of an interface or a type literal named one of the owners. */
function declaredOn(owners: ReadonlySet<string>, declaration: ts.Declaration): boolean {
  const owner = declaration.parent;
  if (ts.isInterfaceDeclaration(owner)) return owners.has(owner.name.text);
  return ts.isTypeLiteralNode(owner) && ts.isTypeAliasDeclaration(owner.parent) && owners.has(owner.parent.name.text);
}

/** Whether a value of this type holds the owners' member: any member of a union, the type itself otherwise. */
function holdsMember(rule: MemberRule, type: ts.Type): boolean {
  const members = type.isUnion() ? type.types : [type];
  return members.some((t) => t.getProperty(rule.member)?.declarations?.some((d) => declaredOn(rule.owners, d)) === true);
}

/** The value a node reads the member from, when it reads it: `x.m`, `x['m']`, or `{ m } = x` / `{ m: v }: X`. */
function readFrom(member: string, node: ts.Node): ts.Node | undefined {
  if (ts.isPropertyAccessExpression(node) && node.name.text === member) return node.expression;
  if (ts.isElementAccessExpression(node) && ts.isStringLiteralLike(node.argumentExpression) && node.argumentExpression.text === member) return node.expression;
  if (ts.isBindingElement(node) && ts.isObjectBindingPattern(node.parent)) {
    const name = node.propertyName ?? node.name;
    if ((ts.isIdentifier(name) || ts.isStringLiteralLike(name)) && name.text === member) return node.parent;
  }
  return undefined;
}

export async function checkMemberReads(root: string, rule: MemberRule): Promise<Violation[]> {
  const files = (await sourcesUnder(root, 'src/')).filter((f) => f.endsWith('.ts'));
  const program = ts.createProgram(
    files.map((f) => join(root, f)),
    { ...(await optionsOf(root)), noEmit: true },
  );
  const checker = program.getTypeChecker();
  const found: Violation[] = [];
  for (const file of files) {
    if (rule.exempt.has(file)) continue;
    const sf = program.getSourceFile(join(root, file));
    if (sf === undefined) {
      found.push({ code: 'unreadable', file, detail: 'the program did not load the file' });
      continue;
    }
    visit(sf, (node) => {
      const from = readFrom(rule.member, node);
      if (from !== undefined && holdsMember(rule, checker.getTypeAtLocation(from))) {
        found.push({ code: rule.code, file, detail: `line ${lineOf(sf, node)}: ${rule.says}` });
      }
    });
  }
  return found;
}
