// KBOX-56: a migration is additive only. The statements of `src/shell/migrations.ts` (every string inside a `*_MIGRATIONS` list) are read as text.
import ts from 'typescript';
import type { Violation } from './violation.ts';
import { lineOf, parse, visit } from './parse.ts';
import { readTextIfPresent } from './tree.ts';

const FILE = 'src/shell/migrations.ts';

const REFUSED: readonly { readonly pattern: RegExp; readonly why: string }[] = [
  { pattern: /\bDROP\b/i, why: 'DROP' },
  { pattern: /\bRENAME\b/i, why: 'RENAME' },
  { pattern: /\bALTER\s+TABLE\s+\S+\s+ALTER\b/i, why: 'ALTER TABLE ... ALTER' },
];

/** `ADD COLUMN x TYPE ... NOT NULL` with no DEFAULT in the statement. */
const notNullWithoutDefault = (statement: string): boolean => /\bADD\s+COLUMN\b/i.test(statement) && /\bNOT\s+NULL\b/i.test(statement) && !/\bDEFAULT\b/i.test(statement);

export async function checkMigrations(root: string): Promise<Violation[]> {
  const text = await readTextIfPresent(root, FILE);
  if (text === undefined) return [];
  const sf = parse(FILE, text);
  const found: Violation[] = [];
  visit(sf, (n) => {
    if (!ts.isVariableDeclaration(n) || !ts.isIdentifier(n.name) || !n.name.text.endsWith('_MIGRATIONS') || n.initializer === undefined) return;
    visit(n.initializer, (m) => {
      if (!ts.isStringLiteral(m) && !ts.isNoSubstitutionTemplateLiteral(m)) return;
      const refused = REFUSED.filter((r) => r.pattern.test(m.text)).map((r) => r.why);
      if (notNullWithoutDefault(m.text)) refused.push('NOT NULL column without DEFAULT');
      for (const why of refused) found.push({ code: 'migration-not-additive', file: FILE, detail: `line ${lineOf(sf, m)}: ${why}` });
    });
  });
  return found;
}
