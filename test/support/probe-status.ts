// KBOX-42: what a platform's probe report says is still unverified, compared with the entry's `unverified` list. A report line names an id
// and ends in VERIFIED, REFUTED or STILL UNVERIFIED (the format of test/arch/probes.ts). Helpers only: nothing here runs on its own.
import type { PlatformEntry } from '../../src/ports/platform.ts';

const escapeForRegExp = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const STILL = /\bSTILL UNVERIFIED\b/;
const naming = (id: string): RegExp => new RegExp(`(?<![\\w.-])${escapeForRegExp(id)}(?![\\w.-])`);

/** What disagrees between the entry's list and the report, or undefined when they say the same. */
export function unverifiedDisagreement(entry: Pick<PlatformEntry, 'id' | 'unverified'>, report: string | undefined): string | undefined {
  if (report === undefined) return entry.unverified.length === 0 ? undefined : `${entry.id}: docs/probes/${entry.id}.md is missing`;
  const marked = report.split('\n').filter((line) => STILL.test(line));
  const unmarked = entry.unverified.filter((id) => !marked.some((line) => naming(id).test(line)));
  if (unmarked.length > 0) return `${entry.id}: listed as unverified but the report does not say STILL UNVERIFIED for ${unmarked.join(', ')}`;
  const unlisted = marked.filter((line) => !entry.unverified.some((id) => naming(id).test(line)));
  if (unlisted.length > 0) return `${entry.id}: the report says STILL UNVERIFIED on a line no listed id names: ${unlisted.join(' | ')}`;
  return undefined;
}
