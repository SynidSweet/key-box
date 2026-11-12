// KBOX-42: what a platform's probe report says is still unverified, compared with the entry's `unverified` list, and the folders of
// `src/platforms/` compared with the registry. A report row is a table row: the id is the backticked text of its first cell and the status is
// its last cell (VERIFIED, REFUTED or STILL UNVERIFIED); prose in the other cells names other ids freely. Helpers only: nothing here runs on its own.
import type { PlatformEntry } from '../../src/ports/platform.ts';

const STILL = /\bSTILL UNVERIFIED\b/;
const CELL_SPLIT = /(?<!\\)\|/;
const ID_CELL = /^`([^`]+)`$/;

interface Row {
  readonly id: string;
  readonly still: boolean;
}

/** Every table row whose first cell is one backticked id, with whether its last cell says STILL UNVERIFIED. */
function rowsOf(report: string): Row[] {
  return report.split('\n').flatMap((line) => {
    if (!line.trimStart().startsWith('|')) return [];
    const cells = line.trim().split(CELL_SPLIT).slice(1, -1).map((c) => c.trim());
    const first = cells[0];
    const id = first === undefined ? undefined : ID_CELL.exec(first)?.[1];
    const last = cells[cells.length - 1];
    return id === undefined || cells.length < 2 || last === undefined ? [] : [{ id, still: STILL.test(last) }];
  });
}

/** What disagrees between the entry's list and the report, or undefined when they say the same. */
export function unverifiedDisagreement(entry: Pick<PlatformEntry, 'id' | 'unverified'>, report: string | undefined): string | undefined {
  if (report === undefined) return entry.unverified.length === 0 ? undefined : `${entry.id}: docs/probes/${entry.id}.md is missing`;
  const marked = new Set(rowsOf(report).filter((r) => r.still).map((r) => r.id));
  const unmarked = entry.unverified.filter((id) => !marked.has(id));
  if (unmarked.length > 0) return `${entry.id}: listed as unverified but the report does not say STILL UNVERIFIED for ${unmarked.join(', ')}`;
  const unlisted = [...marked].filter((id) => !entry.unverified.includes(id));
  if (unlisted.length > 0) return `${entry.id}: the report says STILL UNVERIFIED for ${unlisted.join(', ')} and the list leaves it out`;
  return undefined;
}

const UNVERIFIED_ONLY = 'unverified.json';

/**
 * What disagrees between the registry and the tree: `files` are the paths under `src/platforms/` and `probes` the paths under `docs/probes/`
 * (both relative to the repo root). A folder holding only `unverified.json` is probed and not built, so it needs no entry; a folder with any
 * other file needs one; an entry needs its folder and its probe report.
 */
export function platformGaps(entryIds: readonly string[], files: readonly string[], probes: readonly string[]): string[] {
  const folders = new Map<string, string[]>();
  for (const path of files) {
    const [, , id, ...rest] = path.split('/');
    if (id === undefined || rest.length === 0) continue;
    folders.set(id, [...(folders.get(id) ?? []), rest.join('/')]);
  }
  const gaps: string[] = [];
  for (const [id, inside] of folders) {
    if (!entryIds.includes(id) && inside.some((f) => f !== UNVERIFIED_ONLY)) gaps.push(`src/platforms/${id}/ holds code and has no registry entry`);
  }
  for (const id of entryIds) {
    if (!folders.has(id)) gaps.push(`registry entry ${id} has no folder src/platforms/${id}/`);
    if (!probes.includes(`docs/probes/${id}.md`)) gaps.push(`registry entry ${id} has no docs/probes/${id}.md`);
  }
  return gaps;
}
