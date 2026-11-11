// Reading a tree of files: every check works on a root directory, so a fixture and the repo are judged alike.
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';

/** Relative POSIX paths of every file under `dir` (relative to `root`); hidden folders and node_modules are skipped. */
export async function walk(root: string, dir = ''): Promise<string[]> {
  let entries;
  try {
    entries = await readdir(join(root, dir), { withFileTypes: true });
  } catch (error) {
    if (isMissing(error)) return [];
    throw error;
  }
  const found: string[] = [];
  for (const entry of entries) {
    if (entry.name.startsWith('.') || entry.name === 'node_modules') continue;
    const rel = dir === '' ? entry.name : `${dir}/${entry.name}`;
    if (entry.isDirectory()) found.push(...(await walk(root, rel)));
    else if (entry.isFile()) found.push(rel);
  }
  return found.sort();
}

export function isMissing(error: unknown): boolean {
  return error instanceof Error && 'code' in error && error.code === 'ENOENT';
}

export const isSource = (path: string): boolean => /\.(ts|js|mjs|cjs|mts|cts)$/.test(path);

export async function sourcesUnder(root: string, ...prefixes: string[]): Promise<string[]> {
  const all = await walk(root);
  return all.filter((p) => isSource(p) && prefixes.some((prefix) => p.startsWith(prefix)));
}

export async function readText(root: string, rel: string): Promise<string> {
  return readFile(join(root, rel), 'utf8');
}

/** The file's text, or undefined when it does not exist. */
export async function readTextIfPresent(root: string, rel: string): Promise<string | undefined> {
  try {
    return await readText(root, rel);
  } catch (error) {
    if (isMissing(error)) return undefined;
    throw error;
  }
}
