// KBOX-42: each platform folder has a probe report naming every UNVERIFIED id of that platform, with a status.
import type { Violation } from './violation.ts';
import { readTextIfPresent, walk } from './tree.ts';

const STATUS = /\b(VERIFIED|REFUTED|STILL UNVERIFIED)\b/;
const escapeForRegExp = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

async function readIds(root: string, id: string): Promise<{ ids: string[] } | { problem: string }> {
  const text = await readTextIfPresent(root, `src/platforms/${id}/unverified.json`);
  if (text === undefined) return { problem: 'unverified.json is missing' };
  try {
    const value: unknown = JSON.parse(text);
    if (!Array.isArray(value) || value.some((x) => typeof x !== 'string' || x === '')) return { problem: 'unverified.json must be an array of non-empty strings' };
    return { ids: value.map(String) };
  } catch (error) {
    return { problem: `unverified.json is not JSON: ${error instanceof Error ? error.message : String(error)}` };
  }
}

export async function checkProbes(root: string): Promise<Violation[]> {
  const found: Violation[] = [];
  const platforms = new Set(
    (await walk(root))
      .filter((f) => f.startsWith('src/platforms/') && f.split('/').length > 3)
      .map((f) => f.split('/')[2] ?? ''),
  );
  for (const platform of [...platforms].sort()) {
    const probeFile = `docs/probes/${platform}.md`;
    const probe = await readTextIfPresent(root, probeFile);
    if (probe === undefined) {
      found.push({ code: 'probe-missing', file: `src/platforms/${platform}`, detail: `${probeFile} is not committed` });
      continue;
    }
    const list = await readIds(root, platform);
    if ('problem' in list) {
      found.push({ code: 'unverified-list', file: `src/platforms/${platform}/unverified.json`, detail: list.problem });
      continue;
    }
    for (const id of list.ids) {
      const named = new RegExp(`(?<![\\w.-])${escapeForRegExp(id)}(?![\\w.-])`);
      if (!probe.split('\n').some((line) => named.test(line) && STATUS.test(line))) {
        found.push({ code: 'probe-item-missing', file: probeFile, detail: `${id} has no line with VERIFIED, REFUTED or STILL UNVERIFIED` });
      }
    }
  }
  return found;
}
