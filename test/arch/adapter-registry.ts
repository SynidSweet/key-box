// KBOX-23: an adapter folder never imports the registry (it is built from the adapters; `RegistryDeps` lives in `src/ports/platform.ts`).
import type { Violation } from './violation.ts';
import { importsOf, parse, resolveRelative, isRelative } from './parse.ts';
import { readTextIfPresent, sourcesUnder } from './tree.ts';

const REGISTRY = 'src/platforms/registry';
const withoutExtension = (path: string): string => path.replace(/\.(ts|js)$/, '');

export async function checkAdapterRegistryImport(root: string): Promise<Violation[]> {
  const found: Violation[] = [];
  for (const file of await sourcesUnder(root, 'src/platforms/')) {
    if (!/^src\/platforms\/[^/]+\/.+/.test(file)) continue;
    for (const ref of importsOf(parse(file, (await readTextIfPresent(root, file)) ?? ''))) {
      if (ref.spec === null || !isRelative(ref.spec)) continue;
      const target = resolveRelative(file, ref.spec);
      if (withoutExtension(target) === REGISTRY) found.push({ code: 'adapter-imports-registry', file, detail: `line ${ref.line}: imports ${target}` });
    }
  }
  return found;
}
