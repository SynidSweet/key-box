// KBOX-6: kb-install loads every module before its first step, so a rollback after the switch never loads code from the new
// release. A dynamic `import()` or `require()` in src/cli, or in any module a src/cli file reaches, is refused.
import type { Violation } from './violation.ts';
import { importsOf, isRelative, parse, resolveRelative } from './parse.ts';
import { readTextIfPresent, sourcesUnder } from './tree.ts';

export async function checkStaticCli(root: string): Promise<Violation[]> {
  const found: Violation[] = [];
  const queue = (await sourcesUnder(root, 'src/cli/')).filter((f) => !/\.test\.(ts|js)$/.test(f));
  const seen = new Set(queue);
  for (let file = queue.shift(); file !== undefined; file = queue.shift()) {
    const text = await readTextIfPresent(root, file);
    if (text === undefined) continue;
    for (const ref of importsOf(parse(file, text))) {
      if (ref.kind === 'dynamic' || ref.kind === 'require') found.push({ code: 'cli-dynamic-import', file, detail: `line ${ref.line}: a ${ref.kind} import in code src/cli loads` });
      if (ref.spec === null || !isRelative(ref.spec) || ref.kind === 'type' || ref.kind === 'import-type') continue;
      const target = resolveRelative(file, ref.spec);
      if (!seen.has(target)) {
        seen.add(target);
        queue.push(target);
      }
    }
  }
  return found;
}
