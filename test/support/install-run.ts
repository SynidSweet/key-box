// One kb-install run in a process of its own, for tests that start it under limits of their own (a low `ulimit -n`):
// its units always restart and pass, and it prints the process's "Max open files" line so the test can see the limit held.
// Run with no arguments (as `node --test` does to every file under test/) it does nothing.
import { readFileSync } from 'node:fs';
import { parseWordlist } from '../../src/pure/codes.ts';
import { systemClock } from '../../src/shell/clock.ts';
import { runInstaller } from '../../src/shell/installer.ts';
import type { InstallPaths } from '../../src/shell/installer.ts';

const [pathsFile] = process.argv.slice(2);

if (pathsFile !== undefined) {
  const paths = JSON.parse(readFileSync(pathsFile, 'utf8')) as InstallPaths;
  const wordlist = parseWordlist(readFileSync(new URL('../../src/data/wordlist.txt', import.meta.url), 'utf8'));
  const limit = readFileSync('/proc/self/limits', 'utf8').split('\n').find((l) => l.startsWith('Max open files'));
  process.stdout.write(`${limit ?? 'no limit line'}\n`);
  await runInstaller({
    paths,
    units: { restart: () => Promise.resolve(), healthCheck: () => Promise.resolve(true), selfCheck: () => Promise.resolve(true) },
    clock: systemClock,
    wordlist,
    domain: undefined,
    journal: (code) => void process.stderr.write(`journal ${code}\n`),
  });
}
