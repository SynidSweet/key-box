// A kb-install run in a process of its own that kills itself (SIGKILL) at one step of an install, for the interruption
// tests of KBOX-6: nothing after the kill runs, as when systemd's TimeoutStartSec or a power cut ends the oneshot. Its
// units always restart and pass. Run with no arguments (as `node --test` does to every file under test/) it does nothing.
import { readFileSync } from 'node:fs';
import { parseWordlist } from '../../src/pure/codes.ts';
import { systemClock } from '../../src/shell/clock.ts';
import { runInstaller } from '../../src/shell/installer.ts';
import type { InstallHooks, InstallPaths } from '../../src/shell/installer.ts';

const [pathsJson, step] = process.argv.slice(2);

if (pathsJson !== undefined && (step === 'afterCopy' || step === 'afterSwitch')) {
  const paths = JSON.parse(pathsJson) as InstallPaths;
  const die = (): void => void process.kill(process.pid, 'SIGKILL');
  const hooks: InstallHooks = step === 'afterCopy' ? { afterCopy: die } : { afterSwitch: die };
  const wordlist = parseWordlist(readFileSync(new URL('../../src/data/wordlist.txt', import.meta.url), 'utf8'));
  await runInstaller({ paths, units: { restart: () => Promise.resolve(), healthCheck: () => Promise.resolve(true) }, clock: systemClock, wordlist, domain: undefined, hooks });
}
