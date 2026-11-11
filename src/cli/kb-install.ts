// kb-install (KBOX-6): the root oneshot started by kb-install.path whenever a `*.request` appears in core's staging. It runs
// from the RUNNING release: systemd starts /opt/keybox/current/bin/node on /opt/keybox/current/src/cli/kb-install.ts, Node
// resolves the main module's real path once, and every module below is a static import loaded before the first step, so a
// rollback after the switch never loads code from the new release. stdout carries a count, never a request's content.
import { readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { parseWordlist } from '../pure/codes.ts';
import { systemClock, systemScheduler } from '../shell/clock.ts';
import { runInstaller } from '../shell/installer.ts';
import type { InstallPaths } from '../shell/installer.ts';
import { systemdUnits } from '../shell/systemd.ts';

const absolute = (value: string | undefined, fallback: string): string => {
  const path = value ?? fallback;
  if (!isAbsolute(path)) throw new RangeError('kb-install paths are absolute');
  return path;
};

function readPaths(env: NodeJS.ProcessEnv): InstallPaths {
  return {
    staging: absolute(env['KB_STAGING_DIR'], '/var/lib/keybox/staging'),
    releases: absolute(env['KB_RELEASES_DIR'], '/opt/keybox/releases'),
    current: absolute(env['KB_CURRENT'], '/opt/keybox/current'),
    trustFile: absolute(env['KB_TRUST_FILE'], '/etc/keybox/trust.json'),
    codesDir: absolute(env['KB_CODES_DIR'], '/etc/keybox/codes'),
    results: absolute(env['KB_INSTALL_RESULTS'], '/var/lib/keybox-install'),
    bootIdFile: absolute(env['KB_BOOT_ID_FILE'], '/proc/sys/kernel/random/boot_id'),
  };
}

async function main(): Promise<number> {
  const env = process.env;
  const paths = readPaths(env);
  const wordlist = parseWordlist(readFileSync(new URL('../data/wordlist.txt', import.meta.url), 'utf8'));
  const units = systemdUnits({
    systemctl: absolute(env['KB_SYSTEMCTL'], '/usr/bin/systemctl'),
    units: ['keybox.service', 'keyrelay.service', 'caddy.service'],
    healthSockets: [absolute(env['KB_CORE_SOCKET'], '/run/keybox/http.sock'), absolute(env['KB_RELAY_SOCKET'], '/run/keyrelay/http.sock')],
    clock: systemClock,
    wait: (ms) => new Promise<void>((resolve) => void systemScheduler.after(ms, resolve)),
  });
  const answered = await runInstaller({ paths, units, clock: systemClock, wordlist, journal: (code) => void process.stderr.write(`kb-install: ${code}\n`) });
  process.stdout.write(`kb-install: ${answered.length} answered\n`);
  return 0;
}

// A refusal is a decided outcome written as a result (exit 0); only a run that could not start or read staging fails.
process.exitCode = await main();
