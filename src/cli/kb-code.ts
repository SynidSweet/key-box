// kb-code (KBOX-20, KBOX-49): the root oneshot that makes the codes. `recovery` runs at every host boot and writes a fresh
// recovery code unless this boot already has one; `setup` runs once from the bootstrap while trust.json does not exist.
// The words go to the console device only. stdout carries a fixed status word, never a code.
import { existsSync, readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { parseWordlist } from '../pure/codes.ts';
import { decodeJsonBody, parseObject, text } from '../pure/schemas.ts';
import { systemClock } from '../shell/clock.ts';
import { consoleSink, createCodeRoot, readBootId } from '../shell/console.ts';
import { systemRandom } from '../shell/random.ts';

interface Config {
  readonly mode: 'setup' | 'recovery';
  readonly codesDir: string;
  readonly bootIdFile: string;
  readonly consoleDevice: string;
  readonly trustFile: string;
}

const absolute = (value: string | undefined, fallback: string): string => {
  const path = value ?? fallback;
  if (!isAbsolute(path)) throw new RangeError('kb-code paths are absolute');
  return path;
};

function readConfig(env: NodeJS.ProcessEnv, argv: readonly string[]): Config {
  const mode = argv[2];
  if (mode !== 'setup' && mode !== 'recovery') throw new RangeError('kb-code takes one argument: setup or recovery');
  const runtime = decodeJsonBody(readFileSync(absolute(env['KB_RUNTIME_CONFIG'], '/opt/keybox/current/deploy/runtime.config.json')));
  // The file is shared with other parts (KBOX-21's link speed); kb-code reads its one member and checks its shape.
  const member = runtime.ok && typeof runtime.value === 'object' && runtime.value !== null ? (runtime.value as Record<string, unknown>)['console_device'] : undefined;
  const parsed = parseObject({ console_device: text(/^\/[A-Za-z0-9/_.-]{1,128}$/) }, { console_device: member });
  if (!parsed.ok) throw new RangeError('runtime.config.json does not name a console_device');
  return {
    mode,
    codesDir: absolute(env['KB_CODES_DIR'], '/etc/keybox/codes'),
    bootIdFile: absolute(env['KB_BOOT_ID_FILE'], '/proc/sys/kernel/random/boot_id'),
    consoleDevice: parsed.value.console_device,
    trustFile: absolute(env['KB_TRUST_FILE'], '/etc/keybox/trust.json'),
  };
}

function main(): string {
  const config = readConfig(process.env, process.argv);
  const wordlist = parseWordlist(readFileSync(new URL('../data/wordlist.txt', import.meta.url), 'utf8'));
  const codes = createCodeRoot({ dir: config.codesDir, sink: consoleSink(config.consoleDevice), random: systemRandom, clock: systemClock, wordlist });
  return config.mode === 'setup' ? codes.writeSetupCode(existsSync(config.trustFile)) : codes.writeRecoveryCode(readBootId(config.bootIdFile));
}

process.stdout.write(`kb-code: ${main()}\n`);
