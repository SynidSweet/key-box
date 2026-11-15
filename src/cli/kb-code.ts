// kb-code (KBOX-20, KBOX-49, KBOX-66): the root oneshot that makes the codes. `boot` runs at every host boot: with trust.json it does
// what `recovery` does (a fresh recovery code unless this boot already has one), without it what `setup` does (a fresh setup code
// whose hash replaces the kept one, so an earlier code is dead). `setup` also runs once from the bootstrap while trust.json does
// not exist. The words and the box address (text and QR code) go to the console device only; stdout carries a fixed status word,
// never a code. With no usable KB_DOMAIN no code is made.
import { existsSync, readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { DOMAIN_NAME } from '../pure/actions.ts';
import { pagesOrigin } from '../pure/box-origins.ts';
import { parseWordlist } from '../pure/codes.ts';
import { renderQr } from '../pure/qr.ts';
import { decodeJsonBody, parseObject, text } from '../pure/schemas.ts';
import { systemClock } from '../shell/clock.ts';
import { consoleSink, createCodeRoot, readBootId } from '../shell/console.ts';
import { systemRandom } from '../shell/random.ts';

interface Config {
  readonly mode: 'setup' | 'recovery' | 'boot';
  /** KB_DOMAIN, or undefined when it is missing or not a lower-case domain name. */
  readonly host: string | undefined;
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
  if (mode !== 'setup' && mode !== 'recovery' && mode !== 'boot') throw new RangeError('kb-code takes one argument: setup, recovery or boot');
  const runtime = decodeJsonBody(readFileSync(absolute(env['KB_RUNTIME_CONFIG'], '/opt/keybox/current/deploy/runtime.config.json')));
  // The file is shared with other parts (KBOX-21's link speed); kb-code reads its one member and checks its shape.
  const member = runtime.ok && typeof runtime.value === 'object' && runtime.value !== null ? (runtime.value as Record<string, unknown>)['console_device'] : undefined;
  const parsed = parseObject({ console_device: text(/^\/[A-Za-z0-9/_.-]{1,128}$/) }, { console_device: member });
  if (!parsed.ok) throw new RangeError('runtime.config.json does not name a console_device');
  return {
    mode,
    host: env['KB_DOMAIN'] !== undefined && DOMAIN_NAME.test(env['KB_DOMAIN']) ? env['KB_DOMAIN'] : undefined,
    codesDir: absolute(env['KB_CODES_DIR'], '/etc/keybox/codes'),
    bootIdFile: absolute(env['KB_BOOT_ID_FILE'], '/proc/sys/kernel/random/boot_id'),
    consoleDevice: parsed.value.console_device,
    trustFile: absolute(env['KB_TRUST_FILE'], '/etc/keybox/trust.json'),
  };
}

const NO_NAME = 'Key box: this box has no name configured. Write the card again.\n';

/** Which code a run makes: boot is recovery with trust.json and setup without it. */
const kindOf = (mode: Config['mode'], trustExists: boolean): 'setup' | 'recovery' => (mode === 'boot' ? (trustExists ? 'recovery' : 'setup') : mode);

function main(): string {
  const config = readConfig(process.env, process.argv);
  const sink = consoleSink(config.consoleDevice);
  if (config.host === undefined) {
    sink(NO_NAME);
    return 'no_name';
  }
  const wordlist = parseWordlist(readFileSync(new URL('../data/wordlist.txt', import.meta.url), 'utf8'));
  const codes = createCodeRoot({ dir: config.codesDir, sink, random: systemRandom, clock: systemClock, wordlist });
  const trustExists = existsSync(config.trustFile);
  const kind = kindOf(config.mode, trustExists);
  const status = kind === 'setup' ? codes.writeSetupCode(trustExists) : codes.writeRecoveryCode(readBootId(config.bootIdFile));
  // The address is no secret: it goes right under a new code, as text and as the QR code that holds exactly that text.
  if (status === 'written') sink(`\n${renderQr(`${pagesOrigin(config.host)}/${kind === 'setup' ? 'setup' : 'recover'}`)}`);
  return status;
}

process.stdout.write(`kb-code: ${main()}\n`);
