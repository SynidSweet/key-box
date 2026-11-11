// KBOX-20, KBOX-49, KBOX-6: the root side of the setup and recovery codes. kb-code (root, at every host boot) and the
// bootstrap make them and write the words to the console sink only; root keeps only each code's hash in a root-only
// directory (0700, files 0600); kb-install checks a typed code against it. Core never runs this code and never sees a hash.
import { chmodSync, closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, writeSync, constants } from 'node:fs';
import { join } from 'node:path';
import type { Clock } from '../ports/clock.ts';
import type { Random } from '../ports/random.ts';
import { CODE_BYTES, codeFromBytes, codeHash, codeMatches } from '../pure/codes.ts';
import { decodeJsonBody, int, parseObject, text } from '../pure/schemas.ts';

/** A recovery code is valid this long after it was written (KBOX-20). */
export const RECOVERY_VALID_MS = 30 * 60_000;

export type CodeKind = 'setup' | 'recovery';
export type CodeCheck = { readonly ok: true } | { readonly ok: false; readonly code: 'no_code' | 'wrong_code' | 'expired' | 'stale_boot' | 'trust_exists' };

export interface CodeRootDeps {
  /** `/etc/keybox/codes`. */
  readonly dir: string;
  /** Writes one line to the console device. Never stdout, never the journal. */
  readonly sink: (text: string) => void;
  readonly random: Random;
  readonly clock: Clock;
  readonly wordlist: readonly string[];
}

export interface CodeRoot {
  /** At bootstrap: a one-time setup code, only while trust.json does not exist. */
  writeSetupCode(trustExists: boolean): 'written' | 'trust_exists';
  /** At a host boot: a fresh recovery code, unless one was already written for this boot. */
  writeRecoveryCode(bootId: string): 'written' | 'same_boot';
  /** Checks a typed code. A wrong code leaves the kept hash as it is. */
  check(kind: CodeKind, typed: string, context: { readonly bootId: string; readonly trustExists: boolean }): CodeCheck;
  /** Deletes the kept hash once the change it allowed was made: a code works once. */
  consume(kind: CodeKind): void;
}

const HEX64 = /^[0-9a-f]{64}$/;
const BOOT_ID = /^[0-9A-Za-z-]{1,64}$/;
const KEPT = {
  setup: { hash: text(HEX64), written_at: int() },
  recovery: { hash: text(HEX64), boot_id: text(BOOT_ID), written_at: int() },
} as const;

export function createCodeRoot(deps: CodeRootDeps): CodeRoot {
  const file = (kind: CodeKind): string => join(deps.dir, `${kind}.hash`);

  const keep = (kind: CodeKind, record: Readonly<Record<string, string | number>>): void => {
    mkdirSync(deps.dir, { recursive: true, mode: 0o700 });
    chmodSync(deps.dir, 0o700); // a directory that already existed keeps its old mode otherwise
    const temp = `${file(kind)}.tmp`;
    rmSync(temp, { force: true });
    const fd = openSync(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try {
      writeSync(fd, JSON.stringify(record));
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(temp, file(kind));
  };

  const read = (kind: CodeKind): { hash: string; written_at: number; boot_id?: string } | undefined => {
    if (!existsSync(file(kind))) return undefined;
    const raw = decodeJsonBody(readFileSync(file(kind)));
    const parsed = raw.ok ? parseObject(KEPT[kind], raw.value) : raw;
    return parsed.ok ? parsed.value : undefined;
  };

  const issue = (kind: CodeKind, extra: Readonly<Record<string, string>>): void => {
    const code = codeFromBytes(deps.random.bytes(CODE_BYTES), deps.wordlist);
    keep(kind, { hash: codeHash(code), ...extra, written_at: deps.clock.now() });
    deps.sink(`key box ${kind} code: ${code}\n`);
  };

  return {
    writeSetupCode(trustExists) {
      if (trustExists) return 'trust_exists';
      issue('setup', {});
      return 'written';
    },

    writeRecoveryCode(bootId) {
      if (!BOOT_ID.test(bootId)) throw new RangeError('a boot id is a short hyphenated hex text');
      if (read('recovery')?.boot_id === bootId) return 'same_boot';
      issue('recovery', { boot_id: bootId });
      return 'written';
    },

    check(kind, typed, context) {
      if (kind === 'setup' && context.trustExists) return { ok: false, code: 'trust_exists' };
      const kept = read(kind);
      if (kept === undefined) return { ok: false, code: 'no_code' };
      if (!codeMatches(typed, kept.hash, deps.wordlist)) return { ok: false, code: 'wrong_code' };
      if (kind === 'recovery') {
        if (kept.boot_id !== context.bootId) return { ok: false, code: 'stale_boot' };
        if (deps.clock.now() - kept.written_at > RECOVERY_VALID_MS) return { ok: false, code: 'expired' };
      }
      return { ok: true };
    },

    consume(kind) {
      rmSync(file(kind), { force: true });
    },
  };
}

/** The console device, written directly: opened for writing only, never as a controlling terminal. */
export function consoleSink(devicePath: string): (text: string) => void {
  return (line: string): void => {
    const fd = openSync(devicePath, constants.O_WRONLY | constants.O_NOCTTY | constants.O_APPEND);
    try {
      writeSync(fd, line);
    } finally {
      closeSync(fd);
    }
  };
}

/** `/proc/sys/kernel/random/boot_id`: changes at every host boot and only then. */
export function readBootId(path: string): string {
  const id = readFileSync(path, 'utf8').trim();
  if (!BOOT_ID.test(id)) throw new RangeError('the boot id file does not hold a boot id');
  return id;
}
