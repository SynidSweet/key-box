// KBOX-4: the vault on disk, one file per generation: <root>/<ref>/<gen>, mode 0600 in 0700 directories.
import { chmodSync, closeSync, existsSync, fchmodSync, fstatSync, fsyncSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, rmSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { VaultError, osErrorCode } from '../pure/errors.ts';
import { makeLent } from '../pure/lent.ts';
import type { KeyRef, Lent } from '../ports/types.ts';
import type { Vault } from '../ports/vault.ts';

/** The one filesystem step a test replaces to simulate a crash between write and rename. */
export interface VaultFsOps {
  rename(from: string, to: string): void;
}

const SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
let tempCounter = 0;

function segmentsOf(ref: KeyRef, gen: number): string[] {
  const segments = ref.split('/');
  if (segments.length > 8 || !segments.every((s) => SEGMENT.test(s))) throw new VaultError('bad_ref');
  if (!Number.isSafeInteger(gen) || gen < 1) throw new VaultError('bad_ref');
  return segments;
}

function ensureDir(path: string): void {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  chmodSync(path, 0o700);
}

function writeAll(fd: number, bytes: Uint8Array): void {
  let done = 0;
  while (done < bytes.length) done += writeSync(fd, bytes, done);
}

/** Cleanup after a failed write; its own failure must not replace the fixed error, so it reports as a result. */
function tryRemove(path: string): boolean {
  try {
    rmSync(path, { force: true });
    return true;
  } catch {
    return false;
  }
}

function syncDirectory(dir: string): void {
  const fd = openSync(dir, 'r');
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

export function createFileVault(root: string, ops: VaultFsOps = { rename: renameSync }): Vault {
  const place = (ref: KeyRef, gen: number): { dir: string; file: string; dirs: string[] } => {
    const segments = segmentsOf(ref, gen);
    const dirs = segments.map((_, i) => join(root, ...segments.slice(0, i + 1)));
    const dir = dirs[dirs.length - 1] ?? root;
    return { dir, file: join(dir, String(gen)), dirs };
  };

  return {
    put(ref: KeyRef, gen: number, v: Uint8Array): void {
      const { dir, file, dirs } = place(ref, gen);
      const temp = join(dir, `.${gen}.tmp-${process.pid}-${tempCounter++}`);
      try {
        for (const d of [root, ...dirs]) ensureDir(d);
        rmSync(temp, { force: true });
        const fd = openSync(temp, 'wx', 0o600);
        try {
          fchmodSync(fd, 0o600);
          writeAll(fd, v);
          fsyncSync(fd);
        } finally {
          closeSync(fd);
        }
        ops.rename(temp, file);
        syncDirectory(dir);
      } catch (error) {
        tryRemove(temp);
        throw new VaultError('write_failed', osErrorCode(error));
      }
    },

    lend(ref: KeyRef, gen: number): Lent {
      const { file } = place(ref, gen);
      if (!existsSync(file)) throw new VaultError('unknown_key');
      return makeLent(`${ref}:${gen}`, () => {
        try {
          return readFileSync(file);
        } catch (error) {
          throw new VaultError('read_failed', osErrorCode(error));
        }
      });
    },

    retire(ref: KeyRef, gen: number): void {
      const { file } = place(ref, gen);
      try {
        rmSync(file, { force: true });
      } catch (error) {
        throw new VaultError('write_failed', osErrorCode(error));
      }
    },
  };
}

const ORPHAN_TEMP = /^\.[0-9]+\.tmp-[0-9]+-[0-9]+$/;

function zeroFillAndUnlink(path: string): void {
  const fd = openSync(path, 'r+');
  try {
    writeAll(fd, new Uint8Array(fstatSync(fd).size));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  rmSync(path);
}

/**
 * A hard kill between open and rename leaves `.<gen>.tmp-<pid>-<n>` holding a full copy of a value. Zero-fills each such file under the
 * vault root and unlinks it; returns the key reference each one sat under, one entry per file. Symlinks and other names are left alone.
 * A failure throws the fixed vault error: the core does not start with a copy of a value still on disk.
 */
export function sweepOrphanTemps(root: string): KeyRef[] {
  const swept: KeyRef[] = [];
  const walk = (dir: string, ref: string[]): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) walk(path, [...ref, entry.name]);
      else if (entry.isFile() && ORPHAN_TEMP.test(entry.name)) {
        zeroFillAndUnlink(path);
        swept.push(ref.join('/'));
      }
    }
  };
  try {
    if (existsSync(root)) walk(root, []);
  } catch (error) {
    throw new VaultError('write_failed', osErrorCode(error));
  }
  return swept;
}
