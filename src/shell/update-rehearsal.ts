// The first-start update rehearsal (design 3.8, M-E): what an update does to the card and to memory, done once over the running release
// before any key exists. It reads every file of the release (its `bin/` holds the pinned binaries) through the installer's own
// descriptor reads and hashes, holding the bytes as the installer does, writes them with fsync under `rehearsal.<random>` in the install
// directory, and removes that directory when it ends, pass or fail (N-L5). It never writes inside the release it reads.
import { closeSync, fsyncSync, mkdirSync, openSync, rmSync, writeSync } from 'node:fs';
import { dirname, join } from 'node:path';
import type { Clock } from '../ports/clock.ts';
import type { Random } from '../ports/random.ts';
import { fileSha256 } from '../pure/release-hash.ts';
import { closeFd, listAt, openAt, openDirectory, readThrough } from './safe-open.ts';

/** The name kb-join's debris rule removes after a power cut. */
export const REHEARSAL_PREFIX = 'rehearsal.';

export interface RehearsalDeps {
  readonly clock: Clock;
  readonly random: Random;
  readonly releaseDir: string;
  readonly installDir: string;
  /** One file written to the card and fsynced; the default makes its directories. */
  readonly writeDurable?: (path: string, bytes: Uint8Array) => void;
}

export interface CopyMeasure {
  readonly copy_ms: number;
  readonly bytes: number;
}

interface Held {
  readonly rel: string;
  readonly bytes: Uint8Array;
  readonly sha256: string;
}

export function writeDurableFile(path: string, bytes: Uint8Array): void {
  mkdirSync(dirname(path), { recursive: true });
  const fd = openSync(path, 'wx', 0o600);
  try {
    let done = 0;
    while (done < bytes.length) done += writeSync(fd, bytes, done);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/** Every regular file under the release, read and hashed through held descriptors; anything else (a link, a FIFO) is refused. */
function readRelease(releaseDir: string): Held[] {
  const held: Held[] = [];
  const walk = (dirFd: number, prefix: string): void => {
    for (const name of listAt(dirFd)) {
      const rel = prefix === '' ? name.toString('utf8') : `${prefix}/${name.toString('utf8')}`;
      const opened = openAt(dirFd, name);
      if (opened.kind === 'refused') throw new Error(`the rehearsal refused ${rel}: not a regular file or directory`);
      try {
        if (opened.kind === 'dir') walk(opened.fd, rel);
        else {
          const read = readThrough(opened.fd, opened.size, Number.POSITIVE_INFINITY);
          if (!read.ok) throw new Error(`the rehearsal could not read ${rel} whole`);
          held.push({ rel, bytes: read.bytes, sha256: fileSha256(read.bytes) });
        }
      } finally {
        closeFd(opened.fd);
      }
    }
  };
  const top = openDirectory(releaseDir);
  try {
    walk(top, '');
  } finally {
    closeFd(top);
  }
  return held;
}

/** Reads and hashes the release, writes it under a fresh `rehearsal.<random>`, removes that directory whatever happens, and times it. */
export function rehearseCopy(deps: RehearsalDeps): CopyMeasure {
  const write = deps.writeDurable ?? writeDurableFile;
  const dir = join(deps.installDir, `${REHEARSAL_PREFIX}${Buffer.from(deps.random.bytes(6)).toString('hex')}`);
  const started = deps.clock.now();
  try {
    const held = readRelease(deps.releaseDir);
    for (const file of held) write(join(dir, file.rel), file.bytes);
    return { copy_ms: deps.clock.now() - started, bytes: held.reduce((n, f) => n + f.bytes.length, 0) };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
