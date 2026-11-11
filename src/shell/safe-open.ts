// KBOX-6: reads from a directory another user can change at any moment, trusting no path, only descriptors it holds. Every
// entry is opened relative to the held descriptor of its parent (Node has no openat; `/proc/self/fd/<n>/<name>` resolves
// through the held descriptor) with O_NOFOLLOW|O_NONBLOCK, so a symlink is refused at the open and a FIFO does not block
// it; the descriptor is then fstat'ed and only a directory or a regular file with one link is taken. A file is read
// through its descriptor, at most its fstat size plus one byte, so a file that grows is caught. Removal walks the same way
// and never follows a link.
import { closeSync, constants, fstatSync, mkdirSync, openSync, readSync, readdirSync, renameSync, rmdirSync, unlinkSync } from 'node:fs';
import { osErrorCode } from '../pure/errors.ts';

export type Opened =
  | { readonly kind: 'file'; readonly fd: number; readonly size: number; readonly executable: boolean }
  | { readonly kind: 'dir'; readonly fd: number }
  | { readonly kind: 'refused' };

/** The path of `name` inside the directory held open as `dirFd`. Names are bytes: they need not be UTF-8. */
export const at = (dirFd: number, name: Uint8Array | string): Buffer => Buffer.concat([Buffer.from(`/proc/self/fd/${dirFd}/`), Buffer.from(name)]);

/** Runs `fn`; an OS error whose code is in `benign` comes back as `{os: code}`, every other error is thrown. */
function tryOs<T>(fn: () => T, benign: readonly string[]): T | { readonly os: string } {
  try {
    return fn();
  } catch (error) {
    const code = osErrorCode(error);
    if (code !== undefined && benign.includes(code)) return { os: code };
    throw error;
  }
}
const isOs = (v: unknown): v is { readonly os: string } => typeof v === 'object' && v !== null && 'os' in v;

/** Opens a directory path whose last component must not be a link. */
export function openDirectory(path: string | Buffer): number {
  return openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
}

/** The names in a held directory, as bytes. */
export function listAt(dirFd: number): Buffer[] {
  return readdirSync(`/proc/self/fd/${dirFd}`, { encoding: 'buffer' }).sort(Buffer.compare);
}

/**
 * Opens one entry of a held directory. A link (ELOOP), a socket (ENXIO), an entry that vanished, and anything fstat does not
 * call a directory or a regular file with exactly one link (FIFO, device, hard link) is `refused`, its descriptor closed.
 */
export function openAt(dirFd: number, name: Uint8Array | string): Opened {
  const fd = tryOs(() => openSync(at(dirFd, name), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK), ['ELOOP', 'ENXIO', 'ENOENT', 'ENOTDIR', 'EACCES']);
  if (isOs(fd)) return { kind: 'refused' };
  const st = fstatSync(fd);
  if (st.isDirectory()) return { kind: 'dir', fd };
  if (st.isFile() && st.nlink === 1) return { kind: 'file', fd, size: st.size, executable: (st.mode & 0o100) !== 0 };
  closeSync(fd);
  return { kind: 'refused' };
}

export type ReadThrough = { readonly ok: true; readonly bytes: Uint8Array } | { readonly ok: false };

/** Reads at most `size + 1` bytes through the descriptor; anything but exactly `size` bytes, or a size over `limit`, fails. */
export function readThrough(fd: number, size: number, limit: number): ReadThrough {
  if (size > limit) return { ok: false };
  const buffer = Buffer.alloc(size + 1);
  let got = 0;
  for (;;) {
    const n = readSync(fd, buffer, got, buffer.length - got, null);
    if (n === 0) break;
    got += n;
    if (got === buffer.length) break;
  }
  return got === size ? { ok: true, bytes: Uint8Array.from(buffer.subarray(0, size)) } : { ok: false };
}

export function closeFd(fd: number): void {
  closeSync(fd);
}

/** How often one entry may change type under a removal before it gives up. */
const REMOVE_TRIES = 4;
const changing = (): Error => new Error('a staging entry kept changing while it was removed');

/** Unlinks `name` (a link, FIFO or file: the entry itself, never a target), or opens it as a directory to empty. */
function unlinkOrOpen(dirFd: number, name: Uint8Array | string): 'gone' | { readonly fd: number } {
  for (let attempt = 0; attempt < REMOVE_TRIES; attempt += 1) {
    const unlinked = tryOs(() => unlinkSync(at(dirFd, name)), ['ENOENT', 'EISDIR', 'EPERM']);
    if (!isOs(unlinked) || unlinked.os === 'ENOENT') return 'gone';
    const sub = tryOs(() => openDirectory(at(dirFd, name)), ['ELOOP', 'ENOTDIR', 'ENOENT']);
    if (!isOs(sub)) return { fd: sub };
    if (sub.os === 'ENOENT') return 'gone';
    // it became a link or a file meanwhile: unlink it on the next try
  }
  throw changing();
}

/** Which directory a descriptor holds: device and inode, the same for every descriptor of it. */
const identity = (fd: number): string => {
  const st = fstatSync(fd, { bigint: true });
  return `${st.dev}:${st.ino}`;
};

/** One directory being emptied: its name in its parent, which directory it is, and what is left to remove in it. */
interface Level {
  readonly name: Uint8Array | string;
  readonly identity: string;
  readonly left: Buffer[];
  readonly tries: number;
}

/**
 * Removes one entry of a held directory whatever its type, never following a link: a link, FIFO or file is unlinked (the
 * link itself, not its target); a directory is emptied bottom-up and removed. The walk holds ONE descriptor of its own,
 * the directory it is in: it opens a child and closes the parent to go down, and reopens the parent through `..` to go up,
 * checking it is the very directory it came from (an entry moved meanwhile stops the walk instead of letting it climb out).
 * So any depth needs a constant number of descriptors; what it keeps per level is a name list, not a descriptor. If an entry
 * keeps changing type under it, it gives up after a few tries and throws.
 */
export function removeAt(dirFd: number, name: Uint8Array | string): void {
  const first = unlinkOrOpen(dirFd, name);
  if (first === 'gone') return;
  const levels: Level[] = [];
  /** The walk's one descriptor: the directory `levels` ends in; undefined once the walk is back in `dirFd`. */
  let here: number | undefined = first.fd;
  const enter = (fd: number, entry: Uint8Array | string, tries: number): void => {
    here = fd;
    levels.push({ name: entry, identity: identity(fd), left: listAt(fd), tries });
  };
  const leave = (): void => {
    if (here !== undefined) closeSync(here);
    here = undefined;
  };
  try {
    enter(first.fd, name, 0);
    for (let top = levels.at(-1); top !== undefined && here !== undefined; top = levels.at(-1)) {
      const child = top.left.pop();
      if (child !== undefined) {
        const opened = unlinkOrOpen(here, child);
        if (opened === 'gone') continue;
        leave();
        enter(opened.fd, child, 0);
        continue;
      }
      // `top` is empty: back up to its parent and remove it there.
      levels.pop();
      const below = levels.at(-1);
      const parent: number = below === undefined ? dirFd : openDirectory(at(here, '..'));
      leave();
      if (below !== undefined) {
        here = parent;
        if (identity(parent) !== below.identity) throw changing();
      }
      const removed = tryOs(() => rmdirSync(at(parent, top.name)), ['ENOENT', 'ENOTEMPTY', 'ENOTDIR']);
      if (!isOs(removed) || removed.os === 'ENOENT') continue;
      // Something was added, or the entry was swapped, meanwhile: look again from its parent.
      if (top.tries + 1 >= REMOVE_TRIES) throw changing();
      const again = unlinkOrOpen(parent, top.name);
      if (again === 'gone') continue;
      leave();
      enter(again.fd, top.name, top.tries + 1);
    }
  } finally {
    leave();
  }
}

/** Where kb-install puts every staging entry it takes or refuses: a root-owned 0700 directory inside staging itself (one
 * file system, so a rename moves the entry at once), made fresh under a name core cannot guess. */
export const TRASH_PREFIX = '.kb-trash-';

export interface Trash {
  /** Moves `name` out of the held directory into the trash at once (the rename never follows a link), whatever it is. */
  discard(name: Uint8Array | string): void;
  /** Removes the trash, and any trash an earlier run that was killed left, with `removeAt`. */
  empty(): void;
}

/** A trash in the held directory `dirFd`, made on first use as `<TRASH_PREFIX><suffix>`. */
export function trashIn(dirFd: number, suffix: string): Trash {
  const name = `${TRASH_PREFIX}${suffix}`;
  let held: number | undefined;
  let count = 0;
  /** Ours: a directory owned by this process's user, 0700. Another user's entry under a trash name is never emptied. */
  const ours = (fd: number): boolean => {
    const st = fstatSync(fd);
    return st.isDirectory() && st.uid === process.geteuid?.() && (st.mode & 0o777) === 0o700;
  };
  const open = (): number => {
    if (held !== undefined) return held;
    mkdirSync(at(dirFd, name), { mode: 0o700 });
    const fd = openDirectory(at(dirFd, name));
    held = fd;
    if (!ours(fd)) throw new Error('the trash was swapped before it was opened');
    return fd;
  };
  return {
    discard(entry) {
      count += 1;
      const target = String(count);
      tryOs(() => renameSync(at(dirFd, entry), at(open(), target)), ['ENOENT']);
    },
    empty() {
      if (held !== undefined) closeSync(held);
      held = undefined;
      for (const entry of listAt(dirFd).filter((n) => n.subarray(0, TRASH_PREFIX.length).toString('latin1') === TRASH_PREFIX)) {
        const opened = openAt(dirFd, entry);
        if (opened.kind === 'refused') continue;
        const mine = opened.kind === 'dir' && ours(opened.fd);
        closeSync(opened.fd);
        if (mine) removeAt(dirFd, entry);
      }
    },
  };
}
