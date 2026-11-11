// KBOX-6: reads from a directory another user can change at any moment, trusting no path, only descriptors it holds. Every
// entry is opened relative to the held descriptor of its parent (Node has no openat; `/proc/self/fd/<n>/<name>` resolves
// through the held descriptor) with O_NOFOLLOW|O_NONBLOCK, so a symlink is refused at the open and a FIFO does not block
// it; the descriptor is then fstat'ed and only a directory or a regular file with one link is taken. A file is read
// through its descriptor, at most its fstat size plus one byte, so a file that grows is caught. Removal walks the same way
// and never follows a link.
import { closeSync, constants, fstatSync, openSync, readSync, readdirSync, rmdirSync, unlinkSync } from 'node:fs';
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

/** One directory being emptied: its descriptor, its name in the directory below it on the stack, and what is left in it. */
interface Emptying {
  readonly parent: number;
  readonly name: Uint8Array | string;
  readonly fd: number;
  left: Buffer[];
  readonly tries: number;
}

/**
 * Removes one entry of a held directory whatever its type, never following a link: a link, FIFO or file is unlinked (the
 * link itself, not its target); a directory is opened O_NOFOLLOW and emptied through its own descriptor, then removed. The
 * walk keeps its own stack of held descriptors, so the depth of a planted tree is bounded by descriptors, not by the call
 * stack. If an entry keeps changing type under it, it gives up after a few tries and throws.
 */
export function removeAt(dirFd: number, name: Uint8Array | string): void {
  const stack: Emptying[] = [];
  /** Unlinks the entry, or puts it on the stack to be emptied; the stack owns every descriptor it holds. */
  const enter = (parent: number, entry: Uint8Array | string, tries: number): void => {
    const opened = unlinkOrOpen(parent, entry);
    if (opened === 'gone') return;
    const frame: Emptying = { parent, name: entry, fd: opened.fd, left: [], tries };
    stack.push(frame);
    frame.left = listAt(opened.fd);
  };
  try {
    enter(dirFd, name, 0);
    for (let top = stack.at(-1); top !== undefined; top = stack.at(-1)) {
      const child = top.left.pop();
      if (child !== undefined) {
        enter(top.fd, child, 0);
        continue;
      }
      const removed = tryOs(() => rmdirSync(at(top.parent, top.name)), ['ENOENT', 'ENOTEMPTY', 'ENOTDIR']);
      stack.pop();
      closeSync(top.fd);
      if (!isOs(removed) || removed.os === 'ENOENT') continue;
      // Something was added, or the entry was swapped, meanwhile: look again from its parent.
      if (top.tries + 1 >= REMOVE_TRIES) throw changing();
      enter(top.parent, top.name, top.tries + 1);
    }
  } finally {
    for (const frame of stack) closeSync(frame.fd);
  }
}
