// KBOX-6: the bundle intake. A ustar archive of the tracked files at commit C plus runtime.lock, parsed by hand: regular
// files and directories only, one pax global header first (how `git archive` writes the commit id) accepted and ignored,
// every other extended header, link, device and FIFO refused, and the name and size rules of release-hash.ts applied.
// Every refusal is one fixed code; nothing of the input is quoted.
import { RELEASE_LIMITS, checkPath } from './release-hash.ts';

export type TarEntry =
  | { readonly kind: 'file'; readonly path: string; readonly executable: boolean; readonly bytes: Uint8Array }
  | { readonly kind: 'dir'; readonly path: string };

export type TarRefusal = 'truncated' | 'bad_header' | 'entry_type' | 'extended_header' | 'name' | 'duplicate' | 'too_many' | 'too_large';

export type TarParse = { readonly ok: true; readonly entries: readonly TarEntry[] } | { readonly ok: false; readonly code: TarRefusal };

const BLOCK = 512;
const MAGIC = [0x75, 0x73, 0x74, 0x61, 0x72]; // "ustar"

/** An octal field: digits, then spaces or NULs to its end. A base-256 field (high bit set) or anything else is refused. */
function octal(header: Uint8Array, offset: number, width: number): number | undefined {
  const field = header.subarray(offset, offset + width);
  let value = 0;
  let i = 0;
  while (i < field.length && field[i] === 0x20) i += 1;
  let digits = 0;
  for (; i < field.length; i += 1) {
    const b = field[i] ?? 0;
    if (b < 0x30 || b > 0x37) break;
    value = value * 8 + (b - 0x30);
    digits += 1;
  }
  for (; i < field.length; i += 1) if (field[i] !== 0x20 && field[i] !== 0) return undefined;
  return digits === 0 || !Number.isSafeInteger(value) ? undefined : value;
}

/** A NUL-terminated field. A NUL followed by more non-NUL bytes is not a name and is refused. */
function nameField(header: Uint8Array, offset: number, width: number): Uint8Array | undefined {
  const field = header.subarray(offset, offset + width);
  const end = field.indexOf(0);
  if (end === -1) return field;
  return field.subarray(end).every((b) => b === 0) ? field.subarray(0, end) : undefined;
}

const isZero = (bytes: Uint8Array): boolean => bytes.every((b) => b === 0);

function checksumOk(header: Uint8Array): boolean {
  const stored = octal(header, 148, 8);
  let sum = 0;
  for (let i = 0; i < BLOCK; i += 1) sum += i >= 148 && i < 156 ? 0x20 : (header[i] ?? 0);
  return stored === sum;
}

const refuse = (code: TarRefusal): TarParse => ({ ok: false, code });

const ancestors = (path: string): string[] => {
  const parts = path.split('/');
  return parts.slice(1).map((_, i) => parts.slice(0, i + 1).join('/'));
};

export function parseTar(input: Uint8Array): TarParse {
  const entries: TarEntry[] = [];
  const files = new Set<string>();
  const dirs = new Set<string>();
  const implied = new Set<string>();
  let total = 0;
  let at = 0;
  let first = true;
  for (;;) {
    if (at + BLOCK > input.length) return refuse('truncated');
    const header = input.subarray(at, at + BLOCK);
    if (isZero(header)) {
      // The end of the archive: everything after it is zero padding.
      return isZero(input.subarray(at)) ? { ok: true, entries } : refuse('bad_header');
    }
    if (!MAGIC.every((b, i) => header[257 + i] === b) || !checksumOk(header)) return refuse('bad_header');
    const size = octal(header, 124, 12);
    if (size === undefined) return refuse('bad_header');
    const bodyStart = at + BLOCK;
    const bodyEnd = bodyStart + size;
    if (bodyEnd > input.length) return refuse('truncated');
    at = bodyStart + Math.ceil(size / BLOCK) * BLOCK;
    const type = header[156] ?? 0;
    const wasFirst = first;
    first = false;
    if (type === 0x67 /* g */) {
      if (!wasFirst) return refuse('extended_header');
      continue;
    }
    if (type === 0x78 /* x */ || type === 0x4c /* L */ || type === 0x4b /* K */) return refuse('extended_header');
    const isFile = type === 0x30 || type === 0;
    const isDir = type === 0x35;
    if (!isFile && !isDir) return refuse('entry_type');
    if (isDir && size !== 0) return refuse('bad_header');

    const name = nameField(header, 0, 100);
    const prefix = nameField(header, 345, 155);
    if (name === undefined || prefix === undefined) return refuse('name');
    let raw = prefix.length === 0 ? name : Uint8Array.from([...prefix, 0x2f, ...name]);
    if (isDir && raw.at(-1) === 0x2f) raw = raw.subarray(0, raw.length - 1);
    const path = checkPath(raw);
    if (path === undefined) return refuse('name');

    if (files.has(path) || dirs.has(path) || (isFile && implied.has(path))) return refuse('duplicate');
    const above = ancestors(path);
    if (above.some((p) => files.has(p))) return refuse('duplicate');
    for (const p of above) implied.add(p);

    if (entries.length + 1 > RELEASE_LIMITS.entries) return refuse('too_many');
    if (isDir) {
      dirs.add(path);
      entries.push({ kind: 'dir', path });
      continue;
    }
    total += size;
    if (total > RELEASE_LIMITS.totalBytes) return refuse('too_large');
    const mode = octal(header, 100, 8);
    if (mode === undefined) return refuse('bad_header');
    files.add(path);
    entries.push({ kind: 'file', path, executable: (mode & 0o100) !== 0, bytes: input.slice(bodyStart, bodyEnd) });
  }
}
