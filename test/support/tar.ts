// A small ustar writer for the update tests, written from the POSIX header layout and independent of src/pure/tar.ts, so the
// parser is tested against bytes it did not make. Each entry can plant one fault (type flag, raw name bytes, a bad checksum,
// a base-256 size). Run directly, this file does nothing.

export interface TarEntrySpec {
  /** The path as text, or raw bytes for a name that is not valid UTF-8. */
  readonly name: string | Uint8Array;
  readonly body?: Uint8Array | string;
  /** Octal permission bits; 0o644 by default (0o755 for a directory). */
  readonly mode?: number;
  /** The ustar type flag; '0' for a file, '5' for a directory. */
  readonly type?: string;
  /** The ustar prefix field (a path longer than 100 bytes). */
  readonly prefix?: string;
  readonly linkname?: string;
  /** Plants a wrong checksum. */
  readonly badChecksum?: boolean;
  /** Writes the size in base-256 (GNU) instead of octal. */
  readonly base256Size?: boolean;
  /** Declares this size instead of the body's length. */
  readonly declaredSize?: number;
}

const BLOCK = 512;
const enc = new TextEncoder();
const asBytes = (v: Uint8Array | string): Uint8Array => (typeof v === 'string' ? enc.encode(v) : v);

function octal(header: Uint8Array, offset: number, width: number, value: number): void {
  const digits = value.toString(8).padStart(width - 1, '0');
  header.set(enc.encode(digits), offset);
  header[offset + width - 1] = 0;
}

function headerFor(e: TarEntrySpec, size: number): Uint8Array {
  const h = new Uint8Array(BLOCK);
  const name = asBytes(e.name);
  if (name.length > 100) throw new RangeError('the test writer takes names up to 100 bytes; use prefix');
  h.set(name, 0);
  const type = e.type ?? '0';
  octal(h, 100, 8, e.mode ?? (type === '5' ? 0o755 : 0o644));
  octal(h, 108, 8, 1000);
  octal(h, 116, 8, 1000);
  if (e.base256Size === true) {
    h[124] = 0x80;
    new DataView(h.buffer).setUint32(132, size);
  } else octal(h, 124, 12, size);
  octal(h, 136, 12, 1_700_000_000);
  h.set(enc.encode(type), 156);
  if (e.linkname !== undefined) h.set(enc.encode(e.linkname), 157);
  h.set(enc.encode('ustar\u0000'), 257);
  h.set(enc.encode('00'), 263);
  if (e.prefix !== undefined) h.set(enc.encode(e.prefix), 345);
  h.fill(0x20, 148, 156);
  let sum = 0;
  for (const b of h) sum += b;
  if (e.badChecksum === true) sum += 1;
  const digits = sum.toString(8).padStart(6, '0');
  h.set(enc.encode(digits), 148);
  h[154] = 0;
  h[155] = 0x20;
  return h;
}

/** A tar of the entries, ended by two zero blocks and padded to 10240 bytes as `git archive` does. */
export function tarOf(entries: readonly TarEntrySpec[], options: { readonly end?: boolean } = {}): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const e of entries) {
    const body = asBytes(e.body ?? '');
    parts.push(headerFor(e, e.declaredSize ?? body.length));
    const padded = new Uint8Array(Math.ceil(body.length / BLOCK) * BLOCK);
    padded.set(body);
    parts.push(padded);
  }
  if (options.end !== false) parts.push(new Uint8Array(2 * BLOCK));
  let length = parts.reduce((n, p) => n + p.length, 0);
  if (options.end !== false && length % 10240 !== 0) {
    const pad = 10240 - (length % 10240);
    parts.push(new Uint8Array(pad));
    length += pad;
  }
  const out = new Uint8Array(length);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** The pax global header `git archive` writes first: a `comment` record with the commit id. */
export function gitGlobalHeader(commit: string): TarEntrySpec {
  const record = ` comment=${commit}\n`;
  const len = record.length + String(record.length + 3).length;
  return { name: 'pax_global_header', type: 'g', body: `${len}${record}` };
}
