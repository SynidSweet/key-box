// What a leak of a vault value looks like when it is not a whole copy: a prefix or suffix of 8 or more bytes, the length next to
// the key's name, and a SHA-256 digest. canary() finds whole copies; this finds the pieces (KBOX-2, KBOX-5, KBOX-19).
import { createHash } from 'node:crypto';
import type { Surface } from './canary.ts';

const PIECE_BYTES = 8;
/** How far from the key's name a decimal length still counts as "next to" it. */
const NEAR_CHARS = 24;

export interface DerivedHit {
  readonly surface: string;
  readonly form: string;
}

function encodings(raw: Buffer): [string, string][] {
  return [
    ['raw', raw.toString('latin1')],
    ['hex', raw.toString('hex')],
    ['hex upper', raw.toString('hex').toUpperCase()],
    ['base64', raw.toString('base64')],
    ['base64 unpadded', raw.toString('base64').replace(/=+$/, '')],
    ['base64 url', raw.toString('base64url')],
  ];
}

/** Every needle: the named form and its text. */
function needlesFor(value: Uint8Array): [string, string][] {
  const raw = Buffer.from(value);
  const whole = raw.toString('base64url');
  const out: [string, string][] = [];
  for (const [piece, bytes] of [['prefix', raw.subarray(0, PIECE_BYTES)], ['suffix', raw.subarray(raw.length - PIECE_BYTES)]] as const) {
    for (const [name, text] of encodings(bytes)) out.push([`${piece} of ${PIECE_BYTES} bytes, ${name}`, text]);
  }
  out.push(['prefix of the base64url text', whole.slice(0, 12)], ['suffix of the base64url text', whole.slice(-12)]);
  for (const [label, input] of [['value', raw], ['base64url text', Buffer.from(whole)]] as const) {
    const digest = createHash('sha256').update(input).digest();
    for (const [name, text] of encodings(digest)) if (name !== 'raw') out.push([`sha256 of the ${label}, ${name}`, text]);
  }
  return out;
}

/** The decimal length within NEAR_CHARS characters of the key's name, in either order. */
function lengthNearName(haystack: string, name: string, length: number): boolean {
  const digits = new RegExp(`(?<![0-9])${length}(?![0-9])`);
  for (let at = haystack.indexOf(name); at !== -1; at = haystack.indexOf(name, at + 1)) {
    const around = haystack.slice(Math.max(0, at - NEAR_CHARS), at) + ' ' + haystack.slice(at + name.length, at + name.length + NEAR_CHARS);
    if (digits.test(around)) return true;
  }
  return false;
}

/** Surfaces and forms that hold a piece, a length beside `name`, or a digest of `value`. Never carries the value itself. */
export function findDerived(value: Uint8Array, name: string, surfaces: Readonly<Record<string, Surface>>): DerivedHit[] {
  const needles = needlesFor(value);
  const hits: DerivedHit[] = [];
  for (const [surface, content] of Object.entries(surfaces)) {
    const buffer = typeof content === 'string' ? Buffer.from(content, 'utf8') : Buffer.from(content);
    const text = buffer.toString('latin1');
    for (const [form, needle] of needles) if (buffer.includes(Buffer.from(needle, 'latin1'))) hits.push({ surface, form });
    if (lengthNearName(text, name, value.length)) hits.push({ surface, form: `length ${value.length} next to the name` });
  }
  return hits;
}
