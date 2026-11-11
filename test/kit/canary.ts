import { AssertionError } from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { inspect } from 'node:util';

export type Surface = string | Uint8Array;

export interface Hit {
  readonly surface: string;
  readonly form: string;
}

interface Needle {
  readonly form: string;
  readonly bytes: Buffer;
}

function needlesFor(raw: Buffer): Needle[] {
  const latin1 = raw.toString('latin1');
  const hex = raw.toString('hex');
  const percent = (upper: boolean): string =>
    [...raw].map((b) => `%${upper ? b.toString(16).toUpperCase().padStart(2, '0') : b.toString(16).padStart(2, '0')}`).join('');
  const escaped = (upper: boolean): string =>
    [...raw].map((b) => `\\u${upper ? b.toString(16).toUpperCase().padStart(4, '0') : b.toString(16).padStart(4, '0')}`).join('');
  const text: [string, string][] = [
    ['raw as utf-8 text', latin1],
    ['base64 std', raw.toString('base64')],
    ['base64 std unpadded', raw.toString('base64').replace(/=+$/, '')],
    ['base64 url', raw.toString('base64url')],
    ['base64 url padded', raw.toString('base64url') + '='.repeat((4 - (raw.length % 4)) % 4)],
    ['hex', hex],
    ['hex upper', hex.toUpperCase()],
    ['percent', percent(false)],
    ['percent upper', percent(true)],
    ['json-escaped', JSON.stringify(latin1).slice(1, -1)],
    ['u-escaped', escaped(false)],
    ['u-escaped upper', escaped(true)],
  ];
  return [{ form: 'raw bytes', bytes: raw }, ...text.map(([form, s]): Needle => ({ form, bytes: Buffer.from(s, 'utf8') }))];
}

/** Fresh random bytes to plant in a request, and a search for them in every place they must not reach. */
export interface Canary {
  readonly bytes: Uint8Array;
  /** Every surface and form that holds a copy. */
  findIn(surfaces: Readonly<Record<string, Surface>>): Hit[];
  /** Throws naming the surfaces and forms that hold a copy; never prints the bytes. */
  assertAbsent(surfaces: Readonly<Record<string, Surface>>): void;
}

export function canary(length = 24): Canary {
  const bytes = randomBytes(length);
  const needles = needlesFor(bytes);
  const findIn = (surfaces: Readonly<Record<string, Surface>>): Hit[] => {
    const hits: Hit[] = [];
    for (const [surface, value] of Object.entries(surfaces)) {
      const haystack = typeof value === 'string' ? Buffer.from(value, 'utf8') : Buffer.from(value);
      for (const needle of needles) if (haystack.includes(needle.bytes)) hits.push({ surface, form: needle.form });
    }
    return hits;
  };
  const assertAbsent = (surfaces: Readonly<Record<string, Surface>>): void => {
    const hits = findIn(surfaces);
    if (hits.length === 0) return;
    const where = [...new Set(hits.map((h) => h.surface))];
    const message = `canary found in ${where.join(', ')} as ${hits.map((h) => `${h.surface}: ${h.form}`).join('; ')}`;
    throw new AssertionError({ message });
  };
  const handle: Canary = { bytes, findIn, assertAbsent };
  Object.defineProperty(handle, 'toJSON', { value: () => '[canary]' });
  Object.defineProperty(handle, inspect.custom, { value: () => '[canary]' });
  return handle;
}
