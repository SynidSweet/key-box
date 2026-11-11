// KBOX-15, KBOX-16, KBOX-12: what a key is. The class is computed and never lowered by a caller; admin and master keys go only to
// runtime destinations; a pasted value must fit the adapter's strict shape. Pure.
import type { Alphabet, KeyClass, KeyShape } from '../ports/types.ts';

const RANK: Readonly<Record<KeyClass, number>> = { ordinary: 0, admin: 1, master: 2 };

/** The higher of the adapter's classification and the owner's mark. */
export function classOf(adapter: KeyClass, mark: KeyClass | undefined): KeyClass {
  return mark !== undefined && RANK[mark] > RANK[adapter] ? mark : adapter;
}

/** A caller may raise a key's class or keep it; asking for a lower one is refused (`demote` is a phone action). */
export function raiseClass(current: KeyClass, requested: KeyClass): { readonly ok: true; readonly class: KeyClass } | { readonly ok: false } {
  return RANK[requested] >= RANK[current] ? { ok: true, class: requested } : { ok: false };
}

/** A destination whose own API can read the value back may hold an ordinary key only. */
export function admitDestination(klass: KeyClass, readableBy: 'api' | 'runtime'): boolean {
  return klass === 'ordinary' || readableBy === 'runtime';
}

/**
 * The key reference of a key: `<platform>/<first project>/<NAME>`, the first project cut down to what the vault names a directory
 * (decided here). Two keys with one reference are a `conflict`; the vault takes each segment as written.
 */
export function keyrefOf(platform: string, projects: readonly string[], name: string): string {
  const slug = (projects[0] ?? '').replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^[^A-Za-z0-9]+/, '').slice(0, 64);
  return `${platform}/${slug === '' || /^\.+$/.test(slug) ? 'p' : slug}/${name}`;
}

const ALPHABETS: Readonly<Record<Alphabet, RegExp>> = {
  hex: /^[0-9a-fA-F]*$/,
  base62: /^[0-9A-Za-z]*$/,
  base64: /^[0-9A-Za-z+/]*={0,2}$/,
  base64url: /^[0-9A-Za-z_-]*$/,
};

/** The characters of each alphabet, for a value the box mints; `ALPHABETS` above is the check every minted value passes (tested as a property). */
const CHARACTERS: Readonly<Record<Alphabet, string>> = {
  hex: '0123456789abcdef',
  base62: '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
  base64: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
  base64url: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
};

/**
 * KBOX-51, overlap:false (design §5.2): a value the box chooses for a platform that takes one. The prefix, then the longest core the shape
 * allows, each character drawn evenly from its alphabet (bytes at or above the largest multiple of its size are drawn again). `draw` is the
 * Random port's `bytes`.
 */
export function mintValue(shape: KeyShape, draw: (n: number) => Uint8Array): string {
  const characters = CHARACTERS[shape.alphabet];
  const even = 256 - (256 % characters.length);
  let core = '';
  while (core.length < shape.coreLength.max) {
    for (const byte of draw(shape.coreLength.max - core.length)) {
      if (byte < even && core.length < shape.coreLength.max) core += characters.charAt(byte % characters.length);
    }
  }
  return (shape.prefix ?? '') + core;
}

/** The adapter's strict shape check: the prefix, then a core of the alphabet within the core length. Nothing is trimmed. */
export function matchesShape(shape: KeyShape, value: string): boolean {
  const prefix = shape.prefix ?? '';
  if (!value.startsWith(prefix)) return false;
  const core = value.slice(prefix.length);
  return core.length >= shape.coreLength.min && core.length <= shape.coreLength.max && ALPHABETS[shape.alphabet].test(core);
}
