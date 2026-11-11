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

/** The adapter's strict shape check: the prefix, then a core of the alphabet within the core length. Nothing is trimmed. */
export function matchesShape(shape: KeyShape, value: string): boolean {
  const prefix = shape.prefix ?? '';
  if (!value.startsWith(prefix)) return false;
  const core = value.slice(prefix.length);
  return core.length >= shape.coreLength.min && core.length <= shape.coreLength.max && ALPHABETS[shape.alphabet].test(core);
}
