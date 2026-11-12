// KBOX-37, KBOX-57: what a key's scope items say for Supabase, and where a key is. The items are plain words: `secret` or `publishable` (the type
// of a project API key) and `access-token` (the personal access token, the master). The project is the key's one stored location, never a scope
// item: a `project:` item is refused here (and at proposal, `location_in_scope`), so no second source can name the host a key is made for or
// relayed to.
import type { KeyClass, KeyLocation, Scope } from '../../ports/types.ts';
import { SupabaseError } from './errors.ts';
import { PROJECT_REF } from './shape.ts';

export type KeyType = 'secret' | 'publishable';

/** The scope item of the master: a personal access token (KBOX-37), pasted, never made by the box. */
export const ACCESS_TOKEN_ITEM = 'access-token';

const KEY_TYPES: readonly string[] = ['secret', 'publishable'] satisfies readonly KeyType[];

function itemsOf(scope: Scope): readonly string[] {
  const items = scope['items'];
  return items === undefined ? [] : typeof items === 'string' ? [items] : items;
}

const typeOfItems = (items: readonly string[]): KeyType => (items.includes('publishable') && !items.includes('secret') ? 'publishable' : 'secret');

/**
 * KBOX-37, KBOX-58: whether a key is the personal access token: its scope items include `access-token`, whatever else they say. One home for the
 * class (`classify`), the master verifier's reach (`appliesTo`) and the token's shape (`shapeFor`).
 */
export const isAccessToken = (scope: Scope): boolean => itemsOf(scope).includes(ACCESS_TOKEN_ITEM);

/**
 * KBOX-37: `access-token` is master whatever else is asked; otherwise `secret` is admin and the default, and a publishable key is ordinary only
 * when it says so and does not also say `secret` (a class is never lowered by a doubt, KBOX-16). The location does not take part.
 */
export function classify(scope: Scope, _at: KeyLocation): KeyClass {
  if (isAccessToken(scope)) return 'master';
  return typeOfItems(itemsOf(scope)) === 'secret' ? 'admin' : 'ordinary';
}

/**
 * The type of key an issue makes. Only the two type words are taken: a `project:` item (placement is the stored location), the master item (the
 * box never makes a personal access token) and any other word are `bad_scope`, before any call.
 */
export function issueTypeOf(scope: Scope): KeyType {
  const items = itemsOf(scope);
  if (!items.every((i) => KEY_TYPES.includes(i))) throw new SupabaseError('bad_scope');
  return typeOfItems(items);
}

/** The project a call is for: the key's stored location only (KBOX-57). None, or a value that is not a ref, is `bad_project`, before any call. */
export function projectAt(at: KeyLocation): string {
  if (at.project === undefined || !PROJECT_REF.test(at.project)) throw new SupabaseError('bad_project');
  return at.project;
}
