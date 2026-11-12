// KBOX-38: what a key's scope items mean for OpenAI, the shape of its keys, and the names the adapter derives. Pure.
import type { KeyClass, KeyLocation, KeyShape, Scope } from '../../ports/types.ts';
import { ID, OpenAiError } from './client.ts';

/** The item that names the organization admin key itself: a key of this scope is `master` and is never issued by the box (KBOX-34). */
export const ORGANIZATION_ADMIN_ITEM = 'organization:admin';

/**
 * `sk-admin-` and `sk-svcacct-` keys both fit: the prefix is `sk-` and the core (which begins `admin-` or `svcacct-`) is base64url.
 * UNVERIFIED (openai.admin-key-length, openai.svcacct-key-length): the real core lengths were never observed; the range is wide on both
 * sides (the windowed band of KBOX-18), so a wrong length can at worst move a key between tiers.
 */
export const OPENAI_SHAPE: KeyShape = { prefix: 'sk-', alphabet: 'base64url', coreLength: { min: 32, max: 256 }, random: true };

const itemsOf = (scope: Scope): readonly string[] => {
  const items = scope['items'];
  if (items === undefined) return [];
  return typeof items === 'string' ? [items] : items;
};

/** KBOX-38: project service-account keys are ordinary; the organization admin key is master. (`mark_admin` raises an ordinary key later.) The project is the key's location, not its class. */
export const classify = (scope: Scope, _at: KeyLocation): KeyClass => (itemsOf(scope).includes(ORGANIZATION_ADMIN_ITEM) ? 'master' : 'ordinary');

/**
 * The one project an issue is for: the key's stored location (KBOX-57), never a scope item. A scope with any item (a `project:` item, a master
 * scope) and a project that is absent or not an id the adapter can put in a path are `bad_scope`, before any call.
 */
export function projectOf(scope: Scope, at: KeyLocation): string {
  if (itemsOf(scope).length !== 0) throw new OpenAiError('bad_scope');
  if (at.project === undefined || !ID.test(at.project)) throw new OpenAiError('bad_scope');
  return at.project;
}

/** `kbox_<ref>_g<N>_<run8>` (KBOX-51) names the service account by its stem `kbox_<ref>`, so each rotation adds a key to the same account. */
export const accountNameOf = (intentName: string): string => {
  const stem = intentName.replace(/_g\d+_[a-z0-9]{8}$/, '');
  return stem === '' ? intentName : stem;
};

const KEY_ID = new RegExp(`^(${ID.source.slice(1, -1)})/(${ID.source.slice(1, -1)})$`);

/** The platform key id the box stores: `<project>/<key id>`, since a revoke needs both. A string that is not of this form is no key of ours. */
export const keyIdOf = (project: string, key: string): string => `${project}/${key}`;

export function parseKeyId(id: string): { readonly project: string; readonly key: string } | undefined {
  const m = KEY_ID.exec(id);
  const [, project, key] = m ?? [];
  return project === undefined || key === undefined ? undefined : { project, key };
}
