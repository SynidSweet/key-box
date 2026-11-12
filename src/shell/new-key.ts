// KBOX-15, KBOX-57: the one place that turns an `add_key` request into the rows of a new key: the class is the highest of the adapter's
// classification without the location, the one with it, and the owner's mark; the location is the action's, checked against the entry; the
// grace default follows the destinations, the reference is `platform/project/NAME`.
import { flooredClass, keyrefOf } from '../pure/class.ts';
import type { Action } from '../pure/actions.ts';
import { ApiError } from '../pure/errors.ts';
import { checkLocation } from '../pure/location.ts';
import { defaultGraceHours } from '../pure/rotation-machine.ts';
import type { NewKey } from './orchestrator.ts';
import type { KeyClass, KeyLocation, LocationSchema, Scope } from '../ports/types.ts';
import { classifierOf } from '../pure/platform-shape.ts';
import { setterOf } from './rotation-ports.ts';
import type { PlatformSource } from './rotation-ports.ts';
import type { DestinationRow } from './rotation-store.ts';

export type AddKey = Extract<Action, { kind: 'add_key' }>;
export interface RotateKey {
  readonly kind: 'rotate_key';
  readonly keyref: string;
}
/** The two kinds a paste can settle (KBOX-12). */
export type PasteAction = AddKey | RotateKey;

/** What a key request needs of its platform: the class of a scope at a location, how a key is made, and the location fields it declares. */
export interface KeyConfig {
  readonly classify: (scope: Scope, at: KeyLocation) => KeyClass;
  readonly create: 'api' | 'paste';
  readonly location: LocationSchema | undefined;
}

/**
 * The class source and creation mode for a key's platform, or the refusal of the key's configuration: `unknown_platform` with no adapter;
 * `overlap_needs_set` for an issuer that cannot hold two keys and cannot take a chosen value, so a failed run could not set the old one back.
 * A paste-only entry (no issuer) classifies by its own `classify` (KBOX-40).
 */
export function keyConfigFor(source: PlatformSource, platform: string): KeyConfig {
  const kit = source.platform(platform);
  const classify = classifierOf(kit);
  if (kit === undefined || classify === undefined) throw new ApiError('rejected', 'unknown_platform');
  if (kit.issuer === undefined) return { classify, create: 'paste', location: kit.location };
  const caps = kit.issuer.capabilities();
  if (!caps.overlap && setterOf(kit.issuer) === undefined) throw new ApiError('rejected', 'overlap_needs_set');
  return { classify, create: caps.create, location: kit.location };
}

/** KBOX-15: the class of scope items at a location, never below the class without it, raised by the owner's mark. */
export const classOfKey = (config: KeyConfig, items: readonly string[], at: KeyLocation, mark: KeyClass | undefined): KeyClass =>
  flooredClass(config.classify({ items }, {}), config.classify({ items }, at), mark);

/** The location the action names, `{}` when it names none. */
export const locationOf = (action: AddKey): KeyLocation => action.location ?? {};

/**
 * The class and location of an `add_key`, or its refusal at proposal (`rejected`, KBOX-57): a location the entry refuses for that class, or
 * a scope item that names a declared location field.
 */
export function placedKey(config: KeyConfig, action: AddKey): { readonly klass: KeyClass; readonly at: KeyLocation } {
  const at = locationOf(action);
  const klass = classOfKey(config, action.scope.items, at, action.mark_admin === true ? 'admin' : undefined);
  const verdict = checkLocation(config.location, at, klass, action.scope.items);
  if (verdict !== 'ok') throw new ApiError('rejected', verdict);
  return { klass, at };
}

export function newKeyOf(action: AddKey, source: PlatformSource, destinations: readonly DestinationRow[] = [], rotateEveryDays = 90): NewKey {
  const { klass, at } = placedKey(keyConfigFor(source, action.platform), action);
  return {
    keyref: keyrefOf(action.platform, action.projects, action.name),
    platform: action.platform,
    name: action.name,
    projects: action.projects,
    scopeItems: action.scope.items,
    class: klass,
    destinations,
    rotateEveryDays,
    graceHours: defaultGraceHours(destinations.map((d) => d.readable_by)),
    location: at,
    markAdmin: action.mark_admin === true,
  };
}
