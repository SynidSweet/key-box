// KBOX-15: the one place that turns an `add_key` request into the rows of a new key: the class is the higher of the adapter's
// classification and the owner's mark, the grace default follows the destinations, the reference is `platform/project/NAME`.
import { classOf, keyrefOf } from '../pure/class.ts';
import type { Action } from '../pure/actions.ts';
import { ApiError } from '../pure/errors.ts';
import { defaultGraceHours } from '../pure/rotation-machine.ts';
import type { NewKey } from './orchestrator.ts';
import type { KeyClass, Scope } from '../ports/types.ts';
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

/** What a key request needs of its platform: the class of a scope and how a key is made (a platform with no issuer is always pasted). */
export interface KeyConfig {
  readonly classify: (scope: Scope) => KeyClass;
  readonly create: 'api' | 'paste';
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
  if (kit.issuer === undefined) return { classify, create: 'paste' };
  const caps = kit.issuer.capabilities();
  if (!caps.overlap && setterOf(kit.issuer) === undefined) throw new ApiError('rejected', 'overlap_needs_set');
  return { classify, create: caps.create };
}

export function newKeyOf(action: AddKey, source: PlatformSource, destinations: readonly DestinationRow[] = [], rotateEveryDays = 90): NewKey {
  const config = keyConfigFor(source, action.platform);
  return {
    keyref: keyrefOf(action.platform, action.projects, action.name),
    platform: action.platform,
    name: action.name,
    projects: action.projects,
    scopeItems: action.scope.items,
    class: classOf(config.classify({ items: action.scope.items }), action.mark_admin === true ? 'admin' : undefined),
    destinations,
    rotateEveryDays,
    graceHours: defaultGraceHours(destinations.map((d) => d.readable_by)),
    location: {},
    markAdmin: action.mark_admin === true,
  };
}
