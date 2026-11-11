// KBOX-15: the one place that turns an `add_key` request into the rows of a new key: the class is the higher of the adapter's
// classification and the owner's mark, the grace default follows the destinations, the reference is `platform/project/NAME`.
import { classOf, keyrefOf } from '../pure/class.ts';
import type { Action } from '../pure/actions.ts';
import { ApiError } from '../pure/errors.ts';
import { defaultGraceHours } from '../pure/rotation-machine.ts';
import type { NewKey } from './orchestrator.ts';
import type { IssuerCapabilities } from '../ports/issuer.ts';
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

/**
 * The issuer's capabilities for a key's platform, or the refusal of the key's configuration: `unknown_platform` with no adapter;
 * `overlap_needs_set` for a platform that cannot hold two keys and cannot take a chosen value, so a failed run could not set the old one back.
 */
export function capabilitiesFor(source: PlatformSource, platform: string): IssuerCapabilities {
  const issuer = source.platform(platform)?.issuer;
  if (issuer === undefined) throw new ApiError('rejected', 'unknown_platform');
  const caps = issuer.capabilities();
  if (!caps.overlap && setterOf(issuer) === undefined) throw new ApiError('rejected', 'overlap_needs_set');
  return caps;
}

export function newKeyOf(action: AddKey, source: PlatformSource, destinations: readonly DestinationRow[] = [], rotateEveryDays = 90): NewKey {
  const caps = capabilitiesFor(source, action.platform);
  return {
    keyref: keyrefOf(action.platform, action.projects, action.name),
    platform: action.platform,
    name: action.name,
    projects: action.projects,
    scopeItems: action.scope.items,
    class: classOf(caps.classify({ items: action.scope.items }), action.mark_admin === true ? 'admin' : undefined),
    destinations,
    rotateEveryDays,
    graceHours: defaultGraceHours(destinations.map((d) => d.readable_by)),
    location: {},
    markAdmin: action.mark_admin === true,
  };
}
