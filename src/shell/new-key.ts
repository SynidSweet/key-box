// KBOX-15: the one place that turns an `add_key` request into the rows of a new key: the class is the higher of the adapter's
// classification and the owner's mark, the grace default follows the destinations, the reference is `platform/project/NAME`.
import { classOf, keyrefOf } from '../pure/class.ts';
import type { Action } from '../pure/actions.ts';
import { ApiError } from '../pure/errors.ts';
import { defaultGraceHours } from '../pure/rotation-machine.ts';
import type { NewKey } from './orchestrator.ts';
import type { PlatformSource } from './rotation-ports.ts';
import type { DestinationRow } from './rotation-store.ts';

export type AddKey = Extract<Action, { kind: 'add_key' }>;
export interface RotateKey {
  readonly kind: 'rotate_key';
  readonly keyref: string;
}
/** The two kinds a paste can settle (KBOX-12). */
export type PasteAction = AddKey | RotateKey;

export function newKeyOf(action: AddKey, source: PlatformSource, destinations: readonly DestinationRow[] = [], rotateEveryDays = 90): NewKey {
  const caps = source.platform(action.platform)?.issuer?.capabilities();
  if (caps === undefined) throw new ApiError('rejected', 'unknown_platform');
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
