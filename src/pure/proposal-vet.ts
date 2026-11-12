// KBOX-23: the proposal check. A proposal whose executor or adapter does not exist is `rejected` before an approval is asked for.
import type { PlatformEntry } from '../ports/platform.ts';
import type { Action, ActionKind } from './actions.ts';
import { platformOfKeyref } from './class.ts';
import { adapterKindOf } from './destination-kind.ts';

type Vet = (action: Action) => 'ok' | 'rejected';
type VetEntry = Pick<PlatformEntry, 'id' | 'relay' | 'destinations'>;

/**
 * The adapter condition of each kind: `add_key` needs its platform registered (with an issuer or paste-only); a destination other than the
 * workstation needs an entry that provides its kind (removing one needs none); `set_allow_rules` needs a key whose platform has a relay profile; the Vercel kinds need
 * the `vercel` platform. The rest need no adapter. Whether an executor exists is `vetWired`'s question, not this one's.
 */
export const vetAction =
  (registry: readonly VetEntry[]): Vet =>
  (action) => {
    switch (action.kind) {
      case 'add_key':
        return registry.some((e) => e.id === action.platform) ? 'ok' : 'rejected';
      case 'add_destination':
        return action.destination.kind === 'workstation' || providesKind(registry, action.destination.kind) ? 'ok' : 'rejected';
      case 'set_allow_rules':
        return registry.some((e) => e.id === platformOfKeyref(action.keyref) && e.relay !== undefined) ? 'ok' : 'rejected';
      case 'vercel_set_domain':
      case 'vercel_set_team_setting':
        return registry.some((e) => e.id === 'vercel') ? 'ok' : 'rejected';
      case 'remove_destination':
      case 'delete_key':
      case 'rotate_key':
      case 'demote':
      case 'set_schedule':
      case 'grant':
      case 'revoke_grant':
      case 'approver_add':
      case 'approver_remove':
      case 'install_update':
      case 'enrol':
        return 'ok';
    }
  };

const providesKind = (registry: readonly VetEntry[], metaKind: string): boolean => {
  const adapterKind = adapterKindOf(metaKind);
  return adapterKind !== undefined && registry.some((e) => (e.destinations ?? []).some((k) => k.destination.kind === adapterKind));
};

/** A kind nobody executes is refused at proposal time (KBOX-23): `wired` is the kinds core has an executor for, taken from the wiring itself. */
export const vetWired =
  (wired: ReadonlySet<ActionKind>, vet: Vet): Vet =>
  (action) =>
    wired.has(action.kind) ? vet(action) : 'rejected';
