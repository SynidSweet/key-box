// KBOX-23: the proposal check. A proposal whose executor or adapter does not exist is `rejected` before an approval is asked for.
import type { PlatformEntry } from '../ports/platform.ts';
import type { Action } from './actions.ts';

/** The kinds whose executors are not built yet (a later unit builds each): refused whatever is registered. The one list. */
const NO_EXECUTOR: ReadonlySet<Action['kind']> = new Set(['add_destination', 'set_allow_rules', 'vercel_set_domain', 'vercel_set_team_setting']);

/** `add_key` needs its platform registered (with an issuer or paste-only); the kinds in `NO_EXECUTOR` are refused; the rest pass. */
export const vetAction =
  (registry: readonly Pick<PlatformEntry, 'id'>[]) =>
  (action: Action): 'ok' | 'rejected' => {
    if (NO_EXECUTOR.has(action.kind)) return 'rejected';
    if (action.kind === 'add_key') return registry.some((e) => e.id === action.platform) ? 'ok' : 'rejected';
    return 'ok';
  };
