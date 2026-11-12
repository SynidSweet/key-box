// KBOX-41: the one home of a Google key's impersonation target. A key that makes the box act as a service account carries exactly one scope
// item `sa:<project>/<account>` (the `@` of the address is outside the scope-item alphabet), approved on the phone and stored with the key; the
// address is derived from it. Nothing else names a target: not `projects`, not a request field.
import type { KeyShape, Scope } from '../../ports/types.ts';
import { GoogleError } from './errors.ts';

/** A Google project id or service-account id: 6 to 30 characters, a lower-case letter first, no hyphen last (Google's id form). */
export const GOOGLE_ID = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const SA_PREFIX = 'sa:';
/** The box's own admin account, made by the owner in each project (setup checklist); never a key's target. */
export const ADMIN_ACCOUNT = 'kbox-keys';

/** The service account a token is minted for, and the project it belongs to. */
export interface Target {
  readonly email: string;
  readonly project: string;
}

export type TargetRefusal = 'target_count' | 'target_malformed' | 'target_reserved';

export type TargetResult = { readonly ok: true; readonly target: Target } | { readonly ok: false; readonly code: TargetRefusal };

/** The address of `account` in `project`; both already in the id form. */
export const serviceAccount = (project: string, account: string): Target => ({ email: `${account}@${project}.iam.gserviceaccount.com`, project });

/** KBOX-24: whether a key with these stored scope items makes the box act as a service account (any `sa:` item, well-formed or not). */
export const actsAs = (items: readonly string[]): boolean => items.some((item) => item.startsWith(SA_PREFIX));

/** The key's target from its stored scope items: exactly one well-formed `sa:` item naming an account other than `kbox-keys`. */
export function targetOf(items: readonly string[]): TargetResult {
  const acting = items.filter((item) => item.startsWith(SA_PREFIX));
  const [only, second] = acting;
  if (only === undefined || second !== undefined) return { ok: false, code: 'target_count' };
  const [project, account, extra] = only.slice(SA_PREFIX.length).split('/');
  if (project === undefined || account === undefined || extra !== undefined || !GOOGLE_ID.test(project) || !GOOGLE_ID.test(account)) return { ok: false, code: 'target_malformed' };
  if (account === ADMIN_ACCOUNT) return { ok: false, code: 'target_reserved' };
  return { ok: true, target: serviceAccount(project, account) };
}

/**
 * KBOX-59: the shape of a Google API key: `AIza` and 35 base64url characters. The prefix is documented; the length is UNVERIFIED
 * (`google.aiza-length`, src/data/credential-shapes.json "AIza" min 35), so a key of another length is refused, never trusted.
 */
export const API_KEY_SHAPE: KeyShape = { prefix: 'AIza', alphabet: 'base64url', coreLength: { min: 35, max: 35 }, random: true };

const API_ITEM = /^api:([a-z][a-z0-9-]{0,62}\.googleapis\.com)$/;

/** A scope's items as a list: a single item is a list of one, none is none. */
export function itemsOf(scope: Scope): readonly string[] {
  const items = scope['items'];
  return items === undefined ? [] : typeof items === 'string' ? [items] : items;
}

/**
 * The services an API key is restricted to, from a scope of `api:<service>.googleapis.com` items, each once, in the order given. At least one,
 * and nothing else: an `sa:` item, any other word or a service outside `googleapis.com` is `bad_scope`, so the box never makes an unrestricted
 * key or one the owner did not approve. Pure; made before any call.
 */
export function apiServicesOf(scope: Scope): readonly string[] {
  const services = new Set<string>();
  for (const item of itemsOf(scope)) {
    const service = API_ITEM.exec(item)?.[1];
    if (service === undefined) throw new GoogleError('bad_scope');
    services.add(service);
  }
  if (services.size === 0) throw new GoogleError('bad_scope');
  return [...services];
}
