// KBOX-41: the one home of a Google key's impersonation target. A key that makes the box act as a service account carries exactly one scope
// item `sa:<project>/<account>` (the `@` of the address is outside the scope-item alphabet), approved on the phone and stored with the key; the
// address is derived from it. Nothing else names a target: not `projects`, not a request field.

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
