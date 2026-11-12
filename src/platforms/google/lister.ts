// KBOX-59, KBOX-51: the keys of one stored project, from `GET .../v2/projects/<project>/locations/global/keys` (no `showDeleted`: the default
// omits deleted keys, UNVERIFIED `google.apikeys-create-answer`), following `nextPageToken`. There is no platform-wide `list`: no master sees the
// whole platform, so reconcile asks one stored location at a time. Each key is reported by the stored id (`storedIdOf`: a key that names another
// place is left out and the listing is not complete); a key with a `deleteTime` is `disabled` (UNVERIFIED `google.apikey-verify-call`), which
// KBOX-51 counts as dead. No key string is read: a listing carries no value.
import type { KeyLister, KeyListing, PlatformKeyInfo } from '../../ports/issuer.ts';
import type { KeyLocation, Lent } from '../../ports/types.ts';
import { APIKEYS_ORIGIN, failureOf, recordOf, withAdmin } from './admin.ts';
import type { Admin, AdminDeps } from './admin.ts';
import { GoogleError } from './errors.ts';
import { storedIdOf } from './key-name.ts';
import { GOOGLE_ID } from './scope.ts';

const PAGE_TOKEN = /^[A-Za-z0-9._~=-]{1,2048}$/;

/** One key of a listing as the box knows it, or undefined for an entry that names no key of the stored project. */
async function infoOf(entry: unknown, admin: Admin, project: string): Promise<PlatformKeyInfo | undefined> {
  const key = typeof entry === 'object' && entry !== null && !Array.isArray(entry) ? (entry as Record<string, unknown>) : undefined;
  const id = key === undefined ? undefined : await storedIdOf(key['name'], project, admin.numberOf);
  if (key === undefined || id === undefined) return undefined;
  const deleted = typeof key['deleteTime'] === 'string' && key['deleteTime'] !== '';
  return { platformKeyId: id, name: typeof key['displayName'] === 'string' ? key['displayName'] : '', location: { project }, ...(deleted ? { disabled: true as const } : {}) };
}

export function createLister(deps: AdminDeps): KeyLister {
  async function listAt(at: KeyLocation, master: Lent): Promise<KeyListing> {
    const project = at.project;
    if (project === undefined || !GOOGLE_ID.test(project)) throw new GoogleError('bad_location');
    return withAdmin(deps, master, project, async (admin) => {
      const keys: PlatformKeyInfo[] = [];
      const tokens = new Set<string>();
      let complete = true;
      let token: string | undefined;
      for (let reads = 0; ; reads += 1) {
        const query = token === undefined ? '' : `?pageToken=${encodeURIComponent(token)}`;
        const page = await pageOf(admin, `${APIKEYS_ORIGIN}/projects/${project}/locations/global/keys${query}`, reads === 0);
        if (page === 'unread') {
          complete = false;
          break;
        }
        for (const entry of page.keys) {
          const info = await infoOf(entry, admin, project);
          if (info === undefined) complete = false;
          else keys.push(info);
        }
        if (page.next === undefined) break;
        if (!PAGE_TOKEN.test(page.next) || tokens.has(page.next)) {
          // A token that is no token, or one already followed, would loop: what was read is what there is, and it is not the whole.
          complete = false;
          break;
        }
        tokens.add(page.next);
        token = page.next;
      }
      return { complete, at: { project }, keys };
    });
  }

  return { listAt };
}

interface Page {
  readonly keys: readonly unknown[];
  readonly next: string | undefined;
}

/** One page: the first must be read (else the listing throws), a later one that cannot be is `unread` (the listing is then not complete). */
async function pageOf(admin: Admin, url: string, first: boolean): Promise<Page | 'unread'> {
  try {
    const answer = await admin.call({ method: 'GET', url });
    if (answer.status !== 200) throw failureOf(answer.status);
    const body = recordOf(answer.json);
    const keys = body?.['keys'] ?? [];
    if (body === undefined || !Array.isArray(keys)) throw new GoogleError('bad_answer');
    const next = body['nextPageToken'];
    return { keys, next: typeof next === 'string' && next !== '' ? next : undefined };
  } catch (error) {
    // The first page's failure is the listing's: it throws. A later page's leaves a partial listing, which says it is not complete.
    if (first || !(error instanceof GoogleError)) throw error;
    return 'unread';
  }
}
