// KBOX-37, KBOX-51: the keys the platform holds, from `GET /v1/projects/{ref}/api-keys` (reveal not asked: a value never enters a listing).
// A key with no id (a legacy key) cannot be revoked by id and is left out. A project the platform does not know has no keys to show, but a
// listing of it is not complete: absence from it proves nothing.
import type { KeyLister, KeyListing, PlatformKeyInfo } from '../../ports/issuer.ts';
import type { KeyLocation, Lent } from '../../ports/types.ts';
import { failureOf, SupabaseError } from './errors.ts';
import { isRecord } from './management.ts';
import type { Management } from './management.ts';
import { projectRefs } from './projects.ts';
import { keyIdOf, PROJECT_REF, splitKeyId } from './shape.ts';

export function createLister(call: Management): KeyLister {
  async function inProject(ref: string, master: Lent): Promise<{ readonly complete: boolean; readonly keys: PlatformKeyInfo[] }> {
    const answer = await call(master, { method: 'GET', path: `/v1/projects/${ref}/api-keys` });
    if (answer.status === 404) return { complete: false, keys: [] };
    if (answer.status !== 200) throw failureOf(answer.status);
    if (!answer.json.ok || !Array.isArray(answer.json.value)) throw new SupabaseError('bad_answer');
    const keys: PlatformKeyInfo[] = [];
    for (const entry of answer.json.value as unknown[]) {
      if (!isRecord(entry) || typeof entry['name'] !== 'string') throw new SupabaseError('bad_answer');
      const id = entry['id'];
      if (id === null || id === undefined) continue;
      if (typeof id !== 'string' || splitKeyId(keyIdOf(ref, id)) === undefined) throw new SupabaseError('bad_answer');
      keys.push({ platformKeyId: keyIdOf(ref, id), name: entry['name'], location: { project: ref } });
    }
    return { complete: true, keys };
  }

  async function listAt(at: KeyLocation, master: Lent): Promise<KeyListing> {
    if (at.project !== undefined && !PROJECT_REF.test(at.project)) throw new SupabaseError('bad_project');
    const refs = at.project === undefined ? await projectRefs(call, master) : [at.project];
    let complete = true;
    const keys: PlatformKeyInfo[] = [];
    for (const ref of refs) {
      const found = await inProject(ref, master);
      complete &&= found.complete;
      keys.push(...found.keys);
    }
    return { complete, at, keys };
  }

  return {
    list: async (master) => [...(await listAt({}, master)).keys],
    listAt,
  };
}
