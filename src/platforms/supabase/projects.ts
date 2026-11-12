// The projects the master can see: `GET /v1/projects`. Used only where the port gives no project: a listing of every place (the reconcile
// sweep). An issue never uses it: its project is the key's stored location (KBOX-57). A project's ref is its `ref` (or, on older answers, its `id`) when that is 20 lower-case letters.
import type { Lent } from '../../ports/types.ts';
import { failureOf, SupabaseError } from './errors.ts';
import { isRecord } from './management.ts';
import type { Management } from './management.ts';
import { PROJECT_REF } from './shape.ts';

export async function projectRefs(call: Management, master: Lent): Promise<string[]> {
  const answer = await call(master, { method: 'GET', path: '/v1/projects' });
  if (answer.status !== 200) throw failureOf(answer.status);
  if (!answer.json.ok || !Array.isArray(answer.json.value)) throw new SupabaseError('bad_answer');
  const refs: string[] = [];
  for (const project of answer.json.value as unknown[]) {
    const ref = isRecord(project) ? (typeof project['ref'] === 'string' ? project['ref'] : project['id']) : undefined;
    if (typeof ref !== 'string' || !PROJECT_REF.test(ref)) throw new SupabaseError('bad_answer');
    refs.push(ref);
  }
  return refs;
}
