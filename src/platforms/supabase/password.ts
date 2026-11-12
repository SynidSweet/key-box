// KBOX-37: the database password call, `PATCH /v1/projects/{ref}/database/password` body `{password}` (VERIFIED). The box makes the value (32
// random bytes as base64url, 43 characters, `overlap: false`). Rotating it is deferred with the CI destination (design 13), so this is the
// call and its test only: nothing registers it as an issuer's `set`.
import type { Lent, KeyLocation } from '../../ports/types.ts';
import { failureOf, SupabaseError } from './errors.ts';
import type { Management } from './management.ts';
import { PASSWORD, PROJECT_REF } from './shape.ts';

export type PasswordSetter = (value: Lent, at: KeyLocation, master: Lent) => Promise<void>;

/** "Make it so": safe to repeat. The value is read inside `use` and goes into the request body only. */
export function createPasswordSetter(call: Management): PasswordSetter {
  return async (value, at, master) => {
    const ref = at.project;
    if (ref === undefined || !PROJECT_REF.test(ref)) throw new SupabaseError('bad_project');
    await value.use(async (bytes) => {
      const password = Buffer.from(bytes).toString('utf8');
      if (!PASSWORD.test(password)) throw new SupabaseError('bad_password');
      const answer = await call(master, { method: 'PATCH', path: `/v1/projects/${ref}/database/password`, body: { password } });
      if (answer.status !== 200 && answer.status !== 201) throw failureOf(answer.status);
    });
  };
}
