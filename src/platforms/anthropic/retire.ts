// KBOX-40, KBOX-51 step 10: retire the old Anthropic key after a paste rotation. The box never recorded the old key's id (a pasted
// generation has none), and the list shows only `partial_key_hint`, so the id is found by matching the old value against the hints of the
// LIVE keys: one match is retired, none is `absent`, two or more is refused (`ambiguous`) and nothing is changed. The caller then confirms
// through the verifier that the old value is rejected before it marks the generation `retired`.
import type { AdapterHttp } from '../../ports/http.ts';
import type { Lent } from '../../ports/types.ts';
import { call, failureOf } from './call.ts';
import { AnthropicError } from './errors.ts';
import { DEFAULT_PAGE_SIZE, readKeys } from './keys.ts';

export interface AnthropicRetirer {
  /** Sets the live key matching `old` to `inactive` with the admin key. 'absent' when no live key matches or the update is answered 404. */
  retire(old: Lent, admin: Lent): Promise<'retired' | 'absent'>;
}

/**
 * Whether a list `hint` fits a key value: the hint is the start and the end of the value around `...`.
 * UNVERIFIED (anthropic.key-formats): that shape of `partial_key_hint` is assumed; a hint of another shape matches nothing.
 */
export function hintMatches(hint: string | undefined, value: string): boolean {
  if (hint === undefined) return false;
  const at = hint.indexOf('...');
  if (at < 1) return false;
  const head = hint.slice(0, at);
  const tail = hint.slice(at + 3);
  return tail.length > 0 && value.length >= head.length + tail.length && value.startsWith(head) && value.endsWith(tail);
}

export function createAnthropicRetirer(deps: { readonly http: AdapterHttp }): AnthropicRetirer {
  const { http } = deps;
  return {
    async retire(old, admin) {
      const pages = await readKeys(http, admin, { status: 'active', pageSize: DEFAULT_PAGE_SIZE });
      // an unread page could hold a second match: a partial list cannot say the match is unique
      if (!pages.complete) throw new AnthropicError('http_error');
      const matches = await old.use((bytes) => {
        const text = Buffer.from(bytes).toString('utf8');
        return Promise.resolve(pages.keys.filter((k) => hintMatches(k.hint, text)));
      });
      const [only, ...rest] = matches;
      if (only === undefined) return 'absent';
      if (rest.length > 0) throw new AnthropicError('ambiguous');
      // UNVERIFIED (anthropic.key-retire-statuses): `inactive` is a status the update accepts (SDK documentation); no live answer seen.
      const answer = await call(http, admin, 'POST', `/v1/organizations/api_keys/${encodeURIComponent(only.id)}`, { status: 'inactive' });
      if (answer === undefined) throw new AnthropicError('rejected');
      if (answer.status === 200) return 'retired';
      if (answer.status === 404) return 'absent';
      throw failureOf(answer.status);
    },
  };
}
