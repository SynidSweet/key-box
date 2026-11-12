// KBOX-40: the organization's key list, read page by page. One reader for the lister and the retire call.
import type { AdapterHttp } from '../../ports/http.ts';
import type { Lent } from '../../ports/types.ts';
import { call, failureOf } from './call.ts';
import { AnthropicError } from './errors.ts';

/** A key as the list shows it: never the secret, only a hint at its start and end. */
export interface ListedKey {
  readonly id: string;
  readonly name: string;
  readonly status: string;
  readonly hint: string | undefined;
}

export interface KeyPages {
  readonly keys: readonly ListedKey[];
  /** False when a page after the first could not be read: absence from this list proves nothing. */
  readonly complete: boolean;
}

export const DEFAULT_PAGE_SIZE = 1000;

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/** One page's body as keys, or the fixed `bad_answer` when it is not a page of keys. */
function pageOf(json: unknown): { readonly keys: ListedKey[]; readonly hasMore: boolean; readonly lastId: string | undefined } {
  if (!isRecord(json) || !Array.isArray(json['data'])) throw new AnthropicError('bad_answer');
  const keys = json['data'].map((item: unknown): ListedKey => {
    if (!isRecord(item) || typeof item['id'] !== 'string' || typeof item['status'] !== 'string') throw new AnthropicError('bad_answer');
    return { id: item['id'], name: typeof item['name'] === 'string' ? item['name'] : '', status: item['status'], hint: typeof item['partial_key_hint'] === 'string' ? item['partial_key_hint'] : undefined };
  });
  const lastId = json['last_id'];
  return { keys, hasMore: json['has_more'] === true, lastId: typeof lastId === 'string' ? lastId : undefined };
}

/**
 * Every key the admin key can see (with `status` set, only those), a page at a time. A first page that cannot be read throws (`rejected`,
 * `http_error`, `unreachable`); a later page that cannot be read ends the list as incomplete, unless the platform refused the key.
 */
export async function readKeys(http: AdapterHttp, admin: Lent, options: { readonly status?: string; readonly pageSize: number }): Promise<KeyPages> {
  // UNVERIFIED (anthropic.key-list-status-filter): the path, `status`, `limit`, `after_id`, and the page fields `data`, `has_more`, `last_id`
  // are from the SDK documentation; a live 401 does not tell a wrong path from a bad key.
  const keys: ListedKey[] = [];
  let after: string | undefined;
  for (;;) {
    const query = new URLSearchParams();
    if (options.status !== undefined) query.set('status', options.status);
    query.set('limit', String(options.pageSize));
    if (after !== undefined) query.set('after_id', after);
    let page: ReturnType<typeof pageOf>;
    try {
      const answer = await call(http, admin, 'GET', `/v1/organizations/api_keys?${query.toString()}`);
      if (answer === undefined) throw new AnthropicError('rejected');
      if (answer.status !== 200) throw failureOf(answer.status);
      page = pageOf(answer.json);
    } catch (error) {
      if (after !== undefined && error instanceof AnthropicError && error.code !== 'rejected') return { keys, complete: false };
      throw error;
    }
    keys.push(...page.keys);
    if (!page.hasMore) return { keys, complete: true };
    if (page.lastId === undefined || page.lastId === after) return { keys, complete: false };
    after = page.lastId;
  }
}
