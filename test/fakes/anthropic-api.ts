// The Anthropic API as the probe report (docs/probes/anthropic.md) describes it: `x-api-key` auth, 401 `authentication_error` for a bad key
// (the message quotes the presented key, as a real platform may), `/v1/models`, and the organization key list and update. Ordinary keys
// verify on `/v1/models`; the admin key works on the organization routes only. ASSUMED (UNVERIFIED): the shape of `partial_key_hint`.

import { json, loopback } from './loopback.ts';
import type { Loopback, Teardown } from './loopback.ts';

export type FakeKeyStatus = 'active' | 'inactive' | 'archived' | 'expired';

export interface FakeApiKey {
  readonly id: string;
  readonly value: string;
  readonly name: string;
  status: FakeKeyStatus;
}

export const hintOf = (value: string): string => `${value.slice(0, 14)}...${value.slice(-4)}`;

export interface FakeAnthropic extends Loopback {
  readonly keys: Map<string, FakeApiKey>;
  readonly admins: Set<string>;
  /** Every request the platform answered: method and path with query. */
  readonly log: string[];
  /** From the n-th list page on (counted from this call) the list route answers 500: a page that cannot be read. */
  failPagesFrom(n: number): void;
  add(value: string, name: string, status?: FakeKeyStatus): string;
}

export async function fakeAnthropic(t: Teardown): Promise<FakeAnthropic> {
  const keys = new Map<string, FakeApiKey>();
  const admins = new Set<string>();
  const log: string[] = [];
  const state = { next: 1, pages: 0, failFromPage: undefined as number | undefined };
  const listed = (k: FakeApiKey) => ({ id: k.id, name: k.name, status: k.status, partial_key_hint: hintOf(k.value), type: 'api_key' });
  const server = await loopback(t, (req, body, res) => {
    const url = new URL(req.url ?? '/', 'http://platform');
    log.push(`${req.method ?? ''} ${url.pathname}${url.search}`);
    const presented = req.headers['x-api-key'];
    const key = typeof presented === 'string' ? presented : '';
    const deny = (status: number): void => json(res, status, { type: 'error', error: { type: status === 401 ? 'authentication_error' : 'permission_error', message: `invalid x-api-key: ${key}` }, request_id: 'req_fake' });
    const live = [...keys.values()].some((k) => k.value === key && k.status === 'active');
    if (url.pathname === '/v1/models' && req.method === 'GET') {
      if (admins.has(key)) return deny(403);
      return live ? json(res, 200, { data: [], has_more: false }) : deny(401);
    }
    if (!url.pathname.startsWith('/v1/organizations/api_keys')) return json(res, 404, { type: 'error', error: { type: 'not_found_error', message: 'not found' } });
    if (!admins.has(key)) return deny(401);
    if (url.pathname === '/v1/organizations/api_keys' && req.method === 'GET') {
      state.pages += 1;
      if (state.failFromPage !== undefined && state.pages >= state.failFromPage) return json(res, 500, { type: 'error', error: { type: 'api_error', message: `boom ${key}` } });
      const status = url.searchParams.get('status');
      const limit = Number(url.searchParams.get('limit') ?? '20');
      const after = url.searchParams.get('after_id');
      const all = [...keys.values()].filter((k) => status === null || k.status === status);
      const start = after === null ? 0 : all.findIndex((k) => k.id === after) + 1;
      const page = all.slice(start, start + limit);
      return json(res, 200, { data: page.map(listed), has_more: start + limit < all.length, first_id: page[0]?.id ?? null, last_id: page[page.length - 1]?.id ?? null });
    }
    const id = url.pathname.slice('/v1/organizations/api_keys/'.length);
    const target = keys.get(id);
    if (req.method !== 'POST' || target === undefined) return json(res, 404, { type: 'error', error: { type: 'not_found_error', message: 'no such key' } });
    const wanted = (JSON.parse(body) as { status?: FakeKeyStatus }).status;
    if (wanted === 'inactive' || wanted === 'archived' || wanted === 'active') target.status = wanted;
    return json(res, 200, listed(target));
  });
  return Object.assign(server, {
    keys,
    admins,
    log,
    failPagesFrom(n: number): void {
      state.failFromPage = n;
      state.pages = 0;
    },
    add(value: string, name: string, status: FakeKeyStatus = 'active'): string {
      const id = `apikey_fake${String(state.next++).padStart(4, '0')}`;
      keys.set(id, { id, value, name, status });
      return id;
    },
  });
}
