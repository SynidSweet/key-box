// The Stripe API as the probe report (docs/probes/stripe.md) describes it: Bearer auth, an unknown path is 404 before auth, a bad key is 401
// `invalid_request_error` quoting the key, and a restricted key gets 403 on a resource it has no permission for.

import { json, loopback } from './loopback.ts';
import type { Loopback, Teardown } from './loopback.ts';

const ROUTES = ['/v1/balance', '/v1/customers', '/v1/charges', '/v1/products', '/v1/prices', '/v1/account'];

export interface FakeStripe extends Loopback {
  /** A live key and the route paths its restriction allows. */
  readonly allowed: Map<string, ReadonlySet<string>>;
  readonly log: string[];
}

export async function fakeStripe(t: Teardown): Promise<FakeStripe> {
  const allowed = new Map<string, ReadonlySet<string>>();
  const log: string[] = [];
  const server = await loopback(t, (req, _body, res) => {
    const url = new URL(req.url ?? '/', 'http://platform');
    log.push(`${req.method ?? ''} ${url.pathname}${url.search}`);
    if (!ROUTES.includes(url.pathname)) return json(res, 404, { error: { message: 'Unrecognized request URL', type: 'invalid_request_error' } });
    const key = (req.headers.authorization ?? '').replace(/^Bearer /, '');
    const may = allowed.get(key);
    if (may === undefined) return json(res, 401, { error: { message: `Invalid API Key provided: ${key}`, type: 'invalid_request_error' } });
    if (!may.has(url.pathname)) return json(res, 403, { error: { message: 'The provided key does not have the required permissions', type: 'invalid_request_error' } });
    return json(res, 200, { object: 'list', data: [] });
  });
  return Object.assign(server, { allowed, log });
}
