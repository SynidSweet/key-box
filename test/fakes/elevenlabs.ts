// The ElevenLabs platform as docs/probes/elevenlabs.md describes it: two regional hosts with a workspace each (service accounts holding
// keys), the `xi-api-key` header, `{detail:{status:'invalid_api_key',...}}` for a bad key (echoing the presented key, as a real 401 may),
// 404 `{detail:'Not Found'}` for an unknown route. Each region is a loopback server; `http` routes by the URL's host like the shell does.
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { randomBytes } from 'node:crypto';
import type { AdapterHttp, HttpRequest, HttpResponse } from '../../src/ports/http.ts';
import { HttpTransportError } from '../../src/ports/http.ts';
import type { Lent } from '../../src/ports/types.ts';
import { adapterHttpTo } from '../kit/adapter-http.ts';
import type { SentRequest } from '../kit/adapter-http.ts';
import { lent } from '../kit/lent.ts';

export type Region = 'global' | 'us';
export const HOST_OF: Readonly<Record<Region, string>> = { global: 'api.elevenlabs.io', us: 'api.us.elevenlabs.io' };

interface StoredKey {
  readonly name: string;
  readonly value: string;
  disabled: boolean;
}
interface Account {
  readonly name: string;
  readonly keys: Map<string, StoredKey>;
}

export interface RegionState {
  readonly accounts: Map<string, Account>;
  readonly masters: Set<string>;
  /** Key values that are live but lack the permission `/v1/user` and `/v1/models` need: those routes answer them 403 (a real restricted key may be refused by permission). */
  readonly restricted: Set<string>;
  /** Make every call answer with this status and a body that quotes the presented key (a failing platform). */
  failWith: number | undefined;
  /** Drop every connection without an answer. */
  down: boolean;
  /** The create answer: `ok`, `no-key-id` (the value without its id), or a fixed value to hand out instead of a random one. */
  createValue: string | undefined;
  createAnswer: 'ok' | 'no-key-id';
}

const hex = (n: number): string => randomBytes(n).toString('hex');
export const MASTER_GLOBAL = 'sk_kbox-test-master-global-fake';
export const MASTER_US = 'sk_kbox-test-master-us-fake';
export const STRANGER = 'sk_kbox-test-stranger-fake';

function freshRegion(master: string): RegionState {
  return {
    accounts: new Map([['sa-test-1', { name: 'service account one', keys: new Map() }]]),
    masters: new Set([master]),
    restricted: new Set(),
    failWith: undefined,
    down: false,
    createValue: undefined,
    createAnswer: 'ok',
  };
}

const json = (res: ServerResponse, status: number, body: unknown): void => {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
};

const refusal = (res: ServerResponse, presented: string): void =>
  json(res, 401, { detail: { type: 'authentication_error', code: 'unauthorized', message: `Invalid API key: ${presented}`, status: 'invalid_api_key', request_id: 'req-fake' } });

const parsed = (text: string): unknown => {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return 'not json';
  }
};

const bodyOf = (req: IncomingMessage): Promise<unknown> =>
  new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => void chunks.push(c));
    req.on('end', () => resolve(parsed(Buffer.concat(chunks).toString('utf8'))));
  });

function handle(state: RegionState, req: IncomingMessage, res: ServerResponse, body: unknown): void {
  const presented = String(req.headers['xi-api-key'] ?? '');
  if (state.down) {
    req.socket.destroy();
    return;
  }
  if (state.failWith !== undefined) {
    json(res, state.failWith, { detail: { message: `internal: ${presented}` } });
    return;
  }
  const path = new URL(req.url ?? '/', 'http://fake').pathname;
  const method = req.method ?? '';
  const live = [...state.accounts.values()].some((a) => [...a.keys.values()].some((k) => k.value === presented && !k.disabled));
  if (path === '/v1/user' || path === '/v1/models') {
    if (state.restricted.has(presented)) {
      json(res, 403, { detail: { type: 'authorization_error', code: 'missing_permissions', message: 'The API key is missing the permission user_read', status: 'missing_permissions' } });
      return;
    }
    if (state.masters.has(presented) || live) json(res, 200, { ok: true });
    else refusal(res, presented);
    return;
  }
  if (!path.startsWith('/v1/service-accounts')) {
    json(res, 404, { detail: 'Not Found' });
    return;
  }
  if (!state.masters.has(presented)) {
    refusal(res, presented);
    return;
  }
  const parts = path.split('/').filter((p) => p !== '');
  if (parts.length === 2 && method === 'GET') {
    json(res, 200, {
      'service-accounts': [...state.accounts].map(([id, a]) => ({
        service_account_user_id: id,
        name: a.name,
        'api-keys': [...a.keys].map(([keyId, k]) => ({ key_id: keyId, name: k.name, hint: 'sk_...fake', is_disabled: k.disabled })),
      })),
    });
    return;
  }
  const account = state.accounts.get(parts[2] ?? '');
  if (account === undefined || parts[3] !== 'api-keys') {
    json(res, 404, { detail: { status: 'not_found', message: 'no such service account' } });
    return;
  }
  if (parts.length === 4 && method === 'POST') {
    const asked = body as { name?: unknown; permissions?: unknown } | undefined;
    if (typeof asked?.name !== 'string' || asked.permissions === undefined) {
      json(res, 422, { detail: [{ loc: ['body', 'permissions'], msg: 'field required' }] });
      return;
    }
    const keyId = `key-${hex(6)}`;
    const value = state.createValue ?? `sk_${hex(24)}`;
    account.keys.set(keyId, { name: asked.name, value, disabled: false });
    json(res, 200, state.createAnswer === 'ok' ? { 'xi-api-key': value, key_id: keyId } : { 'xi-api-key': value });
    return;
  }
  const key = account.keys.get(parts[4] ?? '');
  if (key === undefined) {
    json(res, 404, { detail: { status: 'not_found', message: 'no such key' } });
    return;
  }
  if (parts.length === 5 && method === 'DELETE') {
    account.keys.delete(parts[4] ?? '');
    json(res, 200, { status: 'ok' });
    return;
  }
  json(res, 404, { detail: 'Not Found' });
}

function listen(state: RegionState): Promise<Server> {
  const server = createServer((req, res) => {
    void bodyOf(req).then((body) => handle(state, req, res, body));
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

export interface ElevenLabsWorld {
  readonly http: AdapterHttp;
  readonly sent: readonly SentRequest[];
  readonly regions: Readonly<Record<Region, RegionState>>;
  /** A master key the global region accepts, and one the us region accepts. */
  master(region?: Region): Lent;
  stranger(): Lent;
  /** Back to one fresh service account in each region, no keys, no failures. */
  clearSent(): void;
  reset(): void;
  close(): Promise<void>;
}

export async function startElevenLabsWorld(): Promise<ElevenLabsWorld> {
  const regions: Record<Region, RegionState> = { global: freshRegion(MASTER_GLOBAL), us: freshRegion(MASTER_US) };
  const servers: Record<Region, Server> = { global: await listen(regions.global), us: await listen(regions.us) };
  const linkTo = (region: Region): AdapterHttp & { readonly sent: readonly SentRequest[] } => adapterHttpTo({ url: `http://127.0.0.1:${(servers[region].address() as AddressInfo).port}` });
  const links: Record<Region, AdapterHttp & { readonly sent: readonly SentRequest[] }> = { global: linkTo('global'), us: linkTo('us') };
  const sent: SentRequest[] = [];
  const http: AdapterHttp = {
    request(req: HttpRequest): Promise<HttpResponse> {
      const host = new URL(req.url).hostname;
      const region = (Object.keys(HOST_OF) as Region[]).find((r) => HOST_OF[r] === host);
      if (region === undefined) return Promise.reject(new HttpTransportError('refused'));
      const before = links[region].sent.length;
      const answer = links[region].request(req);
      void answer.then(
        () => sent.push(...links[region].sent.slice(before)),
        () => sent.push(...links[region].sent.slice(before)),
      );
      return answer;
    },
  };
  return {
    http,
    sent,
    regions,
    master: (region = 'global') => lent(Buffer.from(region === 'global' ? MASTER_GLOBAL : MASTER_US), `master:${region}`),
    stranger: () => lent(Buffer.from(STRANGER), 'stranger:1'),
    clearSent() {
      sent.length = 0;
    },
    reset() {
      for (const r of Object.keys(regions) as Region[]) {
        const fresh = freshRegion(r === 'global' ? MASTER_GLOBAL : MASTER_US);
        regions[r].accounts.clear();
        for (const [id, a] of fresh.accounts) regions[r].accounts.set(id, a);
        regions[r].masters.clear();
        for (const m of fresh.masters) regions[r].masters.add(m);
        regions[r].restricted.clear();
        regions[r].failWith = undefined;
        regions[r].down = false;
        regions[r].createValue = undefined;
        regions[r].createAnswer = 'ok';
      }
      sent.length = 0;
    },
    close: () => Promise.all(Object.values(servers).map((s) => new Promise<void>((resolve) => { s.closeAllConnections(); s.close(() => resolve()); }))).then(() => undefined),
  };
}
