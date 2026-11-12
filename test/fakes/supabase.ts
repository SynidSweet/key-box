// A loopback server that plays the Supabase Management API as `docs/probes/supabase.md` describes it: auth first (401 `{message}` that quotes
// the bearer it was shown), api-keys under a project, edge-function secrets, the database password, a project list and one project read
// (`GET /v1/projects/{ref}`, whose answer shape is UNVERIFIED supabase.project-get-shape). `mode` makes it fail in its real ways. Synthetic
// values only.
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

export const REF = 'abcdefghijklmnopqrst';
export const OTHER_REF = 'tsrqponmlkjihgfedcba';
export const MASTER_TEXT = 'sbp_kbox-test-master-0123456789abcdef';
export const WRONG_TEXT = 'sbp_kbox-test-stranger-0123456789abcd';

/**
 * How the fake fails. `403`: every route is forbidden to this master (it is valid, but not this account's). `other-ref`: a project read answers 200 naming another project.
 * `no-ref`: a project read answers 200 with an object naming no project.
 */
export type Mode = 'ok' | '500' | '429' | '403' | 'null-key' | 'malformed' | 'gone-project' | 'other-ref' | 'no-ref';

interface StoredKey {
  /** Empty for a legacy key, which the platform lists with a null id. */
  readonly id: string;
  readonly name: string;
  readonly type: string;
  readonly value: string;
}

export interface FakeSupabase {
  readonly url: string;
  mode: Mode;
  /** The bearer the fake accepts (MASTER_TEXT after `reset`): a test whose master comes from elsewhere names it here. */
  masterText: string;
  /** Text planted in every key-create answer (a field the adapter never reads) to prove it goes nowhere. */
  plant: string | undefined;
  readonly keys: Map<string, StoredKey[]>;
  readonly secrets: Map<string, Map<string, string>>;
  readonly passwords: Map<string, string>;
  readonly projects: string[];
  readonly seen: { method: string; target: string; body: string }[];
  reset(): void;
  close(): Promise<void>;
}

const uuid = (n: number): string => `00000000-0000-4000-8000-${n.toString(16).padStart(12, '0')}`;

const json = (res: ServerResponse, status: number, body: unknown): void => {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
};

const readBody = (req: IncomingMessage): Promise<string> =>
  new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });

export async function startFakeSupabase(): Promise<FakeSupabase> {
  let counter = 0;
  const state: FakeSupabase = {
    url: '',
    mode: 'ok',
    masterText: MASTER_TEXT,
    plant: undefined,
    keys: new Map(),
    secrets: new Map(),
    passwords: new Map(),
    projects: [REF],
    seen: [],
    reset() {
      counter = 0;
      state.mode = 'ok';
      state.masterText = MASTER_TEXT;
      state.plant = undefined;
      state.keys.clear();
      state.secrets.clear();
      state.passwords.clear();
      state.projects.splice(0, state.projects.length, REF);
      state.seen.splice(0);
    },
    close: () => new Promise((resolve) => {
      server.closeAllConnections();
      server.close(() => resolve());
    }),
  };
  const server: Server = createServer((req, res) => {
    void (async () => {
      const body = await readBody(req);
      const url = new URL(req.url ?? '/', 'http://fake');
      state.seen.push({ method: req.method ?? '', target: `${url.pathname}${url.search}`, body });
      const bearer = (req.headers.authorization ?? '').replace(/^Bearer /, '');
      if (bearer !== state.masterText) return json(res, 401, { message: `JWT could not be decoded: ${bearer}` });
      if (state.mode === '500') return json(res, 500, { message: `internal ${bearer}` });
      if (state.mode === '429') return json(res, 429, { message: 'rate limited' });
      if (state.mode === '403') return json(res, 403, { message: 'Your account does not have the necessary privileges to access this endpoint' });
      if (state.mode === 'malformed') {
        res.writeHead(200, { 'content-type': 'application/json' });
        return res.end('[{"ref":');
      }
      const parts = url.pathname.split('/').filter((p) => p !== '');
      const method = req.method ?? '';
      if (parts.length === 2 && parts[1] === 'projects' && method === 'GET') return json(res, 200, state.projects.map((ref) => ({ ref, name: 'kbox-test' })));
      const ref = parts[2] ?? '';
      if (parts[1] !== 'projects' || !state.projects.includes(ref) || state.mode === 'gone-project') return json(res, 404, { message: 'project not found' });
      const rest = parts.slice(3);
      if (rest.length === 0 && method === 'GET') {
        if (state.mode === 'no-ref') return json(res, 200, { name: 'kbox-test', status: 'ACTIVE_HEALTHY' });
        const named = state.mode === 'other-ref' ? OTHER_REF : ref;
        return json(res, 200, { id: named, ref: named, name: 'kbox-test', organization_id: 'kboxtestorg', region: 'eu-west-1', status: 'ACTIVE_HEALTHY' });
      }
      const keys = state.keys.get(ref) ?? [];
      if (rest[0] === 'api-keys') {
        if (rest.length === 1 && method === 'GET') return json(res, 200, keys.map((k) => ({ id: k.id === '' ? null : k.id, name: k.name, type: k.type, api_key: null })));
        if (rest.length === 1 && method === 'POST') {
          const asked = JSON.parse(body) as { type: string; name: string };
          counter += 1;
          const value = `sb_secret_kbox-test_${counter.toString(16).padStart(24, '0')}`;
          const key = { id: uuid(counter), name: asked.name, type: asked.type, value };
          state.keys.set(ref, [...keys, key]);
          const revealed = url.searchParams.get('reveal') === 'true' && state.mode !== 'null-key';
          return json(res, 201, { id: key.id, name: key.name, type: key.type, api_key: revealed ? value : null, description: state.plant ?? null });
        }
        if (rest.length === 2 && method === 'DELETE') {
          const found = keys.find((k) => k.id === rest[1]);
          if (found === undefined) return json(res, 404, { message: 'not found' });
          state.keys.set(ref, keys.filter((k) => k !== found));
          return json(res, 200, { id: found.id, name: found.name });
        }
      }
      if (rest[0] === 'secrets' && rest.length === 1) {
        const held = state.secrets.get(ref) ?? new Map<string, string>();
        state.secrets.set(ref, held);
        if (method === 'POST') {
          for (const { name, value } of JSON.parse(body) as { name: string; value: string }[]) held.set(name, value);
          return json(res, 201, {});
        }
        if (method === 'DELETE') {
          for (const name of JSON.parse(body) as string[]) held.delete(name);
          return json(res, 200, {});
        }
        if (method === 'GET') return json(res, 200, [...held].map(([name, value]) => ({ name, value, updated_at: 'x' })));
      }
      if (rest[0] === 'database' && rest[1] === 'password' && method === 'PATCH') {
        state.passwords.set(ref, (JSON.parse(body) as { password: string }).password);
        return json(res, 200, { message: 'ok' });
      }
      return json(res, 404, { message: 'no route' });
    })();
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const withUrl = Object.assign(state, { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}` });
  return withUrl;
}
