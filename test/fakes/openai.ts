// A stateful stand-in for the OpenAI management API as docs/probes/openai.md describes it (KBOX-38): projects, service accounts and their
// keys behind an admin bearer, `GET /v1/models` behind any live key, pages of two, and a 401 that quotes the key it was sent.
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

export type OpenAiMode =
  | 'ok'
  /** Every answer is 401 quoting the presented key whole (the platform masks it; the worst case does not). */
  | '401-echo'
  | '500'
  /** The socket is destroyed before any answer. */
  | 'drop'
  /** The create-key answer is 200 with a `value` but no `id`. */
  | 'create-bad-shape'
  /** The create-key answer is 500 and its body carries the value that would have been issued. */
  | 'create-500-echo'
  /** `has_more` is true on every page, with the same cursor. */
  | 'stuck-pages';

export interface OpenAiCall {
  readonly method: string;
  readonly path: string;
  readonly body: unknown;
}

export interface FakeOpenAi {
  readonly url: string;
  readonly calls: readonly OpenAiCall[];
  readonly adminKey: string;
  close(): Promise<void>;
  /** Project ids, service accounts and keys now held, for assertions about what the adapter left on the platform. */
  readonly projects: readonly string[];
  serviceAccounts(project: string): readonly { readonly id: string; readonly name: string }[];
  keysOf(project: string): readonly { readonly id: string; readonly name: string; readonly expiresInSeconds: number | null }[];
  setMode(mode: OpenAiMode): void;
  /** Revokes a key the platform holds, as the owner would in the dashboard. */
  dropKey(id: string): void;
}

interface KeyRow {
  readonly id: string;
  readonly project: string;
  readonly name: string;
  readonly value: string;
  readonly expiresInSeconds: number | null;
}

const PAGE = 2;
const FILLER = 'kbox-test-filler-0123456789abcdefghijklmnopqrstuvwxyz';

const readBody = (req: IncomingMessage): Promise<unknown> =>
  new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      resolve(text === '' ? undefined : (JSON.parse(text) as unknown));
    });
  });

const send = (res: ServerResponse, status: number, body?: unknown): void => {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(body === undefined ? '' : JSON.stringify(body));
};

function page<T extends { readonly id: string }>(rows: readonly T[], url: URL, mode: OpenAiMode): { object: 'list'; data: T[]; has_more: boolean; last_id: string | null } {
  const after = url.searchParams.get('after');
  const start = after === null ? 0 : rows.findIndex((r) => r.id === after) + 1;
  const data = rows.slice(start, start + PAGE);
  const last = data[data.length - 1]?.id ?? after;
  return { object: 'list', data: [...data], has_more: mode === 'stuck-pages' ? true : start + PAGE < rows.length, last_id: last };
}

export async function fakeOpenAi(options: { readonly adminKey: string; readonly projects?: readonly string[] }): Promise<FakeOpenAi> {
  const calls: OpenAiCall[] = [];
  const projects = [...(options.projects ?? ['proj_kbox_test'])];
  const accounts: { id: string; name: string; project: string }[] = [];
  const keys = new Map<string, KeyRow>();
  let mode: OpenAiMode = 'ok';
  let next = 1;
  const newValue = (): string => {
    next += 1;
    return `sk-svcacct-${String(next).padStart(4, '0')}-${FILLER}`;
  };
  const addKey = (project: string, name: string, expires: number | null): KeyRow => {
    const id = `key_${String(next).padStart(4, '0')}`;
    const row: KeyRow = { id, project, name, value: newValue(), expiresInSeconds: expires };
    keys.set(id, row);
    return row;
  };

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://fake');
    const body = await readBody(req);
    calls.push({ method: req.method ?? '', path: `${url.pathname}${url.search}`, body });
    if (mode === 'drop') {
      req.socket.destroy();
      return;
    }
    const presented = (req.headers.authorization ?? '').replace(/^Bearer /i, '');
    if (mode === '401-echo') return send(res, 401, { error: { message: `Incorrect API key provided: ${presented}`, type: 'invalid_request_error', param: null, code: 'invalid_api_key' } });
    if (mode === '500') return send(res, 500, { error: { message: 'server error' } });
    const live = [...keys.values()].some((k) => k.value === presented);
    if (url.pathname === '/v1/models') {
      return live || presented === options.adminKey ? send(res, 200, { object: 'list', data: [] }) : send(res, 401, { error: { message: `Incorrect API key provided: ${presented.slice(0, 8)}******${presented.slice(-4)}`, code: 'invalid_api_key' } });
    }
    if (presented !== options.adminKey) return send(res, 401, { error: { message: `Incorrect API key provided: ${presented.slice(0, 8)}******${presented.slice(-4)}`, code: 'invalid_api_key' } });
    const parts = url.pathname.split('/').filter((p) => p !== '');
    // /v1/organization/projects[/{p}[/service_accounts[/{sa}/api_keys] | /api_keys[/{k}]]]
    if (parts[0] !== 'v1' || parts[1] !== 'organization' || parts[2] !== 'projects') return send(res, 404);
    const method = req.method ?? '';
    const project = parts[3];
    if (project === undefined) return method === 'GET' ? send(res, 200, page(projects.map((id) => ({ id })), url, mode)) : send(res, 404);
    if (!projects.includes(project)) return send(res, 404);
    if (parts[4] === 'service_accounts' && parts[5] === undefined) {
      if (method === 'GET') return send(res, 200, page(accounts.filter((a) => a.project === project), url, mode));
      if (method === 'POST') {
        const name = (body as { name?: string } | undefined)?.name ?? '';
        const account = { id: `svc_acct_${String(accounts.length + 1).padStart(3, '0')}`, name, project };
        accounts.push(account);
        const first = addKey(project, 'Secret Key', null);
        return send(res, 200, { object: 'organization.project.service_account', id: account.id, name, role: 'member', created_at: 1, api_key: { object: 'organization.project.service_account.api_key', value: first.value, name: first.name, created_at: 1, id: first.id } });
      }
    }
    if (parts[4] === 'service_accounts' && parts[6] === 'api_keys' && method === 'POST') {
      if (!accounts.some((a) => a.id === parts[5] && a.project === project)) return send(res, 404);
      const request = body as { name?: string; expires_in_seconds?: number | null } | undefined;
      const row = addKey(project, request?.name ?? '', request?.expires_in_seconds ?? null);
      if (mode === 'create-bad-shape') return send(res, 200, { object: 'organization.project.service_account.api_key', value: row.value, name: row.name });
      if (mode === 'create-500-echo') return send(res, 500, { error: { message: `could not store ${row.value}` } });
      return send(res, 200, { object: 'organization.project.service_account.api_key', value: row.value, name: row.name, created_at: 1, expires_at: row.expiresInSeconds === null ? null : 1_000 + row.expiresInSeconds, id: row.id });
    }
    if (parts[4] === 'api_keys') {
      const id = parts[5];
      if (id === undefined && method === 'GET') {
        const rows = [...keys.values()].filter((k) => k.project === project).map((k) => ({ object: 'organization.project.api_key', redacted_value: 'sk-...kbox', name: k.name, created_at: 1, id: k.id, owner: { type: 'service_account' } }));
        return send(res, 200, page(rows, url, mode));
      }
      if (id !== undefined && method === 'DELETE') {
        const row = keys.get(id);
        if (row === undefined || row.project !== project) return send(res, 404);
        keys.delete(id);
        return send(res, 200, { object: 'organization.project.api_key.deleted', id, deleted: true });
      }
    }
    return send(res, 404);
  }

  const server: Server = createServer((req, res) => {
    void handle(req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((err) => (err === undefined ? resolve() : reject(err)));
      }),
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    calls,
    adminKey: options.adminKey,
    projects,
    serviceAccounts: (project) => accounts.filter((a) => a.project === project).map(({ id, name }) => ({ id, name })),
    keysOf: (project) => [...keys.values()].filter((k) => k.project === project).map(({ id, name, expiresInSeconds }) => ({ id, name, expiresInSeconds })),
    setMode: (m) => void (mode = m),
    dropKey: (id) => void keys.delete(id),
  };
}
