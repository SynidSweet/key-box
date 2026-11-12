// A stateful stand-in for api.vercel.com on a loopback port, answering as docs/probes/vercel.md describes: errors are
// `{error:{code,message}}`, a bad token is 403 with `invalidToken: true` (and the message quotes the presented token, the way a masked-key
// answer can), a project-scoped token may read its own project and itself and nothing else. Used with `adapterHttpTo(fake)`.
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

export interface FakeEnvVar {
  readonly id: string;
  readonly key: string;
  value: string;
  type: string;
  target: readonly string[];
}

export interface FakeVercelOptions {
  /** The master token's text. */
  readonly master: string;
  /** Project ids that exist; each starts with one READY production deployment. */
  readonly projects?: readonly string[];
  /** The text of the nth token the platform mints (1-based); default a fixed fake filler with the number. */
  readonly mint?: (n: number) => string;
  /** Tokens per page of `GET /v6/user/tokens`. */
  readonly pageSize?: number;
  /** How many `GET /v13/deployments/{id}` answers say BUILDING before the deploy settles. */
  readonly buildPolls?: number;
}

export interface FakeVercel {
  readonly url: string;
  readonly envs: ReadonlyMap<string, readonly FakeEnvVar[]>;
  /** Token ids that are live. */
  tokenIds(): string[];
  /** The text of a live token, for a test that has to present it. */
  tokenValue(id: string): string | undefined;
  /** The project a live token was made for. */
  tokenProject(id: string): string | undefined;
  /** The next deploy that starts ends in ERROR. */
  failNextDeploy(): void;
  /** Stops listening (a connection is refused) or listens again on the same port. */
  setDown(down: boolean): Promise<void>;
  /** Every request is answered with this status and a body quoting the presented token, until `undefined`. */
  forceStatus(status: number | undefined): void;
  /** Every 200 answer is cut off after its first bytes, until false. */
  cutAnswers(cut: boolean): void;
  /** Back to the start: no tokens, no variables, the seed deployments, every switch off. The server stays up. */
  reset(): void;
}

interface Token {
  readonly id: string;
  readonly name: string;
  readonly value: string;
  readonly projectId: string | undefined;
  readonly createdAt: number;
}

interface Deploy {
  readonly project: string;
  readonly name: string;
  state: string;
  polls: number;
  willFail: boolean;
}

interface Call {
  readonly method: string;
  readonly path: readonly string[];
  readonly query: URLSearchParams;
  readonly bearer: string;
  readonly body: unknown;
}

type Answer = { readonly status: number; readonly body: unknown };

const fail = (status: number, code: string, message: string, extra: object = {}): Answer => ({ status, body: { error: { code, message, ...extra } } });

const readBody = (req: IncomingMessage): Promise<unknown> =>
  new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      try {
        resolve(text === '' ? undefined : (JSON.parse(text) as unknown));
      } catch {
        resolve(undefined);
      }
    });
  });

const asRecord = (value: unknown): Record<string, unknown> => (typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : {});

/** `t` is a test context or the file-level `node:test` hooks: anything with `after`. */
export async function startFakeVercel(t: { after(fn: () => void | Promise<void>): void }, options: FakeVercelOptions): Promise<FakeVercel> {
  const tokens = new Map<string, Token>();
  const envs = new Map<string, FakeEnvVar[]>();
  const deploys = new Map<string, Deploy>();
  const projects = new Set(options.projects ?? ['prj_fake1']);
  const mint = options.mint ?? ((n: number): string => `vcp_KboxTestFake${String(n).padStart(3, '0')}${'A'.repeat(21)}`);
  const pageSize = options.pageSize ?? 100;
  const buildPolls = options.buildPolls ?? 2;
  let nextToken = 1;
  let nextEnv = 1;
  let nextDeploy = 1;
  let failNext = false;
  let forced: number | undefined;
  let cut = false;
  const reset = (): void => {
    tokens.clear();
    envs.clear();
    deploys.clear();
    nextToken = 1;
    nextEnv = 1;
    nextDeploy = 1;
    failNext = false;
    forced = undefined;
    cut = false;
    for (const p of projects) {
      envs.set(p, []);
      deploys.set(`dpl_seed_${p}`, { project: p, name: `${p}-name`, state: 'READY', polls: 0, willFail: false });
    }
  };
  reset();

  /** Who the bearer is: the master, a project token (with its project) or nobody. */
  const who = (bearer: string): { readonly kind: 'master'; readonly token?: Token } | { readonly kind: 'project'; readonly project: string; readonly token: Token } | undefined => {
    if (bearer === options.master) return { kind: 'master' };
    for (const token of tokens.values()) {
      if (token.value === bearer) return token.projectId === undefined ? { kind: 'master', token } : { kind: 'project', project: token.projectId, token };
    }
    return undefined;
  };

  const route = (call: Call): Answer => {
    const bad = fail(403, 'forbidden', `Not authorized: ${call.bearer}`, { invalidToken: true });
    const caller = who(call.bearer);
    if (caller === undefined) return bad;
    const notAllowed = fail(403, 'forbidden', 'Not authorized');
    const isMaster = caller.kind === 'master';
    const [v, a, b, c, d, e] = call.path;
    const key = `${call.method} /${v}/${a}`;
    if (key === 'GET /v2/user') return caller.kind === 'master' ? { status: 200, body: { user: { id: 'u_fake' } } } : notAllowed;
    if (key === 'GET /v5/user' && b === 'tokens' && c === 'current') {
      const token = caller.token;
      return { status: 200, body: { token: { id: token?.id ?? 'tok_master', ...(token?.projectId === undefined ? {} : { projectId: token.projectId }) } } };
    }
    if (call.method === 'POST' && v === 'v3' && a === 'user' && b === 'tokens') {
      if (caller.kind !== 'master') return notAllowed;
      const body = asRecord(call.body);
      if (typeof body['name'] !== 'string') return fail(400, 'bad_request', 'Invalid request: missing required property `name`.');
      const projectId = body['projectId'];
      if (projectId !== undefined && (typeof projectId !== 'string' || !projects.has(projectId))) return fail(404, 'not_found', 'Project not found');
      const n = nextToken++;
      const token: Token = { id: `tok_fake${n}`, name: body['name'], value: mint(n), projectId, createdAt: n };
      tokens.set(token.id, token);
      return { status: 200, body: { bearerToken: token.value, token: { id: token.id, name: token.name, createdAt: token.createdAt } } };
    }
    if (call.method === 'GET' && v === 'v6' && a === 'user' && b === 'tokens') {
      if (caller.kind !== 'master') return notAllowed;
      const until = Number(call.query.get('until') ?? Infinity);
      const all = [...tokens.values()].filter((x) => x.createdAt < until).sort((x, y) => y.createdAt - x.createdAt);
      const page = all.slice(0, pageSize);
      const next = all.length > page.length ? (page[page.length - 1]?.createdAt ?? null) : null;
      return {
        status: 200,
        body: {
          tokens: page.map((x) => ({ id: x.id, name: x.name, createdAt: x.createdAt, ...(x.projectId === undefined ? {} : { projectId: x.projectId }) })),
          pagination: { count: page.length, next, prev: null },
        },
      };
    }
    if (call.method === 'DELETE' && v === 'v3' && a === 'user' && b === 'tokens' && c !== undefined) {
      if (caller.kind !== 'master') return notAllowed;
      if (!tokens.delete(c)) return fail(404, 'not_found', 'Token not found');
      return { status: 200, body: { tokenId: c } };
    }
    if (call.method === 'GET' && v === 'v9' && a === 'projects' && b !== undefined && c === undefined) {
      if (!projects.has(b)) return fail(404, 'not_found', 'Project not found');
      if (caller.kind === 'project' && caller.project !== b) return notAllowed;
      return { status: 200, body: { id: b, name: `${b}-name` } };
    }
    // Everything below is for a token that may manage projects: the master and a team-wide token.
    if (!isMaster) return notAllowed;
    if (call.method === 'POST' && v === 'v10' && a === 'projects' && c === 'env' && b !== undefined) {
      const list = envs.get(b);
      if (list === undefined) return fail(404, 'not_found', 'Project not found');
      const body = asRecord(call.body);
      const targets = Array.isArray(body['target']) ? body['target'].map(String) : [];
      if (typeof body['key'] !== 'string' || typeof body['value'] !== 'string' || typeof body['type'] !== 'string') return fail(400, 'bad_request', 'Invalid request: key, value and type are required.');
      if (body['type'] === 'sensitive' && targets.includes('development')) return fail(400, 'bad_request', 'Sensitive variables cannot target development.');
      const existing = list.find((x) => x.key === body['key']);
      if (existing !== undefined) {
        if (call.query.get('upsert') !== 'true') return fail(409, 'conflict', 'The variable already exists');
        existing.value = body['value'];
        existing.type = body['type'];
        existing.target = targets;
        return { status: 200, body: { created: { id: existing.id, key: existing.key, type: existing.type, target: targets }, failed: [] } };
      }
      const made: FakeEnvVar = { id: `env_fake${nextEnv++}`, key: body['key'], value: body['value'], type: body['type'], target: targets };
      list.push(made);
      return { status: 200, body: { created: { id: made.id, key: made.key, type: made.type, target: targets }, failed: [] } };
    }
    if (call.method === 'GET' && v === 'v10' && a === 'projects' && c === 'env' && b !== undefined) {
      const list = envs.get(b);
      if (list === undefined) return fail(404, 'not_found', 'Project not found');
      return { status: 200, body: { envs: list.map((x) => ({ id: x.id, key: x.key, type: x.type, target: x.target })) } };
    }
    if (call.method === 'DELETE' && v === 'v9' && a === 'projects' && c === 'env' && b !== undefined && d !== undefined) {
      const list = envs.get(b);
      const at = list?.findIndex((x) => x.id === d) ?? -1;
      if (list === undefined || at < 0) return fail(404, 'not_found', 'Environment variable not found');
      list.splice(at, 1);
      return { status: 200, body: {} };
    }
    if (call.method === 'GET' && v === 'v6' && a === 'deployments') {
      const project = call.query.get('projectId') ?? '';
      const found = [...deploys.entries()].filter(([, x]) => x.project === project && x.state === 'READY').map(([id, x]) => ({ uid: id, name: x.name, state: x.state }));
      return { status: 200, body: { deployments: found.slice(0, 1) } };
    }
    if (call.method === 'POST' && v === 'v13' && a === 'deployments') {
      const body = asRecord(call.body);
      const from = typeof body['deploymentId'] === 'string' ? deploys.get(body['deploymentId']) : undefined;
      if (typeof body['name'] !== 'string') return fail(400, 'bad_request', 'Invalid request: missing required property `name`.');
      if (from === undefined) return fail(404, 'not_found', 'Deployment not found');
      const id = `dpl_fake${nextDeploy++}`;
      deploys.set(id, { project: from.project, name: from.name, state: 'QUEUED', polls: 0, willFail: failNext });
      failNext = false;
      return { status: 200, body: { id, readyState: 'QUEUED' } };
    }
    if (call.method === 'GET' && v === 'v13' && a === 'deployments' && b !== undefined) {
      const deploy = deploys.get(b);
      if (deploy === undefined) return fail(404, 'not_found', 'Deployment not found');
      if (deploy.state === 'QUEUED' || deploy.state === 'BUILDING') {
        deploy.polls += 1;
        deploy.state = deploy.polls > buildPolls ? (deploy.willFail ? 'ERROR' : 'READY') : 'BUILDING';
      }
      return { status: 200, body: { id: b, readyState: deploy.state } };
    }
    void e;
    return fail(404, 'not_found', 'No such route');
  };

  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? '/', 'http://fake.invalid');
    const body = await readBody(req);
    const bearer = /^Bearer (.*)$/.exec(req.headers.authorization ?? '')?.[1] ?? '';
    const answer =
      forced === undefined
        ? route({ method: req.method ?? '', path: url.pathname.split('/').slice(1).map(decodeURIComponent), query: url.searchParams, bearer, body })
        : fail(forced, 'forced', `Failure while handling ${bearer}`);
    const text = JSON.stringify(answer.body);
    if (cut && answer.status === 200) {
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(text.length + 50) });
      res.write(text.slice(0, 5), () => req.socket.destroy());
      return;
    }
    res.writeHead(answer.status, { 'content-type': 'application/json' });
    res.end(text);
  };

  let server: Server = createServer((req, res) => void handle(req, res));
  let listening = false;
  const listen = (port: number): Promise<void> =>
    new Promise((resolve, reject) => {
      server = createServer((req, res) => void handle(req, res));
      server.once('error', reject);
      server.listen(port, '127.0.0.1', () => {
        server.off('error', reject);
        listening = true;
        resolve();
      });
    });
  const stop = (): Promise<void> =>
    new Promise((resolve, reject) => {
      server.closeAllConnections();
      server.close((err) => {
        listening = false;
        if (err === undefined) resolve();
        else reject(err);
      });
    });
  await listen(0);
  const port = (server.address() as AddressInfo).port;
  t.after(async () => {
    if (listening) await stop();
  });

  return {
    url: `http://127.0.0.1:${port}`,
    envs,
    tokenIds: () => [...tokens.keys()],
    tokenValue: (id) => tokens.get(id)?.value,
    tokenProject: (id) => tokens.get(id)?.projectId,
    failNextDeploy: () => void (failNext = true),
    setDown: async (down) => {
      if (down && listening) await stop();
      else if (!down && !listening) await listen(port);
    },
    forceStatus: (status) => void (forced = status),
    cutAnswers: (value) => void (cut = value),
    reset,
  };
}
