// KBOX-29, KBOX-10, KBOX-43: the frame every route of the machine API sits in. It reads a request at the edge into typed
// values, answers in the one error shape, and writes one audit row per request. Nothing of a request is ever echoed.
import { chmodSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Audit } from '../ports/audit.ts';
import type { Clock } from '../ports/clock.ts';
import type { TokenScope, TokenStore } from '../ports/meta.ts';
import type { Random } from '../ports/random.ts';
import { parseClientAddress } from '../pure/address.ts';
import type { ClientAddress } from '../pure/address.ts';
import { ApiError, ERROR_TABLE, errorBody, mapError } from '../pure/errors.ts';
import type { ErrorCode, InternalCause } from '../pure/errors.ts';
import { HTTP_METHODS, decodeJsonBody, parseObject, parseQuery } from '../pure/schemas.ts';
import type { Infer, Parsed, Schema } from '../pure/schemas.ts';
import { findToken, parseBearer } from '../pure/tokens.ts';

/** A mechanical safety bound for parsing, not a policy limit (KBOX-29). */
const BODY_LIMIT = 64 * 1024;
const JSON_TYPE = /^application\/json(?:\s*;\s*charset=utf-?8)?$/i;

// --- routes -------------------------------------------------------------------------------------------------------------

/** A JSON answer, or (phone pages and assets) raw bytes of a fixed type. `headers` are added to the frame's own (Set-Cookie). */
export type Reply =
  | { readonly status?: number; readonly json: unknown; readonly headers?: Readonly<Record<string, string>> }
  | { readonly status?: number; readonly raw: { readonly type: string; readonly bytes: Uint8Array }; readonly headers?: Readonly<Record<string, string>> };

export interface RouteInput {
  /** The token's label on the machine API; `box` on a phone route. */
  readonly actor: string;
  readonly source: ClientAddress;
  readonly abort: AbortSignal;
  readonly query: URLSearchParams;
  /** The parsed JSON body; undefined for a route that takes none. */
  readonly body: unknown;
  /** The values of the route's `:name` path segments. */
  readonly params: Readonly<Record<string, string>>;
  /** The raw Cookie header of a phone request (the view session). The machine API refuses any cookie before a route runs. */
  readonly cookie: string | undefined;
  /** The raw body of a route that declares `rawBody`. */
  readonly raw?: Uint8Array;
}

export interface Route {
  readonly method: string;
  /** Exact segments, or `:name` for one segment of `[A-Za-z0-9_-]{1,128}`. */
  readonly path: string;
  /** `api` is the machine API (bearer token, no browser); `phone` is a page or phone route (no bearer token). */
  readonly surface: 'api' | 'phone';
  readonly scope: TokenScope | undefined;
  /** An `api` route that takes no token: only the unauthenticated enrol routes (KBOX-53). */
  readonly open: boolean;
  readonly takesBody: boolean;
  /** A body of raw bytes of exactly this media type, up to `limit` bytes, instead of JSON (the update tar, KBOX-6). */
  readonly rawBody?: { readonly type: string; readonly limit: number };
  run(input: RouteInput): Promise<Reply> | Reply;
}

type Empty = Readonly<Record<never, never>>;

interface Context<Q, B> {
  readonly actor: string;
  readonly source: ClientAddress;
  readonly abort: AbortSignal;
  readonly query: Q;
  readonly body: B;
  readonly params: Readonly<Record<string, string>>;
  readonly cookie: string | undefined;
}

export interface RouteSpec<Q extends Schema, B extends Schema> {
  readonly method: string;
  readonly path: string;
  readonly surface: 'api' | 'phone';
  /** Required on an `api` route unless it is `open`. */
  readonly scope?: TokenScope;
  readonly open?: true;
  readonly query?: Q;
  readonly body?: B;
  handle(context: Context<Infer<Q>, Infer<B>>): Promise<Reply> | Reply;
}

/** A route whose query and body are parsed into the given closed schemas before the handler sees them. */
export function route<Q extends Schema = Empty, B extends Schema = Empty>(spec: RouteSpec<Q, B>): Route {
  if (spec.surface === 'api' && (spec.scope === undefined) === (spec.open === undefined)) throw new RangeError('an api route names the token scope it needs, or is open');
  return {
    method: spec.method,
    path: spec.path,
    surface: spec.surface,
    scope: spec.scope,
    open: spec.open === true,
    takesBody: spec.body !== undefined,
    run: (input) => {
      const query = parseQuery((spec.query ?? {}) as Q, input.query);
      const body = spec.body === undefined ? { ok: true as const, value: {} as Infer<B> } : parseObject(spec.body, input.body);
      if (!query.ok || !body.ok) throw new ApiError('bad_request');
      return spec.handle({ actor: input.actor, source: input.source, abort: input.abort, query: query.value, body: body.value, params: input.params, cookie: input.cookie });
    },
  };
}

/** A route with a nested JSON body: `parse` turns the raw body into its closed type at the edge, or refuses it. */
export function parsedRoute<Q extends Schema, T>(spec: Omit<RouteSpec<Q, Empty>, 'body' | 'handle'> & { readonly parse: (raw: unknown) => Parsed<T>; handle(context: Context<Infer<Q>, T>): Promise<Reply> | Reply }): Route {
  const base = route<Q>({ ...spec, handle: () => ({ json: null }) });
  return {
    ...base,
    takesBody: true,
    run: (input) => {
      const query = parseQuery((spec.query ?? {}) as Q, input.query);
      const body = spec.parse(input.body);
      if (!query.ok || !body.ok) throw new ApiError('bad_request');
      return spec.handle({ actor: input.actor, source: input.source, abort: input.abort, query: query.value, body: body.value, params: input.params, cookie: input.cookie });
    },
  };
}

const SEGMENT = /^[A-Za-z0-9_-]{1,128}$/;

/** The `:name` values when `pathname` matches the route's pattern; undefined otherwise. */
function matchPath(pattern: string, pathname: string): Record<string, string> | undefined {
  const want = pattern.split('/');
  const got = pathname.split('/');
  if (want.length !== got.length) return undefined;
  const params: Record<string, string> = {};
  for (const [i, w] of want.entries()) {
    const g = got[i] ?? '';
    if (w.startsWith(':')) {
      if (!SEGMENT.test(g)) return undefined;
      params[w.slice(1)] = g;
    } else if (w !== g) return undefined;
  }
  return params;
}

// --- the server --------------------------------------------------------------------------------------------------------

export interface ApiServerDeps {
  readonly routes: readonly Route[];
  readonly tokens: TokenStore;
  readonly audit: Audit;
  readonly random: Random;
  readonly clock: Clock;
  /** A fixed code for the journal when the frame itself could not do its job. Never text of a request. */
  readonly journal: (code: string) => void;
}

export interface ApiServer {
  listen(socketPath: string): Promise<void>;
  /** Answers every pending request `unavailable`, then closes. */
  stop(): Promise<void>;
}

interface Trace {
  actor: string;
  ref: string;
  source: string | undefined;
}

interface Outcome {
  readonly status: number;
  readonly body: unknown;
  readonly raw: { readonly type: string; readonly bytes: Uint8Array } | undefined;
  readonly headers: Readonly<Record<string, string>>;
  readonly code: ErrorCode | undefined;
  readonly cause: InternalCause | undefined;
}

const failed = (thrown: unknown): Outcome => {
  const mapped = mapError(thrown);
  return { status: ERROR_TABLE[mapped.code].status, body: errorBody(mapped.code, mapped.detail), raw: undefined, headers: {}, code: mapped.code, cause: mapped.cause };
};

const header = (req: IncomingMessage, name: string): string | undefined => {
  const value = req.headers[name];
  return Array.isArray(value) ? value.join(', ') : value;
};

async function readBody(req: IncomingMessage, limit: number): Promise<Uint8Array> {
  const declared = header(req, 'content-length');
  if (declared !== undefined) {
    if (!/^\d{1,15}$/.test(declared)) throw new ApiError('bad_request');
    if (Number(declared) > limit) throw new ApiError('too_large');
  }
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    for await (const chunk of req) {
      const piece = chunk as Buffer;
      total += piece.length;
      if (total > limit) break;
      chunks.push(piece);
    }
  } catch {
    throw new ApiError('bad_request');
  }
  if (total > limit) throw new ApiError('too_large');
  return Buffer.concat(chunks);
}

export function createApiServer(deps: ApiServerDeps): ApiServer {
  const stopping = new AbortController();
  const inflight = new Set<Promise<void>>();

  const authenticate = (req: IncomingMessage, trace: Trace, source: ClientAddress): TokenScope => {
    const bearer = parseBearer(header(req, 'authorization'));
    if (bearer.kind !== 'token') throw new ApiError('unauthorized');
    const record = findToken(deps.tokens.tokens(), bearer.token);
    if (record === undefined || record.revoked) throw new ApiError('unauthorized');
    trace.actor = record.label;
    deps.tokens.recordUse(record.label, source.network);
    return record.scope;
  };

  async function dispatch(req: IncomingMessage, trace: Trace, abort: AbortSignal): Promise<Outcome> {
    const target = req.url ?? '';
    if (!target.startsWith('/')) throw new ApiError('bad_request');
    let url: URL;
    try {
      url = new URL(target, 'http://box.invalid');
    } catch {
      throw new ApiError('bad_request');
    }
    const surface = url.pathname === '/api' || url.pathname.startsWith('/api/') ? 'api' : 'phone';
    if (surface === 'api' && (req.headers.origin !== undefined || req.headers.cookie !== undefined)) throw new ApiError('browser_call');
    const source = parseClientAddress(header(req, 'x-kb-client-ip'));
    if (source === undefined) throw new ApiError('bad_request');
    trace.source = source.address;

    const matching = (r: Route): boolean => r.surface === surface && r.method === req.method && matchPath(r.path, url.pathname) !== undefined;
    let scope: TokenScope | undefined;
    if (surface === 'api') {
      const openRoute = deps.routes.find((r) => r.open && matching(r));
      if (openRoute === undefined) scope = authenticate(req, trace, source);
      else if (req.headers.authorization !== undefined) throw new ApiError('forbidden');
    } else if (req.headers.authorization !== undefined) throw new ApiError('forbidden');

    const found = deps.routes.find(matching);
    if (found === undefined) throw new ApiError('not_found');
    const params = matchPath(found.path, url.pathname) ?? {};
    trace.ref = found.path;
    if (found.scope !== undefined && found.scope !== scope) throw new ApiError('forbidden');

    const bytes = await readBody(req, found.rawBody?.limit ?? BODY_LIMIT);
    let body: unknown;
    let raw: Uint8Array | undefined;
    if (found.rawBody !== undefined) {
      // A route that takes raw bytes of one fixed type (the update tar, KBOX-6) gets them as they came, bounded by its limit.
      if ((header(req, 'content-type') ?? '').toLowerCase() !== found.rawBody.type) throw new ApiError('unsupported_media');
      raw = bytes;
    } else if (found.takesBody) {
      if (!JSON_TYPE.test(header(req, 'content-type') ?? '')) throw new ApiError('unsupported_media');
      const decoded = decodeJsonBody(bytes);
      if (!decoded.ok) throw new ApiError('bad_request');
      body = decoded.value;
    } else if (bytes.length > 0) {
      throw new ApiError('bad_request');
    }
    const cookie = surface === 'phone' ? header(req, 'cookie') : undefined;
    const reply = await found.run({ actor: trace.actor, source, abort, query: url.searchParams, body, params, cookie, ...(raw === undefined ? {} : { raw }) });
    const common = { status: reply.status ?? 200, code: undefined, cause: undefined, headers: reply.headers ?? {} };
    return 'raw' in reply ? { ...common, body: undefined, raw: reply.raw } : { ...common, body: reply.json, raw: undefined };
  }

  /** One audit row per request. If the row cannot be written the answer is `internal`, and the journal gets a fixed code. */
  const record = (req: IncomingMessage, outcome: Outcome, trace: Trace, requestId: string): Outcome => {
    const method = HTTP_METHODS.find((m) => m === req.method) ?? 'OTHER';
    try {
      deps.audit.append({
        actor: trace.actor,
        action: 'api.request',
        subject: trace.ref,
        at: deps.clock.now(),
        detail: {
          request_id: requestId,
          method,
          status: outcome.status,
          ...(outcome.code === undefined ? {} : { code: outcome.code }),
          ...(outcome.cause === undefined ? {} : { cause: outcome.cause }),
          ...(trace.source === undefined ? {} : { source: trace.source }),
        },
      });
      return outcome;
    } catch {
      deps.journal('audit_write_failed');
      return failed(new ApiError('internal'));
    }
  };

  const send = (res: ServerResponse, outcome: Outcome, requestId: string): void => {
    const payload = outcome.raw === undefined ? Buffer.from(JSON.stringify(outcome.body), 'utf8') : Buffer.from(outcome.raw.bytes);
    res.writeHead(outcome.status, {
      ...outcome.headers,
      'content-type': outcome.raw === undefined ? 'application/json; charset=utf-8' : outcome.raw.type,
      'content-length': payload.length,
      'cache-control': 'no-store',
      'kb-api-version': '1',
      'kb-request-id': requestId,
      ...(outcome.code === 'too_large' ? { connection: 'close' } : {}),
    });
    res.end(payload);
  };

  async function serve(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const requestId = `req_${Buffer.from(deps.random.bytes(9)).toString('base64url')}`;
    const trace: Trace = { actor: 'box', ref: 'unmatched', source: undefined };
    const gone = new AbortController();
    res.on('close', () => {
      if (!res.writableFinished) gone.abort();
    });
    const outcome = await dispatch(req, trace, AbortSignal.any([stopping.signal, gone.signal])).catch(failed);
    send(res, record(req, outcome, trace, requestId), requestId);
  }

  const server = createServer((req, res) => {
    const job = serve(req, res);
    inflight.add(job);
    void job.finally(() => inflight.delete(job));
  });

  return {
    async listen(socketPath: string): Promise<void> {
      rmSync(socketPath, { force: true });
      await new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        server.listen(socketPath, () => {
          server.off('error', reject);
          resolve();
        });
      });
      // Group read and write, nothing for others, whatever the umask: the group on the directory is the access check (KBOX-45).
      chmodSync(socketPath, 0o660);
    },
    async stop(): Promise<void> {
      stopping.abort();
      await Promise.allSettled([...inflight]);
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error === undefined ? resolve() : reject(error)));
        server.closeAllConnections();
      });
    },
  };
}
