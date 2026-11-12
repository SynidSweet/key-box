// KBOX-36, KBOX-47: the one way the adapter reaches api.vercel.com: a bearer call through `AdapterHttp`. The master key is read inside
// `use`, goes into one request and is never kept. Every status is an answer here; only a transport failure throws, as a fixed `VercelError`.
import type { AdapterHttp } from '../../ports/http.ts';
import { HttpTransportError } from '../../ports/http.ts';
import type { Lent } from '../../ports/types.ts';
import { VercelError } from './errors.ts';

export const VERCEL_HOST = 'api.vercel.com';
const ORIGIN = `https://${VERCEL_HOST}`;

export interface ApiAnswer {
  readonly status: number;
  /** The body parsed as JSON; `NOT_JSON` when it is not JSON. */
  readonly json: unknown;
}

export interface ApiCall {
  readonly method: 'GET' | 'POST' | 'DELETE';
  /** Path with its segments already encoded (`segment`), starting with `/`. */
  readonly path: string;
  /** Already encoded, without the `?`. */
  readonly query?: string;
  readonly body?: Uint8Array;
}

export interface VercelApi {
  call(req: ApiCall, key: Lent): Promise<ApiAnswer>;
}

/** One path segment of text from a scope, a target or a platform answer: a plain name only, so it can never climb or split a path. */
export function segment(text: string): string {
  if (text === '' || text === '.' || text === '..' || text.length > 256) throw new VercelError('bad_scope');
  return encodeURIComponent(text);
}

/** What `json` holds when the body is not JSON; every narrowing helper below reads it as no record and no text. */
export const NOT_JSON = Symbol('not json');

const parseJson = (body: Uint8Array): unknown => {
  try {
    return JSON.parse(Buffer.from(body).toString('utf8')) as unknown;
  } catch {
    return NOT_JSON;
  }
};

export function createVercelApi(http: AdapterHttp): VercelApi {
  return {
    call: (req, key) =>
      key.use(async (bytes) => {
        const headers: Record<string, string> = { authorization: `Bearer ${Buffer.from(bytes).toString('utf8')}` };
        if (req.body !== undefined) headers['content-type'] = 'application/json';
        try {
          const answer = await http.request({ method: req.method, url: `${ORIGIN}${req.path}${req.query === undefined ? '' : `?${req.query}`}`, headers, ...(req.body === undefined ? {} : { body: req.body }) });
          return { status: answer.status, json: parseJson(answer.body) };
        } catch (error) {
          if (!(error instanceof HttpTransportError)) throw error;
          throw new VercelError(error.code === 'malformed' ? 'malformed' : 'unreachable');
        }
      }),
  };
}

/** Narrowing helpers for what an answer carries: the edge turns `unknown` into typed values or `undefined`. */
export const recordOf = (value: unknown): Readonly<Record<string, unknown>> | undefined => (typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined);
export const textOf = (value: unknown): string | undefined => (typeof value === 'string' && value !== '' ? value : undefined);
export const encodeJson = (value: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(value));
