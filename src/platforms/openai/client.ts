// KBOX-38, KBOX-14: how the OpenAI adapter talks to the platform. Every call goes through `AdapterHttp`; a key is read inside `use` and only
// ever sits in a request header. A platform failure becomes an `OpenAiError`: a fixed code and the status class, never the platform's text
// (its 401 quotes the key it was sent).
import type { AdapterHttp, HttpResponse } from '../../ports/http.ts';
import { HttpTransportError } from '../../ports/http.ts';
import type { Lent } from '../../ports/types.ts';

export const OPENAI_HOST = 'api.openai.com';

export type OpenAiFailure = 'unreachable' | 'rejected' | 'not_found' | 'rate_limited' | 'upstream_error' | 'bad_response' | 'bad_scope';

/** The adapter's one error. `status` is set when the platform answered; the message is fixed text. */
export class OpenAiError extends Error {
  readonly code: OpenAiFailure;
  readonly status: number | undefined;

  constructor(code: OpenAiFailure, status?: number) {
    super(status === undefined ? `openai: ${code}` : `openai: ${code} (${status})`);
    this.name = 'OpenAiError';
    this.code = code;
    this.status = status;
  }
}

/** The failure of a status that is not a 2xx. A 401 or 403 is the key being refused, never "unreachable". */
export function failureOfStatus(status: number): OpenAiFailure {
  if (status === 401 || status === 403) return 'rejected';
  if (status === 404) return 'not_found';
  if (status === 429) return 'rate_limited';
  return 'upstream_error';
}

const isSuccess = (status: number): boolean => status >= 200 && status < 300;

export interface Call {
  readonly method: 'GET' | 'POST' | 'DELETE';
  /** Path and query, under `https://api.openai.com`. */
  readonly target: string;
  readonly body?: Readonly<Record<string, unknown>>;
}

/** One call with `key` as the bearer. Every answer comes back whatever its status; only a transport failure throws. */
export async function send(http: AdapterHttp, key: Lent, call: Call): Promise<HttpResponse> {
  const body = call.body === undefined ? undefined : new TextEncoder().encode(JSON.stringify(call.body));
  try {
    return await key.use((bytes) =>
      http.request({
        method: call.method,
        url: `https://${OPENAI_HOST}${call.target}`,
        headers: { authorization: `Bearer ${Buffer.from(bytes).toString('utf8')}`, accept: 'application/json', ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
        ...(body === undefined ? {} : { body }),
      }),
    );
  } catch (thrown) {
    if (thrown instanceof HttpTransportError) throw new OpenAiError('unreachable');
    throw thrown;
  }
}

/** `send`, then a fixed error for any answer that is not a 2xx. */
export async function sendOk(http: AdapterHttp, key: Lent, call: Call): Promise<HttpResponse> {
  const answer = await send(http, key, call);
  if (!isSuccess(answer.status)) throw new OpenAiError(failureOfStatus(answer.status), answer.status);
  return answer;
}

/** The JSON of an answer, or `bad_response`. The text it came from is never in the error. */
export function jsonOf(answer: HttpResponse): unknown {
  try {
    return JSON.parse(Buffer.from(answer.body).toString('utf8')) as unknown;
  } catch {
    throw new OpenAiError('bad_response', answer.status);
  }
}

export type Json = Readonly<Record<string, unknown>>;

export const isRecord = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v);

/** An id of the platform as this adapter builds a path from it: no dot, no slash, no escape. */
export const ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;

export const idOf = (v: unknown): string | undefined => (typeof v === 'string' && ID.test(v) ? v : undefined);

export interface Rows {
  readonly rows: readonly Json[];
  /** Set when a page could not be read: `rows` holds what came before it. */
  readonly failure: OpenAiError | undefined;
}

/** The last answer of a list call that names a next page and the cursor to ask it with. */
function nextCursor(body: unknown, after: string | null): { readonly rows: readonly Json[]; readonly next: string | null } | undefined {
  if (!isRecord(body) || !Array.isArray(body['data']) || typeof body['has_more'] !== 'boolean') return undefined;
  const rows = (body['data'] as unknown[]).filter(isRecord);
  if (rows.length !== body['data'].length) return undefined;
  if (!body['has_more']) return { rows, next: null };
  const last = body['last_id'];
  // A platform that says "more" without moving the cursor would be read forever: that page is a failure of the listing.
  return typeof last === 'string' && last !== after ? { rows, next: last } : undefined;
}

/** Every row of a paginated list, page after page. The first page that cannot be read ends it, with its failure. */
export async function readAll(http: AdapterHttp, key: Lent, path: string): Promise<Rows> {
  const rows: Json[] = [];
  let after: string | null = null;
  for (;;) {
    const target: string = `${path}?limit=100${after === null ? '' : `&after=${encodeURIComponent(after)}`}`;
    try {
      const answer = await sendOk(http, key, { method: 'GET', target });
      const page = nextCursor(jsonOf(answer), after);
      if (page === undefined) return { rows, failure: new OpenAiError('bad_response', answer.status) };
      rows.push(...page.rows);
      if (page.next === null) return { rows, failure: undefined };
      after = page.next;
    } catch (thrown) {
      if (thrown instanceof OpenAiError) return { rows, failure: thrown };
      throw thrown;
    }
  }
}
