// KBOX-40, KBOX-14: the one way an Anthropic adapter call is made. The key is read inside `use(...)`, goes into the `x-api-key` header and
// nowhere else; the answer is its status and parsed body, and a transport failure is the fixed `unreachable`.
import type { AdapterHttp } from '../../ports/http.ts';
import { HttpTransportError } from '../../ports/http.ts';
import type { Lent } from '../../ports/types.ts';
import { AnthropicError } from './errors.ts';

const ORIGIN = 'https://api.anthropic.com';
export const ANTHROPIC_VERSION = '2023-06-01';
/** What an HTTP header value can safely carry: printable ASCII, no space. Anything else is not a key the platform could have issued. */
const HEADER_SAFE = /^[\x21-\x7e]+$/;

export type Answer = { readonly status: number; readonly json: unknown };

/** Runs one call with `key` as the credential. `undefined` when the value cannot be a header (no call is made). */
export async function call(http: AdapterHttp, key: Lent, method: 'GET' | 'POST', pathAndQuery: string, body?: unknown): Promise<Answer | undefined> {
  return key.use(async (bytes) => {
    const text = Buffer.from(bytes).toString('utf8');
    if (!HEADER_SAFE.test(text)) return undefined;
    const headers: Record<string, string> = { 'x-api-key': text, 'anthropic-version': ANTHROPIC_VERSION, accept: 'application/json' };
    if (body !== undefined) headers['content-type'] = 'application/json';
    try {
      const answer = await http.request({ method, url: `${ORIGIN}${pathAndQuery}`, headers, ...(body === undefined ? {} : { body: Buffer.from(JSON.stringify(body)) }) });
      const parsed = parse(answer.body);
      return { status: answer.status, json: parsed.ok ? parsed.value : undefined };
    } catch (error) {
      if (error instanceof HttpTransportError) throw new AnthropicError('unreachable');
      throw new AnthropicError('http_error');
    }
  });
}

/** The body as JSON, or `ok: false` when it is not (the caller then treats the answer as having no usable body). */
function parse(body: Uint8Array): { readonly ok: true; readonly value: unknown } | { readonly ok: false } {
  try {
    return { ok: true, value: JSON.parse(Buffer.from(body).toString('utf8')) };
  } catch {
    return { ok: false };
  }
}

/** The fixed error of a status that is not the expected one: a refused key is `rejected`, any other is `http_error` (never the answer's text). */
export const failureOf = (status: number): AnthropicError => new AnthropicError(status === 401 || status === 403 ? 'rejected' : 'http_error');

/** One path segment from a platform answer: a plain name, never empty, `.` or `..`, so it cannot climb or split a path; else the fixed `bad_answer`. */
export function segment(text: string): string {
  if (text === '' || text === '.' || text === '..') throw new AnthropicError('bad_answer');
  return encodeURIComponent(text);
}
