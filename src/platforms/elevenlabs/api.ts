// KBOX-39, KBOX-14: the one way this adapter talks to ElevenLabs. The key rides in `xi-api-key` (not `Authorization`), inside `use(...)`; an
// answer is read as status and parsed JSON only, and no failure ever carries the platform's text, a header, a host or a key.
import type { AdapterHttp } from '../../ports/http.ts';
import { HttpTransportError } from '../../ports/http.ts';
import type { Lent } from '../../ports/types.ts';
import { HOST_OF } from './regions.ts';
import type { Region } from './regions.ts';

export type FailureCode = 'rejected' | 'platform_error' | 'unreachable' | 'malformed' | 'bad_scope' | 'bad_key' | 'service_account_unclear';

/** A fixed, named failure: a code and at most a status number. */
export class ElevenLabsError extends Error {
  readonly code: FailureCode;
  readonly status: number | undefined;

  constructor(code: FailureCode, status?: number) {
    super(`elevenlabs: ${code}${status === undefined ? '' : ` (${status})`}`);
    this.name = 'ElevenLabsError';
    this.code = code;
    this.status = status;
  }
}

/** What an HTTP header value can safely carry: printable ASCII, no space. Anything else is not a key the platform could have issued. */
const HEADER_SAFE = /^[\x21-\x7e]+$/;

export interface Answer {
  readonly status: number;
  /** The body as JSON, or `NOT_JSON` when it is not JSON. */
  readonly json: unknown;
}

/** The `json` of an answer whose body is not JSON: an answer with no readable content; the caller decides what that means for its call. */
export const NOT_JSON: unique symbol = Symbol('not-json');

const parseBody = (body: Uint8Array): unknown => {
  try {
    return JSON.parse(Buffer.from(body).toString('utf8')) as unknown;
  } catch {
    return NOT_JSON;
  }
};

/** One call to the region's host as `key`. Resolves with every answer; rejects only with `unreachable`. */
export async function call(http: AdapterHttp, region: Region, method: string, path: string, key: Lent, body?: unknown): Promise<Answer> {
  try {
    const answer = await key.use((bytes) => {
      const text = Buffer.from(bytes).toString('utf8');
      if (!HEADER_SAFE.test(text)) throw new ElevenLabsError('bad_key');
      return http.request({
        method,
        url: `https://${HOST_OF[region]}${path}`,
        headers: { 'xi-api-key': text, accept: 'application/json', ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
        ...(body === undefined ? {} : { body: Buffer.from(JSON.stringify(body)) }),
      });
    });
    return { status: answer.status, json: parseBody(answer.body) };
  } catch (e) {
    if (e instanceof HttpTransportError) throw new ElevenLabsError('unreachable');
    throw e;
  }
}

export const isRefusal = (answer: Answer): boolean => answer.status === 401 || answer.status === 403;

/** The one answer the probe shows for a key that is not valid: 401. A 403 is a live key refused a permission, so it says nothing about the key. */
export const isInvalidKey = (answer: Answer): boolean => answer.status === 401;

/** One path segment from a platform answer: a plain name, never empty, `.` or `..`, so it cannot climb or split a path. */
export function segment(text: string): string {
  if (text === '' || text === '.' || text === '..') throw new ElevenLabsError('bad_scope');
  return encodeURIComponent(text);
}

/** The answer's JSON when the status is 2xx; otherwise the fixed failure of its status class. */
export function expectJson(answer: Answer): unknown {
  if (answer.status >= 200 && answer.status < 300) {
    if (answer.json === NOT_JSON) throw new ElevenLabsError('malformed');
    return answer.json;
  }
  throw new ElevenLabsError(isRefusal(answer) ? 'rejected' : 'platform_error', answer.status);
}

export const isRecord = (v: unknown): v is Readonly<Record<string, unknown>> => typeof v === 'object' && v !== null && !Array.isArray(v);
