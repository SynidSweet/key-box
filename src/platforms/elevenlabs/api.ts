// KBOX-39, KBOX-14: the one way this adapter talks to ElevenLabs. The key rides in `xi-api-key` (not `Authorization`), inside `use(...)`; an
// answer is read as status and parsed JSON only, and no failure ever carries the platform's text, a header, a host or a key.
import type { AdapterHttp } from '../../ports/http.ts';
import { HttpTransportError } from '../../ports/http.ts';
import type { Lent } from '../../ports/types.ts';
import { HOST_OF } from './regions.ts';
import type { Region } from './regions.ts';

export type FailureCode = 'rejected' | 'platform_error' | 'unreachable' | 'malformed' | 'bad_scope' | 'service_account_unclear';

/** A fixed, named failure: a code and at most a status number. */
export class ElevenLabsError extends Error {
  readonly code: FailureCode;

  constructor(code: FailureCode, status?: number) {
    super(`elevenlabs: ${code}${status === undefined ? '' : ` (${status})`}`);
    this.name = 'ElevenLabsError';
    this.code = code;
  }
}

export interface Answer {
  readonly status: number;
  /** The body as JSON, or undefined when it is not JSON. */
  readonly json: unknown;
}

const parseBody = (body: Uint8Array): unknown => {
  try {
    return JSON.parse(Buffer.from(body).toString('utf8')) as unknown;
  } catch {
    // A body that is not JSON is an answer with no readable content; the caller decides what that means for its call.
    return undefined;
  }
};

/** One call to the region's host as `key`. Resolves with every answer; rejects only with `unreachable`. */
export async function call(http: AdapterHttp, region: Region, method: string, path: string, key: Lent, body?: unknown): Promise<Answer> {
  try {
    const answer = await key.use((bytes) =>
      http.request({
        method,
        url: `https://${HOST_OF[region]}${path}`,
        headers: { 'xi-api-key': Buffer.from(bytes).toString('utf8'), accept: 'application/json', ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
        ...(body === undefined ? {} : { body: Buffer.from(JSON.stringify(body)) }),
      }),
    );
    return { status: answer.status, json: parseBody(answer.body) };
  } catch (e) {
    if (e instanceof HttpTransportError) throw new ElevenLabsError('unreachable');
    throw e;
  }
}

export const isRefusal = (answer: Answer): boolean => answer.status === 401 || answer.status === 403;

/** The answer's JSON when the status is 2xx; otherwise the fixed failure of its status class. */
export function expectJson(answer: Answer): unknown {
  if (answer.status >= 200 && answer.status < 300) {
    if (answer.json === undefined) throw new ElevenLabsError('malformed');
    return answer.json;
  }
  throw new ElevenLabsError(isRefusal(answer) ? 'rejected' : 'platform_error', answer.status);
}

export const isRecord = (v: unknown): v is Readonly<Record<string, unknown>> => typeof v === 'object' && v !== null && !Array.isArray(v);
