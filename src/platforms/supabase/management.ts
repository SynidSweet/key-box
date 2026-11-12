// The one way this adapter calls the Supabase Management API: `https://api.supabase.com`, the master (a personal access token) as the
// bearer, every network call through `deps.http`. The master is used inside `use(...)` only. A transport failure is `unreachable`; an
// answer is returned whatever its status, with its body parsed when it is JSON, and its text goes no further than the parse.
import type { AdapterHttp } from '../../ports/http.ts';
import { HttpTransportError } from '../../ports/http.ts';
import type { Lent } from '../../ports/types.ts';
import type { Parsed } from '../../pure/schemas.ts';
import { SupabaseError } from './errors.ts';

export const MANAGEMENT_HOST = 'api.supabase.com';

export interface Call {
  readonly method: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  /** Absolute path under the host, built from validated parts only. */
  readonly path: string;
  /** Query as `name=value` pairs of validated words. */
  readonly query?: Readonly<Record<string, string>>;
  readonly body?: unknown;
}

export interface Answer {
  readonly status: number;
  readonly json: Parsed<unknown>;
}

const NOT_JSON: Parsed<unknown> = { ok: false };

function parseJson(bytes: Uint8Array): Parsed<unknown> {
  try {
    return { ok: true, value: JSON.parse(Buffer.from(bytes).toString('utf8')) as unknown };
  } catch {
    return NOT_JSON;
  }
}

export type Management = (master: Lent, call: Call) => Promise<Answer>;

export function createManagement(http: AdapterHttp): Management {
  return async (master, call) => {
    const query = call.query === undefined ? '' : `?${new URLSearchParams(call.query).toString()}`;
    const url = `https://${MANAGEMENT_HOST}${call.path}${query}`;
    const body = call.body === undefined ? undefined : new TextEncoder().encode(JSON.stringify(call.body));
    try {
      const answer = await master.use((token) =>
        http.request({
          method: call.method,
          url,
          headers: { authorization: `Bearer ${Buffer.from(token).toString('utf8')}`, accept: 'application/json', ...(body === undefined ? {} : { 'content-type': 'application/json', 'content-length': String(body.length) }) },
          ...(body === undefined ? {} : { body }),
        }),
      );
      return { status: answer.status, json: parseJson(answer.body) };
    } catch (error) {
      if (error instanceof HttpTransportError) throw new SupabaseError('unreachable');
      throw error;
    }
  };
}

export const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
