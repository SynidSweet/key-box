// KBOX-59: how every Google API-key call is made: with KBOX-41's admin token for ONE project, the stored project of the call, minted from the
// master the call was handed. The token is used inside `use` only and never leaves; a transport failure is `unreachable`; an answer comes back
// with its status and its body parsed as JSON, and its text goes no further than the parse (no error here carries Google's words, a URL or a
// value). Adapters are built with `{http, minter}` only, never RegistryDeps, so none can read a stored key's record.
import type { AdapterHttp } from '../../ports/http.ts';
import type { Lent } from '../../ports/types.ts';
import { decodeJsonBody } from '../../pure/schemas.ts';
import type { Parsed } from '../../pure/schemas.ts';
import { GoogleError } from './errors.ts';
import { numberReader } from './key-name.ts';
import { send } from './minter.ts';
import type { Minter } from './minter.ts';

export const APIKEYS_HOST = 'apikeys.googleapis.com';
export const APIKEYS_ORIGIN = `https://${APIKEYS_HOST}/v2`;
export const RESOURCE_MANAGER_V3 = 'https://cloudresourcemanager.googleapis.com/v3';

/** What every API-key adapter is built from. */
export interface AdminDeps {
  readonly http: AdapterHttp;
  readonly minter: Minter;
}

export interface AdminRequest {
  readonly method: 'GET' | 'POST' | 'DELETE';
  /** An absolute https URL built from validated parts. */
  readonly url: string;
  readonly body?: unknown;
}

export interface AdminAnswer {
  readonly status: number;
  readonly json: Parsed<unknown>;
}

/** The calls of one adapter call, all by the admin token of one project. */
export interface Admin {
  call(request: AdminRequest): Promise<AdminAnswer>;
  /** The project number of the stored project, read at most once (`GET cloudresourcemanager/v3/projects/<project>`); undefined when it could not be read. */
  readonly numberOf: () => Promise<string | undefined>;
}

export const recordOf = (json: Parsed<unknown>): Record<string, unknown> | undefined => (json.ok && typeof json.value === 'object' && json.value !== null && !Array.isArray(json.value) ? (json.value as Record<string, unknown>) : undefined);

/** Google's refusal of the request (4xx) or its failure (anything else that is no success). */
export const failureOf = (status: number): GoogleError => new GoogleError(status >= 400 && status < 500 ? 'apikeys_refused' : 'apikeys_failed', status);

const PROJECT_NUMBER = /^projects\/([0-9]{1,20})$/;

/**
 * `fn` with the calls of `project`'s admin token. One mint per adapter call, for `project` and no other: the caller passes the stored project, so
 * no answer can name the project of a call. A mint that fails throws its own code, before any call.
 */
export async function withAdmin<T>(deps: AdminDeps, master: Lent, project: string, fn: (admin: Admin) => Promise<T>): Promise<T> {
  const minted = await deps.minter.mint({ use: 'admin', at: { project } }, master);
  const call = async (request: AdminRequest): Promise<AdminAnswer> => {
    const body = request.body === undefined ? undefined : Buffer.from(JSON.stringify(request.body), 'utf8');
    const response = await minted.token.use((bytes) =>
      send(deps.http, {
        method: request.method,
        url: request.url,
        headers: { authorization: `Bearer ${Buffer.from(bytes).toString('utf8')}`, accept: 'application/json', ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
        ...(body === undefined ? {} : { body }),
      }),
    );
    return { status: response.status, json: decodeJsonBody(response.body) };
  };
  const readNumber = async (): Promise<string | undefined> => {
    try {
      const answer = await call({ method: 'GET', url: `${RESOURCE_MANAGER_V3}/projects/${project}` });
      const name = answer.status === 200 ? recordOf(answer.json)?.['name'] : undefined;
      return typeof name === 'string' ? PROJECT_NUMBER.exec(name)?.[1] : undefined;
    } catch (error) {
      // No answer: the number is unknown, and an answer that names the project by it counts for nothing (the caller then fails closed).
      if (error instanceof GoogleError && error.code === 'unreachable') return undefined;
      throw error;
    }
  };
  return fn({ call, numberOf: numberReader(readNumber) });
}
