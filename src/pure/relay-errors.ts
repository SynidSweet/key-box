// KBOX-13, KBOX-14: the relay's failure shapes, in the one error shape of KBOX-29's frame: a closed code and its fixed text,
// never anything of the request or the upstream answer.
import { ERROR_TABLE } from './errors.ts';
import { FIXED } from './words.ts';

export type RelayErrorCode =
  | 'bad_request'
  | 'browser_call'
  | 'bad_token'
  | 'forbidden'
  | 'not_found'
  | 'bad_path'
  | 'bad_query'
  | 'method_override'
  | 'too_large'
  | 'upstream_unreachable'
  | 'upstream_timeout'
  | 'unavailable'
  | 'withheld'
  | 'internal';

export const RELAY_ERRORS: Readonly<Record<RelayErrorCode, { readonly status: number; readonly message: string }>> = {
  bad_request: ERROR_TABLE.bad_request,
  browser_call: ERROR_TABLE.browser_call,
  bad_token: { status: 401, message: 'A valid relay pass is required.' },
  forbidden: ERROR_TABLE.forbidden,
  not_found: ERROR_TABLE.not_found,
  bad_path: { status: 400, message: 'The request path is ambiguous.' },
  bad_query: { status: 400, message: 'The query string is ambiguous.' },
  method_override: { status: 400, message: 'Method override headers are not accepted.' },
  too_large: ERROR_TABLE.too_large,
  upstream_unreachable: { status: 502, message: 'The platform could not be reached.' },
  upstream_timeout: { status: 504, message: 'The platform did not answer in time.' },
  unavailable: ERROR_TABLE.unavailable,
  withheld: { status: 502, message: FIXED.withheld },
  internal: ERROR_TABLE.internal,
};

export const relayErrorBody = (code: RelayErrorCode): string => JSON.stringify({ error: { code, message: RELAY_ERRORS[code].message } });

/** An upstream 401 or 403: the status passes, the body is replaced by this fixed text (KBOX-14). */
export const upstreamRefusedBody = (): string => JSON.stringify({ error: { code: 'upstream_refused', message: FIXED.upstreamRefused } });

/** Headers every relayed response carries, errors included. */
export const FORCED_RESPONSE_HEADERS: Readonly<Record<string, string>> = {
  'x-content-type-options': 'nosniff',
  'content-security-policy': "sandbox; default-src 'none'",
  'content-disposition': 'attachment',
};

/** Headers that would make the method another one (KBOX-13 step 4). */
export const METHOD_OVERRIDE_HEADERS: readonly string[] = ['x-http-method-override', 'x-http-method', 'x-method-override'];
