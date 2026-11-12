// KBOX-14, KBOX-36: every failure of a Vercel call is one of these fixed names. The platform's own message, a header, a body and the
// transport's error never travel with it (a 403 can quote the presented token), and no `cause` is kept.

export const VERCEL_FAILURES = [
  /** No answer: refused, unreachable, timed out, too large. */
  'unreachable',
  /** The platform refused the key (401, 403). */
  'rejected',
  /** Another 4xx: the call was wrong or the platform is rate limiting. */
  'client_error',
  /** A 5xx. */
  'server_error',
  /** An answer that is cut short, is not what the call expects, or is a status no call expects. */
  'malformed',
  /** A scope or an id that is not a plain name: refused before any call. */
  'bad_scope',
  /** A key whose bytes cannot be an HTTP header value: refused before any call. */
  'bad_key',
  /** A redeploy of a project with no ready production deployment to start from. */
  'no_deployment',
] as const;
export type VercelFailure = (typeof VERCEL_FAILURES)[number];

export class VercelError extends Error {
  readonly code: VercelFailure;

  constructor(code: VercelFailure) {
    super(`vercel: ${code}`);
    this.name = 'VercelError';
    this.code = code;
  }
}

/** The failure a non-success status stands for. A 2xx is no failure; any other class is `malformed` (nothing here follows a redirect). */
export function failureOfStatus(status: number): VercelFailure {
  if (status === 401 || status === 403) return 'rejected';
  if (status >= 400 && status < 500) return 'client_error';
  if (status >= 500 && status < 600) return 'server_error';
  return 'malformed';
}

export const isSuccess = (status: number): boolean => status >= 200 && status < 300;

/** Throws the fixed failure of a non-success status; returns on 2xx. */
export function requireSuccess(status: number): void {
  if (!isSuccess(status)) throw new VercelError(failureOfStatus(status));
}
