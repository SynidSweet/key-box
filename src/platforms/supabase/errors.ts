// KBOX-14: every failure of this adapter is one of these fixed codes. The platform's own message text (it can quote a key) never
// reaches an error, a cause or a log: the code names the status class and nothing else.
export type SupabaseErrorCode =
  | 'unreachable'
  | 'rejected'
  | 'rate_limited'
  | 'server'
  | 'bad_request'
  | 'bad_answer'
  | 'bad_project'
  | 'bad_scope'
  | 'no_key_value'
  | 'no_key_value_not_cleaned'
  | 'bad_password'
  | 'bad_secret_name';

export class SupabaseError extends Error {
  readonly code: SupabaseErrorCode;

  constructor(code: SupabaseErrorCode) {
    super(`supabase: ${code}`);
    this.name = 'SupabaseError';
    this.code = code;
  }
}

/** The error of a status that is not the one the call expects: auth refusals, rate limit, server trouble, any other 4xx. */
export function failureOf(status: number): SupabaseError {
  if (status === 401 || status === 403) return new SupabaseError('rejected');
  if (status === 429) return new SupabaseError('rate_limited');
  if (status >= 500) return new SupabaseError('server');
  return new SupabaseError('bad_request');
}
