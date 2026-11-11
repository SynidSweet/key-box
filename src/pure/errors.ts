// KBOX-29 and KBOX-4: every failure the box shows is a closed code with a fixed text. No error here ever carries
// request text, an adapter's own message, a cause, a path or a value.

export const ERROR_CODES = [
  'bad_request',
  'browser_call',
  'unauthorized',
  'forbidden',
  'not_found',
  'slot_taken',
  'conflict',
  'too_large',
  'unsupported_media',
  'rejected',
  'unavailable',
  'internal',
] as const;
export type ErrorCode = (typeof ERROR_CODES)[number];

export const ERROR_TABLE: Readonly<Record<ErrorCode, { readonly status: number; readonly message: string }>> = {
  bad_request: { status: 400, message: 'The request could not be understood.' },
  browser_call: { status: 403, message: 'Browser calls are not accepted.' },
  unauthorized: { status: 401, message: 'A valid token is required.' },
  forbidden: { status: 403, message: 'This token may not do that.' },
  not_found: { status: 404, message: 'There is nothing here.' },
  slot_taken: { status: 409, message: 'That slot is already taken.' },
  conflict: { status: 409, message: 'That conflicts with the current state.' },
  too_large: { status: 413, message: 'The request body is too large.' },
  unsupported_media: { status: 415, message: 'The request body must be application/json.' },
  rejected: { status: 422, message: 'The value did not pass its checks.' },
  unavailable: { status: 503, message: 'A part of the box is not available.' },
  internal: { status: 500, message: 'Something went wrong inside the box.' },
};

/** A names-only reason that rides along with a code, such as `epoch_changed`. */
export const DETAIL_CODE = /^[a-z][a-z0-9_]{0,63}$/;

export interface ErrorBody {
  readonly error: {
    readonly code: ErrorCode;
    readonly message: string;
    readonly detail?: { readonly code: string };
  };
}

/** A failure with a code of the table. The message is the table's fixed text and nothing else. */
export class ApiError extends Error {
  readonly code: ErrorCode;
  readonly detailCode: string | undefined;

  constructor(code: ErrorCode, detailCode?: string) {
    super(ERROR_TABLE[code].message);
    if (detailCode !== undefined && !DETAIL_CODE.test(detailCode)) throw new RangeError('an error detail code is a lower-case snake_case name');
    this.name = 'ApiError';
    this.code = code;
    this.detailCode = detailCode;
  }
}

/** An adapter call failed or answered something unreadable. Carries the platform's HTTP status when it gave one. */
export class AdapterError extends Error {
  readonly reason: 'call_failed' | 'bad_response';
  readonly status: number | undefined;

  constructor(reason: 'call_failed' | 'bad_response', status?: number) {
    super(
      reason === 'bad_response'
        ? 'adapter response was not understood'
        : status === undefined
          ? 'adapter call failed'
          : `adapter call failed with status ${status}`,
    );
    this.name = 'AdapterError';
    this.reason = reason;
    this.status = status;
  }
}

export type VaultFailure = 'bad_ref' | 'unknown_key' | 'write_failed' | 'read_failed';

/** The vault could not do what was asked. `errno` is the OS code (EACCES, ENOSPC) when there was one. */
export class VaultError extends Error {
  readonly failure: VaultFailure;
  readonly errno: string | undefined;

  constructor(failure: VaultFailure, errno?: string) {
    const text: Record<VaultFailure, string> = {
      bad_ref: 'vault ref refused',
      unknown_key: 'vault key unknown',
      write_failed: 'vault write failed',
      read_failed: 'vault read failed',
    };
    super(errno === undefined ? text[failure] : `${text[failure]} (${errno})`);
    this.name = 'VaultError';
    this.failure = failure;
    this.errno = errno;
  }
}

/** The audit or event writer refused an entry that carries a member or text outside its closed shape. */
export class WriteRefused extends Error {
  constructor() {
    super('write refused: the entry is not in its closed shape');
    this.name = 'WriteRefused';
  }
}

const OS_ERROR_CODE = /^E[A-Z0-9]{2,15}$/;

/** The OS error code of a thrown filesystem error, or undefined. Only a code of the OS's own shape is kept. */
export function osErrorCode(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null || !('code' in error)) return undefined;
  const code = error.code;
  return typeof code === 'string' && OS_ERROR_CODE.test(code) ? code : undefined;
}

const httpStatusOf = (thrown: unknown): number | undefined => {
  if (typeof thrown !== 'object' || thrown === null || !('status' in thrown)) return undefined;
  const status = thrown.status;
  return typeof status === 'number' && Number.isInteger(status) && status >= 100 && status <= 599 ? status : undefined;
};

/** Runs one adapter call. Anything it throws is replaced by a fixed text plus the platform's HTTP status (KREQ-12 pattern). */
export async function wrapAdapterCall<T>(call: () => Promise<T>): Promise<T> {
  try {
    return await call();
  } catch (thrown) {
    if (thrown instanceof AdapterError) throw thrown;
    throw new AdapterError('call_failed', httpStatusOf(thrown));
  }
}

/** Why a 500 happened, as a code the audit log can hold. */
export type InternalCause = 'adapter_failed' | 'adapter_bad_response' | 'vault_failed' | 'write_refused' | 'unhandled';

export interface MappedError {
  readonly code: ErrorCode;
  readonly detailCode: string | undefined;
  /** Set for `internal` only. */
  readonly cause: InternalCause | undefined;
}

/** Turns anything that was thrown into the code to answer with; unknown things become `internal`. */
export function mapError(thrown: unknown): MappedError {
  if (thrown instanceof ApiError) return { code: thrown.code, detailCode: thrown.detailCode, cause: undefined };
  const internal = (cause: InternalCause): MappedError => ({ code: 'internal', detailCode: undefined, cause });
  if (thrown instanceof AdapterError) return internal(thrown.reason === 'bad_response' ? 'adapter_bad_response' : 'adapter_failed');
  if (thrown instanceof VaultError) return internal('vault_failed');
  if (thrown instanceof WriteRefused) return internal('write_refused');
  return internal('unhandled');
}

export function errorBody(code: ErrorCode, detailCode?: string): ErrorBody {
  const base = { code, message: ERROR_TABLE[code].message };
  return { error: detailCode === undefined ? base : { ...base, detail: { code: detailCode } } };
}
