// KBOX-23, KBOX-47: how an adapter reaches its platform. One request, one answer. The shell implementation goes through the egress
// gate as caller `adapter`; core never opens a socket any other way. A 3xx is an answer (redirects are never followed) and so is every
// other status; only a transport failure is an error, and it carries a fixed code, never a header value, a body or a host (KBOX-14).

/** Default deadline for one call, from the request being made to its last body byte. */
export const HTTP_TIMEOUT_MS = 30_000;
/** Default cap on an answer's body. An adapter's answers are small JSON documents; a longer one is a transport failure. */
export const HTTP_BODY_CAP_BYTES = 8 * 1024 * 1024;

export interface HttpRequest {
  readonly method: string;
  /** Absolute `https` URL on the default port. */
  readonly url: string;
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: Uint8Array;
  /** Milliseconds; `HTTP_TIMEOUT_MS` when absent. */
  readonly timeoutMs?: number;
}

export interface HttpResponse {
  readonly status: number;
  /** Lower-case names; a name sent more than once is joined with `, `. */
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Uint8Array;
}

/**
 * Why no answer came, for the adapter to map to `unreachable`:
 * - `refused`: the egress gate or the URL check refused the call (host not declared, not https, bad URL);
 * - `unreachable`: resolving or connecting failed, or the connection broke before an answer;
 * - `timeout`: the deadline passed;
 * - `too_large`: the body went over the cap;
 * - `malformed`: the answer was not valid HTTP or was cut short.
 */
export type HttpFailureCode = 'refused' | 'unreachable' | 'timeout' | 'too_large' | 'malformed';

export class HttpTransportError extends Error {
  readonly code: HttpFailureCode;

  constructor(code: HttpFailureCode) {
    super(`adapter http: ${code}`);
    this.name = 'HttpTransportError';
    this.code = code;
  }
}

export interface AdapterHttp {
  /** Resolves with every answer that arrived whole, whatever its status; rejects only with `HttpTransportError`. */
  request(req: HttpRequest): Promise<HttpResponse>;
}

/** The client of a process that makes no adapter calls (kb-relay): every call is `refused`. */
export const refusingAdapterHttp: AdapterHttp = {
  request: () => Promise.reject(new HttpTransportError('refused')),
};
