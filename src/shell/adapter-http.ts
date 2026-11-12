// KBOX-23, KBOX-47, KBOX-14: the adapter HTTP client over the egress gate. Caller `adapter`; the socket comes from the gate and from
// nowhere else (no agent: `createConnection` is honoured only without one). One connection per call, never reused. No redirect is followed. A failure is an `HttpTransportError` with a fixed
// code: neither it nor anything here carries a request header, a body or a host, and nothing is written to a log or the audit.
import { request as httpRequest } from 'node:http';
import type { ClientRequest, IncomingMessage, OutgoingHttpHeaders } from 'node:http';
import type { Duplex } from 'node:stream';
import type { Scheduler } from '../ports/clock.ts';
import { HTTP_BODY_CAP_BYTES, HTTP_TIMEOUT_MS, HttpTransportError } from '../ports/http.ts';
import type { AdapterHttp, HttpFailureCode, HttpRequest, HttpResponse } from '../ports/http.ts';
import { EgressRefused } from './egress.ts';
import type { Egress } from './egress.ts';

export interface AdapterHttpDeps {
  readonly egress: Egress;
  /** Sets the call's deadline. */
  readonly scheduler: Scheduler;
  /** Defaults to `HTTP_BODY_CAP_BYTES`. */
  readonly bodyCapBytes?: number;
}

const joinedHeaders = (raw: IncomingMessage): Record<string, string> => {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(raw.headers)) {
    if (value !== undefined) out[name] = Array.isArray(value) ? value.join(', ') : value;
  }
  return out;
};

const parseUrl = (text: string): URL => {
  try {
    return new URL(text);
  } catch {
    throw new HttpTransportError('refused');
  }
};

function refusalCode(error: EgressRefused): HttpFailureCode {
  switch (error.code) {
    case 'connect_timeout':
      return 'timeout';
    case 'resolve_failed':
    case 'connect_failed':
      return 'unreachable';
    case 'bad_url':
    case 'undeclared_host':
    case 'wrong_caller':
    case 'private_address':
      return 'refused';
  }
}

export function createAdapterHttp(deps: AdapterHttpDeps): AdapterHttp {
  const cap = deps.bodyCapBytes ?? HTTP_BODY_CAP_BYTES;

  async function send(req: HttpRequest, url: URL, socket: Duplex, signal: AbortSignal, deadlinePassed: () => boolean): Promise<HttpResponse> {
    const headers: OutgoingHttpHeaders = {};
    for (const [name, value] of Object.entries(req.headers ?? {})) headers[name.toLowerCase()] = value;
    headers['host'] = url.host;
    headers['connection'] = 'close';
    if (req.body !== undefined) headers['content-length'] = String(req.body.length);
    return new Promise((resolve, reject) => {
      const fail = (code: HttpFailureCode): void => reject(new HttpTransportError(deadlinePassed() ? 'timeout' : code));
      let answered = false;
      const onResponse = (res: IncomingMessage): void => {
        answered = true;
        const chunks: Buffer[] = [];
        let size = 0;
        res.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > cap) {
            fail('too_large');
            res.destroy();
            return;
          }
          chunks.push(chunk);
        });
        res.on('error', () => fail('malformed'));
        res.on('close', () => {
          if (!res.complete) fail('malformed');
          else resolve({ status: res.statusCode ?? 0, headers: joinedHeaders(res), body: Buffer.concat(chunks) });
        });
      };
      const built = ((): { readonly ok: true; readonly call: ClientRequest } | { readonly ok: false } => {
        try {
          return { ok: true, call: httpRequest({ method: req.method, path: `${url.pathname}${url.search}`, headers, setHost: false, createConnection: () => socket, signal }, onResponse) };
        } catch {
          // node throws at once for a header name or value or a method it cannot put on the wire; its message can echo that text, so it is dropped.
          return { ok: false };
        }
      })();
      if (!built.ok) {
        fail('invalid_request');
        return;
      }
      const { call } = built;
      call.on('error', (error: NodeJS.ErrnoException) => fail(answered ? 'malformed' : error.code?.startsWith('HPE_') === true ? 'malformed' : 'unreachable'));
      call.end(req.body);
    });
  }

  return {
    async request(req) {
      const url = parseUrl(req.url);
      const abort = new AbortController();
      let passed = false;
      const cancel = deps.scheduler.after(req.timeoutMs ?? HTTP_TIMEOUT_MS, () => {
        passed = true;
        abort.abort();
      });
      let socket: Duplex | undefined;
      try {
        try {
          socket = await deps.egress.open('adapter', url, abort.signal);
        } catch (error) {
          // The port rejects only with HttpTransportError: a gate failure that is not a refusal is still "no connection".
          throw new HttpTransportError(passed ? 'timeout' : error instanceof EgressRefused ? refusalCode(error) : 'unreachable');
        }
        return await send(req, url, socket, abort.signal, () => passed);
      } finally {
        cancel();
        socket?.destroy();
      }
    },
  };
}
