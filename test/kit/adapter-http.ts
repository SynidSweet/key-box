// An `AdapterHttp` for adapter tests: every request goes to a loopback server (a `fakePlatform()`) in place of the URL's origin, with the
// method, path, query, headers and body kept, and the original host recorded. A failure comes as the port's `HttpTransportError`.
import { request } from 'node:http';
import type { AdapterHttp, HttpRequest, HttpResponse } from '../../src/ports/http.ts';
import { HTTP_TIMEOUT_MS, HttpTransportError } from '../../src/ports/http.ts';

export interface SentRequest {
  /** The host of the URL the adapter asked for. */
  readonly originalHost: string;
  readonly method: string;
  /** Path and query, as sent. */
  readonly target: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Uint8Array;
}

export interface FakeAdapterHttp extends AdapterHttp {
  readonly sent: readonly SentRequest[];
}

/** `target` is anything with a loopback `url`: a `FakePlatform`, or a server of the test's own. */
export function adapterHttpTo(target: { readonly url: string }): FakeAdapterHttp {
  const sent: SentRequest[] = [];
  const origin = new URL(target.url);
  return {
    sent,
    request(req: HttpRequest): Promise<HttpResponse> {
      const url = new URL(req.url);
      const headers: Record<string, string> = {};
      for (const [name, value] of Object.entries(req.headers ?? {})) headers[name.toLowerCase()] = value;
      const body = req.body ?? new Uint8Array();
      sent.push({ originalHost: url.hostname, method: req.method, target: `${url.pathname}${url.search}`, headers, body });
      return new Promise((resolve, reject) => {
        const call = request(
          { host: origin.hostname, port: origin.port, method: req.method, path: `${url.pathname}${url.search}`, headers, agent: false, timeout: req.timeoutMs ?? HTTP_TIMEOUT_MS },
          (res) => {
            const chunks: Buffer[] = [];
            res.on('data', (chunk: Buffer) => void chunks.push(chunk));
            res.on('error', () => reject(new HttpTransportError('malformed')));
            res.on('close', () => {
              if (!res.complete) {
                reject(new HttpTransportError('malformed'));
                return;
              }
              const answer: Record<string, string> = {};
              for (const [name, value] of Object.entries(res.headers)) if (value !== undefined) answer[name] = Array.isArray(value) ? value.join(', ') : value;
              resolve({ status: res.statusCode ?? 0, headers: answer, body: Buffer.concat(chunks) });
            });
          },
        );
        call.on('timeout', () => {
          call.destroy();
          reject(new HttpTransportError('timeout'));
        });
        call.on('error', () => reject(new HttpTransportError('unreachable')));
        call.end(body);
      });
    },
  };
}
