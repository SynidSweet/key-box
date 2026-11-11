// KBOX-22, KBOX-47: the one outside call of Web Push, a single POST to a push service. It goes through the egress gate like every
// other outbound request of the box: the host must be one the list gives to push, the name is resolved once, a private address is
// refused, and the connection goes to the address the gate chose. Redirects are not followed: the endpoint was checked against
// the host list at subscription, and a Location is not.
import { request as httpRequest } from 'node:http';
import type { OutgoingHttpHeaders } from 'node:http';
import type { PushTransport } from '../ports/push.ts';
import type { Egress } from './egress.ts';

export function createHttpPushTransport(egress: Egress): PushTransport {
  return {
    async post(endpoint: URL, headers: Readonly<Record<string, string>>, body: Uint8Array, signal: AbortSignal): Promise<number> {
      // The gate's socket is already TLS to the endpoint's host, so the request on it is plain HTTP/1.1.
      const socket = await egress.open('push', endpoint, signal);
      return new Promise<number>((resolve, reject) => {
        const outgoing: OutgoingHttpHeaders = { ...headers, 'content-length': body.length };
        const call = httpRequest(
          { method: 'POST', hostname: endpoint.hostname, path: `${endpoint.pathname}${endpoint.search}`, headers: outgoing, createConnection: () => socket, signal },
          (response) => {
            response.resume();
            resolve(response.statusCode ?? 0);
            socket.destroy();
          },
        );
        call.on('error', (error) => {
          socket.destroy();
          reject(error);
        });
        call.end(body);
      });
    },
  };
}
