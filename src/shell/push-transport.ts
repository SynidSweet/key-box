// KBOX-22: the one outside call of Web Push, a single POST to a push service. Redirects are not followed: the endpoint was
// checked against the host list at subscription, and a Location is not.
import type { PushTransport } from '../ports/push.ts';

export function createHttpPushTransport(): PushTransport {
  return {
    async post(endpoint: URL, headers: Readonly<Record<string, string>>, body: Uint8Array, signal: AbortSignal): Promise<number> {
      const response = await fetch(endpoint, { method: 'POST', headers: { ...headers }, body, signal, redirect: 'manual' });
      await response.body?.cancel();
      return response.status;
    },
  };
}
