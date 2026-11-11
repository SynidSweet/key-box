import type { RelayProfile, RelayTarget } from '../../src/ports/relay-profile.ts';
import type { Lent } from '../../src/ports/types.ts';

export const fakeRelayProfile: RelayProfile = {
  platform: 'fake',
  upstream: (target: RelayTarget): URL => new URL(`https://${target.host}${target.path}`),
  callerTokenHeaders: ['authorization'],
  inject: async (h: Headers, v: Lent): Promise<void> => {
    const value = await v.use((b) => Promise.resolve(Buffer.from(b).toString('utf8')));
    h.set('authorization', `Bearer ${value}`);
  },
  allow: [{ id: 'things-list', method: 'GET', host: 'api.fake.example', pathTemplate: '/v1/things', query: {} }],
  mustDeny: [{ id: 'mint-key', samples: [{ method: 'POST', url: 'https://api.fake.example/v1/keys' }] }],
  requestHeaders: ['accept', 'content-type'],
  envForClients: (relayUrl: string): Record<string, string> => ({ FAKE_BASE_URL: relayUrl }),
};
