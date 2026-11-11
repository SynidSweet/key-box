import type { RelayProfile } from '../../src/ports/relay-profile.ts';
import type { Lent } from '../../src/ports/types.ts';

export const fakeRelayProfile: RelayProfile = {
  platform: 'fake',
  origin: { kind: 'fixed', host: 'api.fake.example' },
  callerTokenHeaders: ['authorization'],
  inject: async (h: Headers, v: Lent): Promise<void> => {
    const value = await v.use((b) => Promise.resolve(Buffer.from(b).toString('utf8')));
    h.set('authorization', `Bearer ${value}`);
  },
  allow: [{ id: 'things-list', method: 'GET', host: 'api.fake.example', pathTemplate: '/v1/things', query: {} }],
  tailRules: [],
  mustDeny: [{ id: 'mint-key', samples: [{ method: 'POST', url: 'https://api.fake.example/v1/keys' }] }],
  requestHeaders: ['accept', 'content-type'],
  headerWords: {},
  responseHeaders: [],
  envForClients: (relayUrl: string): Record<string, string> => ({ FAKE_BASE_URL: relayUrl }),
};
