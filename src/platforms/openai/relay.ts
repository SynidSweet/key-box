// KBOX-38, KBOX-13, KBOX-25, KBOX-32: the `openai` relay profile (only for a key the owner marks admin). Fixed origin; the pass arrives as
// `Authorization: Bearer <pass>` and is replaced by the key. Default-deny: only the named operations pass, and the key-minting routes are
// listed by name in `mustDeny` (VERIFIED), each with the canonicalisation variants of KBOX-13.
import type { AllowRule, DenyRule, RelayProfile } from '../../ports/relay-profile.ts';
import type { Lent } from '../../ports/types.ts';
import { OPENAI_HOST } from './client.ts';

const rule = (id: string, method: string, pathTemplate: string): AllowRule => ({ id, method, host: OPENAI_HOST, pathTemplate, query: {} });

const ALLOW: readonly AllowRule[] = [
  rule('responses', 'POST', '/v1/responses'),
  rule('chat-completions', 'POST', '/v1/chat/completions'),
  rule('embeddings', 'POST', '/v1/embeddings'),
  rule('models-list', 'GET', '/v1/models'),
  rule('audio-speech', 'POST', '/v1/audio/speech'),
  rule('audio-transcriptions', 'POST', '/v1/audio/transcriptions'),
  rule('audio-translations', 'POST', '/v1/audio/translations'),
];

/** The sample requests of one denied route: the concrete request and the KBOX-13 ambiguities of its path (escape, slashes, dots, `;`, method tricks). */
function samples(method: string, path: string): DenyRule['samples'] {
  const parts = path.split('/');
  const second = parts[2] ?? '';
  const escaped = `%${second.charCodeAt(0).toString(16).toUpperCase()}${second.slice(1)}`;
  const url = (p: string): string => `https://${OPENAI_HOST}${p}`;
  return [
    { method, url: url(path) },
    { method, url: url([...parts.slice(0, 2), escaped, ...parts.slice(3)].join('/')) },
    { method, url: url(`${path}/`) },
    { method, url: url(path.replace('/', '//')) },
    { method, url: url(path.replace(/\/([^/]+)$/, '/x/../$1')) },
    { method, url: url(path.replace(/\/([^/]+)$/, '/%2e%2e/$1')) },
    { method, url: url(path.replace(/\/([^/]+)$/, '%2F$1')) },
    { method, url: url(`${path};x`) },
    { method, url: url(`${path}?_method=${method}`) },
    { method: 'GET', url: url(`${path}?%24method=${method}`) },
  ];
}

const deny = (id: string, routes: readonly (readonly [string, string])[]): DenyRule => ({ id, samples: routes.flatMap(([method, path]) => samples(method, path)) });

const MUST_DENY: readonly DenyRule[] = [
  // `/v1/organization/{rest:**}`: the admin and project key routes, the service-account routes, projects, users, certificates.
  deny('organization', [
    ['POST', '/v1/organization/admin_api_keys'],
    ['GET', '/v1/organization/admin_api_keys'],
    ['DELETE', '/v1/organization/admin_api_keys/key_x'],
    ['POST', '/v1/organization/projects/proj_x/service_accounts'],
    ['POST', '/v1/organization/projects/proj_x/service_accounts/svc_acct_x/api_keys'],
    ['GET', '/v1/organization/projects/proj_x/api_keys'],
    ['DELETE', '/v1/organization/projects/proj_x/api_keys/key_x'],
  ]),
  deny('realtime-client-secrets', [['POST', '/v1/realtime/client_secrets']]),
  deny('realtime-translation-secrets', [['POST', '/v1/realtime/translations/client_secrets']]),
  deny('realtime-transcription-sessions', [['POST', '/v1/realtime/transcription_sessions']]),
  deny('realtime-sessions', [['POST', '/v1/realtime/sessions']]),
  deny('chatkit-sessions', [['POST', '/v1/chatkit/sessions']]),
  deny('chatkit-session-cancel', [['POST', '/v1/chatkit/sessions/cksess_x/cancel']]),
  // `/v1/webhook_endpoints{rest:**}`: the endpoint list and one endpoint, in every method.
  deny('webhook-endpoints', [
    ['GET', '/v1/webhook_endpoints'],
    ['POST', '/v1/webhook_endpoints'],
    ['POST', '/v1/webhook_endpoints/we_x'],
    ['DELETE', '/v1/webhook_endpoints/we_x'],
  ]),
];

async function inject(h: Headers, key: Lent): Promise<void> {
  const value = await key.use((bytes) => Promise.resolve(Buffer.from(bytes).toString('utf8')));
  h.set('authorization', `Bearer ${value}`);
}

export const openAiRelayProfile: RelayProfile = {
  platform: 'openai',
  origin: { kind: 'fixed', host: OPENAI_HOST },
  callerTokenHeaders: ['authorization'],
  inject,
  allow: ALLOW,
  tailRules: [],
  mustDeny: MUST_DENY,
  requestHeaders: ['openai-beta', 'idempotency-key'],
  headerWords: {},
  responseHeaders: [
    'x-request-id',
    'openai-processing-ms',
    'x-ratelimit-limit-requests',
    'x-ratelimit-limit-tokens',
    'x-ratelimit-remaining-requests',
    'x-ratelimit-remaining-tokens',
    'x-ratelimit-reset-requests',
    'x-ratelimit-reset-tokens',
  ],
  envForClients: (relayUrl: string): Record<string, string> => ({ OPENAI_BASE_URL: `${relayUrl}/v1`, OPENAI_API_KEY: '<pass>' }),
};
