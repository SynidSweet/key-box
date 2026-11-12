// KBOX-39, design 5.5: ElevenLabs has no relay profile in v1 (`relayDenyOnly`). This is the pinned list of requests no future profile may
// let through, because each one makes a key, a token or a way into the workspace. One base sample per method and path on each regional
// host; the KBOX-13 canonicalisation variants are tested against these, not stored.
import type { DenyRule, SampleRequest } from '../../ports/relay-profile.ts';
import { HOST_OF, REGIONS } from './regions.ts';

const ALL_METHODS = ['GET', 'POST', 'PATCH', 'DELETE'];

function rule(id: string, methods: readonly string[], paths: readonly string[]): DenyRule {
  const samples: SampleRequest[] = [];
  for (const region of REGIONS) for (const path of paths) for (const method of methods) samples.push({ method, url: `https://${HOST_OF[region]}${path}` });
  return { id, samples };
}

export const ELEVENLABS_MUST_DENY: readonly DenyRule[] = [
  rule('service-accounts', ALL_METHODS, ['/v1/service-accounts', '/v1/service-accounts/sa-test-1/api-keys', '/v1/service-accounts/sa-test-1/api-keys/key01']),
  rule('workspace-api-keys', ALL_METHODS, ['/v1/workspaces/api-keys/key01']),
  rule('workspace', ALL_METHODS, ['/v1/workspace', '/v1/workspace/members']),
  rule('single-use-token', ['POST'], ['/v1/single-use-token/realtime_scribe']),
  rule('signed-url-dash', ['GET'], ['/v1/convai/conversation/get-signed-url']),
  rule('signed-url-underscore', ['GET'], ['/v1/convai/conversation/get_signed_url']),
  rule('conversation-token', ['GET'], ['/v1/convai/conversation/token']),
  rule('realtime-client-secret', ['POST'], ['/v1/convai/realtime/client_secrets']),
  rule('convai-secrets', ALL_METHODS, ['/v1/convai/secrets', '/v1/convai/secrets/secret01']),
];
