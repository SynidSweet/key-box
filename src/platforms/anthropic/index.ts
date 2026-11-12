// KBOX-40: the Anthropic adapter. Paste-only (the platform's keys are made in its console): the entry states its shape and class, verifies
// a pasted key, lists keys with the admin key, and `createAnthropicRetirer` retires the old key after a paste rotation. No relay profile.
import type { PlatformEntry } from '../../ports/platform.ts';
import type { AdapterHttp } from '../../ports/http.ts';
import { createAnthropicLister } from './lister.ts';
import { ANTHROPIC_SHAPE, classifyAnthropic } from './shape.ts';
import { createAnthropicVerifier } from './verifier.ts';

export { createAnthropicLister } from './lister.ts';
export { createAnthropicRetirer, hintMatches } from './retire.ts';
export type { AnthropicRetirer } from './retire.ts';
export { AnthropicError } from './errors.ts';
export { ANTHROPIC_SHAPE } from './shape.ts';

export function createAnthropicEntry(deps: { readonly http: AdapterHttp }): PlatformEntry {
  return {
    id: 'anthropic',
    verifier: createAnthropicVerifier(deps.http),
    lister: createAnthropicLister(deps.http),
    keyPageUrl: 'https://platform.claude.com/settings/keys',
    shape: ANTHROPIC_SHAPE,
    classify: classifyAnthropic,
    hosts: ['api.anthropic.com'],
    // UNVERIFIED (anthropic.key-page): the console page that makes a key is the one the redirect from console.anthropic.com lands on.
    unverified: ['anthropic.models-verify', 'anthropic.revoked-key-answer', 'anthropic.key-list-status-filter', 'anthropic.key-retire-statuses', 'anthropic.key-formats', 'anthropic.key-page'],
  };
}
