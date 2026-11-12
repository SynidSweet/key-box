// KBOX-38: the OpenAI adapter's registry entry.
import type { PlatformEntry, RegistryDeps } from '../../ports/platform.ts';
import { ID, OPENAI_HOST } from './client.ts';
import { createOpenAiIssuer } from './issuer.ts';
import { createOpenAiLister } from './lister.ts';
import { openAiRelayProfile } from './relay.ts';
import { createOpenAiVerifier } from './verifier.ts';

export function createOpenAiEntry(deps: RegistryDeps): PlatformEntry {
  return {
    id: 'openai',
    issuer: createOpenAiIssuer(deps.http),
    lister: createOpenAiLister(deps.http),
    verifier: createOpenAiVerifier(deps.http),
    relay: openAiRelayProfile,
    keyPageUrl: 'https://platform.openai.com/settings/organization/admin-keys',
    // KBOX-57: the project is the key's one stored location, required of every ordinary and admin key; a `project:` scope item is refused.
    location: { project: { pattern: ID, requiredFor: ['ordinary', 'admin'] } },
    hosts: [OPENAI_HOST],
    // docs/probes/openai.md rows still STILL UNVERIFIED; openai.create-key-path was settled by the probe.
    unverified: ['openai.admin-key-length', 'openai.svcacct-key-length', 'openai.create-key-body', 'openai.verifier-call'],
  };
}
