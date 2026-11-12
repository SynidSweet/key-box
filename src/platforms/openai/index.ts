// KBOX-38: the OpenAI adapter's registry entry.
import type { AdapterHttp } from '../../ports/http.ts';
import type { PlatformEntry } from '../../ports/platform.ts';
import { OPENAI_HOST } from './client.ts';
import { createOpenAiIssuer } from './issuer.ts';
import { createOpenAiLister } from './lister.ts';
import { openAiRelayProfile } from './relay.ts';
import { createOpenAiVerifier } from './verifier.ts';

/** `RegistryDeps` without importing it (the registry imports this file): this adapter needs only the HTTP client. */
export function createOpenAiEntry(deps: { readonly http: AdapterHttp }): PlatformEntry {
  return {
    id: 'openai',
    issuer: createOpenAiIssuer(deps.http),
    lister: createOpenAiLister(deps.http),
    verifier: createOpenAiVerifier(deps.http),
    relay: openAiRelayProfile,
    keyPageUrl: 'https://platform.openai.com/settings/organization/admin-keys',
    hosts: [OPENAI_HOST],
    // docs/probes/openai.md rows still STILL UNVERIFIED; openai.create-key-path was settled by the probe.
    unverified: ['openai.admin-key-length', 'openai.svcacct-key-length', 'openai.create-key-body', 'openai.verifier-call'],
  };
}
