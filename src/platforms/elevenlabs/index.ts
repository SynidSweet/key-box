// KBOX-39: the ElevenLabs adapter. Master = a workspace admin's key with service-account rights, pasted. Every call goes through `deps.http`.
import { readFileSync } from 'node:fs';
import type { PlatformEntry } from '../../ports/platform.ts';
import type { AdapterHttp } from '../../ports/http.ts';
import { ELEVENLABS_MUST_DENY } from './deny.ts';
import { createIssuer } from './issuer.ts';
import { createLister } from './lister.ts';
import { HOST_OF, REGIONS } from './regions.ts';
import { createVerifier } from './verifier.ts';

function loadUnverified(): readonly string[] {
  const parsed: unknown = JSON.parse(readFileSync(new URL('./unverified.json', import.meta.url), 'utf8'));
  if (!Array.isArray(parsed) || !parsed.every((id): id is string => typeof id === 'string')) throw new Error('src/platforms/elevenlabs/unverified.json must be a list of probe ids');
  return parsed;
}

export function createElevenLabsEntry(deps: { readonly http: AdapterHttp }): PlatformEntry {
  return {
    id: 'elevenlabs',
    issuer: createIssuer(deps.http),
    lister: createLister(deps.http),
    verifier: createVerifier(deps.http),
    denyOnly: ELEVENLABS_MUST_DENY,
    keyPageUrl: 'https://elevenlabs.io/app/developers/api-keys',
    // KBOX-57: the region is the key's one stored location, required of every class; the issuer and lister read it from there only.
    location: { region: { pattern: new RegExp(`^(${REGIONS.join('|')})$`), requiredFor: ['ordinary', 'admin', 'master'] } },
    hosts: REGIONS.map((r) => HOST_OF[r]),
    unverified: loadUnverified(),
  };
}
