// KBOX-37: the Supabase adapter. Master = a personal access token, pasted (UNVERIFIED supabase.pat-create-by-api: assumed dashboard-only), with
// the scope item `access-token`. Everything it calls is the Management API through `deps.http`; the relay profile reaches each key's own project
// host, the project being the key's one stored location (KBOX-57), proven at proposal by `locationProver`.
import type { PlatformEntry, RegistryDeps } from '../../ports/platform.ts';
import { createDestination } from './destination.ts';
import { createIssuer, PLATFORM } from './issuer.ts';
import { createLister } from './lister.ts';
import { createManagement, MANAGEMENT_HOST } from './management.ts';
import { createProver } from './prover.ts';
import { createVerifier } from './verifier.ts';
import { supabaseProfile } from './relay.ts';
import { PROJECT_REF } from './shape.ts';

export { createPasswordSetter } from './password.ts';
export type { PasswordSetter } from './password.ts';

export function createSupabaseEntry(deps: RegistryDeps): PlatformEntry {
  const call = createManagement(deps.http);
  return {
    id: PLATFORM,
    issuer: createIssuer(call),
    lister: createLister(call),
    relay: supabaseProfile,
    // KBOX-57: the project names the relay host, so it is required of every ordinary and admin key and proven before the proposal; a master (a
    // personal access token) belongs to an account, not a project.
    location: { project: { pattern: PROJECT_REF, requiredFor: ['ordinary', 'admin'], namesHost: true } },
    locationProver: createProver(call),
    // KBOX-58: the verifier tests the master (a personal access token) only. A project key is tested against its own project host, which no
    // adapter call may reach (KBOX-47): steps 5 and 8 pass it untested and step 10 confirms its revoke through the lister.
    verifier: createVerifier(call),
    destinations: [{ destination: createDestination(call) }],
    keyPageUrl: 'https://supabase.com/dashboard/account/tokens',
    hosts: [MANAGEMENT_HOST],
    // docs/probes/supabase.md rows still STILL UNVERIFIED (the same ids as unverified.json).
    unverified: [
      'supabase.pat-create-by-api', 'supabase.reveal-on-create', 'supabase.reveal-on-get', 'supabase.edge-secrets-get-value', 'supabase.relay-allow-postgrest-tables',
      'supabase.relay-allow-rpc', 'supabase.relay-allow-storage-objects', 'supabase.relay-allow-storage-list', 'supabase.relay-deny-auth', 'supabase.relay-deny-pg',
      'supabase.relay-deny-graphql', 'supabase.relay-deny-functions', 'supabase.relay-deny-storage-sign', 'supabase.relay-deny-storage-upload-sign',
      'supabase.relay-deny-storage-bucket', 'supabase.relay-deny-realtime', 'supabase.relay-deny-rest-root', 'supabase.relay-deny-profile-headers',
      'supabase.sb-secret-length', 'supabase.project-get-shape', 'supabase.pat-verify', 'supabase.pat-shape',
    ],
  };
}
