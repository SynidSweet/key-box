// KBOX-23: the platform registry. It is built, not listed: each platform folder `src/platforms/<id>/` exports `create<Name>Entry(deps)` and
// `createRegistry` calls it on one line. The entry carries everything the adapter registers, so no shared wiring changes with it.
import { refusingAdapterHttp } from '../ports/http.ts';
import type { Clock } from '../ports/clock.ts';
import type { PlatformEntry, RegistryDeps } from '../ports/platform.ts';
import { createAnthropicEntry } from './anthropic/index.ts';
import { createElevenLabsEntry } from './elevenlabs/index.ts';
import { createOpenAiEntry } from './openai/index.ts';
import { createStripeEntry } from './stripe/index.ts';
import { createSupabaseEntry } from './supabase/index.ts';
import { createVercelEntry } from './vercel/index.ts';

export function createRegistry(deps: RegistryDeps): readonly PlatformEntry[] {
  return [createAnthropicEntry(deps), createElevenLabsEntry(deps), createOpenAiEntry(deps), createStripeEntry(deps), createSupabaseEntry(deps), createVercelEntry(deps)];
}

/** The registry as a process that makes no adapter calls sees it: every call is refused and time stands at 0. For structure checks only. */
export const REGISTRY: readonly PlatformEntry[] = createRegistry({ http: refusingAdapterHttp, clock: { now: () => 0 } });

/**
 * The registry of kb-relay, which makes no adapter call: it is built with the refusing client, so every call is refused. `create` is the
 * builder it uses (a test passes a recording one).
 */
export function createRelayRegistry(clock: Clock, create: (deps: RegistryDeps) => readonly PlatformEntry[] = createRegistry): readonly PlatformEntry[] {
  return create({ http: refusingAdapterHttp, clock });
}
