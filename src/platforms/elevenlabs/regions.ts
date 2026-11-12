// KBOX-39: ElevenLabs has two regional hosts with the same API and a workspace each; the region is per key, never a different adapter.
export type Region = 'global' | 'us';

export const REGIONS: readonly Region[] = ['global', 'us'];

export const HOST_OF: Readonly<Record<Region, string>> = { global: 'api.elevenlabs.io', us: 'api.us.elevenlabs.io' };

export const isRegion = (text: string): text is Region => REGIONS.some((r) => r === text);
