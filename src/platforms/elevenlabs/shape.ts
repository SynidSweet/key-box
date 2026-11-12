import type { KeyShape } from '../../ports/types.ts';

/**
 * UNVERIFIED (elevenlabs.key-format): the probe had no credential, so the prefix and length are not observed. `sk_` and hex are what
 * keys commonly look like (48 characters); the window around 48 keeps a key of another length from escaping the scanner and the shape check.
 */
export const ELEVENLABS_SHAPE: KeyShape = { prefix: 'sk_', alphabet: 'hex', coreLength: { min: 32, max: 64 }, random: true };
