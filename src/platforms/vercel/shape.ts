// KBOX-18, KBOX-36: the shape of a Vercel access token: `vcp_` and a base62 core.
import type { KeyShape } from '../../ports/types.ts';

/**
 * UNVERIFIED (vercel.vcp-core-length): the real core length is not measured; the vendor's own example shows 24 characters after `vcp_`.
 * The range is wide so a real token is accepted; the length only moves a key between watch tiers (KBOX-18).
 */
export const VERCEL_SHAPE: KeyShape = { prefix: 'vcp_', alphabet: 'base62', coreLength: { min: 24, max: 256 }, random: true };
