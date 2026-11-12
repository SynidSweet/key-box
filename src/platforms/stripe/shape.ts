// KBOX-40: what a Stripe restricted key looks like, and its class. A paste-only platform states both on its entry (no issuer).
import type { KeyClass, KeyShape } from '../../ports/types.ts';

/**
 * UNVERIFIED (stripe.rk-live-format): `rk_live_` is documented; the core is assumed to be base62 and 24 to 255 characters (no length is
 * documented). Test-mode keys (`rk_test_`) are not the box's: it holds live keys.
 */
export const STRIPE_SHAPE: KeyShape = { prefix: 'rk_live_', alphabet: 'base62', coreLength: { min: 24, max: 255 }, random: true };

/**
 * A restricted key the box holds is never ordinary: an ordinary Stripe key is not the box's business (KBOX-40, design 5.3), so what is
 * pasted here is a key the owner wants kept as admin (never lent to an agent, S-713). The owner can raise it to master with `mark_admin`.
 */
export const classifyStripe = (): KeyClass => 'admin';
