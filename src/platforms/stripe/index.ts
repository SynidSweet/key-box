// KBOX-40: the Stripe adapter. Paste-only (restricted keys are dashboard-only): the entry states its shape and class and verifies a pasted
// key with the first call of `STRIPE_VERIFY_CALLS` its restriction allows. No relay profile, no lister.
import type { PlatformEntry } from '../../ports/platform.ts';
import type { AdapterHttp } from '../../ports/http.ts';
import { STRIPE_SHAPE, classifyStripe } from './shape.ts';
import { createStripeVerifier } from './verifier.ts';

export { STRIPE_SHAPE } from './shape.ts';
export { STRIPE_VERIFY_CALLS } from './verifier.ts';
export type { VerifyCall } from './verifier.ts';

export function createStripeEntry(deps: { readonly http: AdapterHttp }): PlatformEntry {
  return {
    id: 'stripe',
    verifier: createStripeVerifier(deps.http),
    // UNVERIFIED (stripe.key-page): the dashboard page that makes a restricted key (it redirects to login without a session).
    keyPageUrl: 'https://dashboard.stripe.com/apikeys',
    shape: STRIPE_SHAPE,
    classify: classifyStripe,
    hosts: ['api.stripe.com'],
    // UNVERIFIED (stripe.restricted-keys-dashboard-only): no API route rolls a restricted key; this is why the platform is paste-only.
    unverified: ['stripe.restricted-keys-dashboard-only', 'stripe.rk-live-format', 'stripe.verify-calls', 'stripe.invalid-key-answer', 'stripe.key-page'],
  };
}
