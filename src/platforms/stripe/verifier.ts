// KBOX-40: the Stripe verifier. A restricted key answers 200 only on what its restriction allows, so the verifier walks the adapter list
// (`STRIPE_VERIFY_CALLS`, one read call per resource) until one call settles it.
import type { AdapterHttp } from '../../ports/http.ts';
import { HttpTransportError } from '../../ports/http.ts';
import type { Verifier } from '../../ports/issuer.ts';

/** A cheap read call and the dashboard permission that allows it. The paste page offers this list (KBOX-40). */
export interface VerifyCall {
  readonly path: string;
  readonly permission: string;
}

/**
 * UNVERIFIED (stripe.verify-calls): the routes exist (probe) but which permission each needs, and that a key without it is answered 403, is
 * from the dashboard wording and docs only.
 */
export const STRIPE_VERIFY_CALLS: readonly VerifyCall[] = [
  { path: '/v1/balance', permission: 'Balance: read' },
  { path: '/v1/customers?limit=1', permission: 'Customers: read' },
  { path: '/v1/charges?limit=1', permission: 'Charges and Refunds: read' },
  { path: '/v1/products?limit=1', permission: 'Products: read' },
  { path: '/v1/prices?limit=1', permission: 'Prices: read' },
  { path: '/v1/account', permission: 'none documented' },
];

/** What an HTTP header value can safely carry: printable ASCII, no space. Anything else is not a key the platform could have issued. */
const HEADER_SAFE = /^[\x21-\x7e]+$/;

export function createStripeVerifier(http: AdapterHttp): Verifier {
  return {
    verify(key) {
      return key.use(async (bytes) => {
        const text = Buffer.from(bytes).toString('utf8');
        if (!HEADER_SAFE.test(text)) return 'rejected';
        for (const { path } of STRIPE_VERIFY_CALLS) {
          let status: number;
          try {
            status = (await http.request({ method: 'GET', url: `https://api.stripe.com${path}`, headers: { authorization: `Bearer ${text}`, accept: 'application/json' } })).status;
          } catch (error) {
            if (error instanceof HttpTransportError) return 'unreachable';
            throw error;
          }
          if (status === 200) return 'ok';
          // UNVERIFIED (stripe.invalid-key-answer): a deleted key is assumed to be 401 like one never issued (probe: 401 for a fake key).
          if (status === 401) return 'rejected';
          // 403: authenticated but not permitted on this resource; try the next. Any other status says nothing about the key.
          if (status !== 403) return 'unreachable';
        }
        // UNVERIFIED (stripe.verify-calls): every call answered 403, so the key authenticated (assumed: 403 follows authentication).
        return 'ok';
      });
    },
  };
}
