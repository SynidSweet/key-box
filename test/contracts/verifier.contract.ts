import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { Issuer, Verifier } from '../../src/ports/issuer.ts';
import type { Lent } from '../../src/ports/types.ts';

export interface VerifierSubject {
  readonly issuer: Issuer;
  readonly verifier: Verifier;
  readonly master: Lent;
  /** A key the platform never issued. */
  readonly stranger: Lent;
  /** Make the platform unreachable (true) or reachable again (false). */
  setUnreachable(down: boolean): void;
}

/** KBOX-35: what every Verifier must do, run against the fake and each adapter over fakePlatform. */
export function verifierContract(name: string, make: () => VerifierSubject): void {
  const request = { scope: { access: 'read' } };

  test(`KBOX-35 verifier contract (${name}): a live key is ok, a revoked one and a stranger are rejected`, async () => {
    const { issuer, verifier, master, stranger } = make();
    const target = { platform: issuer.platform };
    const issued = await issuer.issue(request, 'a', master);
    assert.equal(await verifier.verify(issued.value, target), 'ok');
    assert.equal(await verifier.verify(stranger, target), 'rejected');
    await issuer.revoke(issued.platformKeyId, master);
    assert.equal(await verifier.verify(issued.value, target), 'rejected');
  });

  test(`KBOX-35 verifier contract (${name}): an unreachable platform is unreachable, never rejected`, async () => {
    const { issuer, verifier, master, setUnreachable } = make();
    const issued = await issuer.issue(request, 'a', master);
    setUnreachable(true);
    assert.equal(await verifier.verify(issued.value, { platform: issuer.platform }), 'unreachable');
    setUnreachable(false);
    assert.equal(await verifier.verify(issued.value, { platform: issuer.platform }), 'ok');
  });
}
