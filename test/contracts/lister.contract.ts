import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { Issuer, KeyLister } from '../../src/ports/issuer.ts';
import type { Lent } from '../../src/ports/types.ts';

export interface ListerSubject {
  readonly issuer: Issuer;
  readonly lister: KeyLister;
  readonly master: Lent;
  readonly wrongMaster: Lent;
}

/** KBOX-35: what every KeyLister must do, run against the fake and each adapter over fakePlatform. */
export function listerContract(name: string, make: () => ListerSubject): void {
  const request = { scope: { access: 'read' } };

  test(`KBOX-35 lister contract (${name}): an issued key shows in the list under its name, and is gone after revoke`, async () => {
    const { issuer, lister, master } = make();
    const issued = await issuer.issue(request, 'listed-name', master);
    const after = await lister.list(master);
    assert.deepEqual(after.filter((k) => k.platformKeyId === issued.platformKeyId).map((k) => k.name), ['listed-name']);
    await issuer.revoke(issued.platformKeyId, master);
    assert.equal((await lister.list(master)).some((k) => k.platformKeyId === issued.platformKeyId), false);
  });

  test(`KBOX-35 lister contract (${name}): the list never carries a key value`, async () => {
    const { issuer, lister, master } = make();
    const issued = await issuer.issue(request, 'a', master);
    const value = await issued.value.use((b) => Promise.resolve(Buffer.from(b).toString('utf8')));
    assert.equal(JSON.stringify(await lister.list(master)).includes(value), false);
  });

  test(`KBOX-35 lister contract (${name}): a master the platform refuses cannot list`, async () => {
    const { lister, wrongMaster } = make();
    await assert.rejects(() => lister.list(wrongMaster));
    await assert.rejects(() => lister.listAt({}, wrongMaster));
  });

  test(`KBOX-35 KBOX-51 lister contract (${name}): a listing of one location says where it is of and whether it is complete, shows an issued key until it is revoked, and carries no value`, async () => {
    const { issuer, lister, master } = make();
    const issued = await issuer.issue(request, 'located', master);
    const value = await issued.value.use((b) => Promise.resolve(Buffer.from(b).toString('utf8')));
    const before = await lister.listAt({}, master);
    assert.deepEqual(before.at, {});
    assert.equal(typeof before.complete, 'boolean');
    assert.equal(before.keys.some((k) => k.platformKeyId === issued.platformKeyId && k.disabled !== true), true);
    assert.equal(JSON.stringify(before).includes(value), false);
    await issuer.revoke(issued.platformKeyId, master);
    const after = await lister.listAt({}, master);
    assert.equal(after.complete && after.keys.some((k) => k.platformKeyId === issued.platformKeyId && k.disabled !== true), false);
  });
}
