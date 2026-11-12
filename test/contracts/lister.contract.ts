import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { Issuer, KeyLister, PlatformKeyInfo } from '../../src/ports/issuer.ts';
import type { KeyLocation, Lent, Scope } from '../../src/ports/types.ts';

export interface ListerSubject {
  readonly issuer: Issuer;
  readonly lister: KeyLister;
  readonly master: Lent;
  readonly wrongMaster: Lent;
  /** The scope every issue request of the contract carries; `{ access: 'read' }` by default. */
  readonly scope?: Scope;
  /** The location the listings of the contract are of when the lister has no platform-wide `list`; `{}` by default. */
  readonly listedAt?: KeyLocation;
}

/** KBOX-35: what every KeyLister must do, run against the fake and each adapter over fakePlatform. */
/** `at`: the location every issue request of the contract carries (KBOX-57); none by default. */
export function listerContract(name: string, make: () => ListerSubject, at: KeyLocation = {}): void {
  const requestOf = (subject: ListerSubject): { readonly scope: Scope; readonly at: KeyLocation } => ({ scope: subject.scope ?? { access: 'read' }, at });
  /** Every key the master can see: `list` where the lister has it, else the listing of the contract's location. */
  const everyKey = async (subject: ListerSubject, master: Lent): Promise<readonly PlatformKeyInfo[]> => {
    const { lister } = subject;
    return lister.list !== undefined ? lister.list(master) : (await lister.listAt(subject.listedAt ?? {}, master)).keys;
  };

  test(`KBOX-35 lister contract (${name}): an issued key shows in the list under its name, and is gone after revoke`, async () => {
    const subject = make();
    const { issuer, master } = subject;
    const issued = await issuer.issue(requestOf(subject), 'listed-name', master);
    const after = await everyKey(subject, master);
    assert.deepEqual(after.filter((k) => k.platformKeyId === issued.platformKeyId).map((k) => k.name), ['listed-name']);
    await issuer.revoke(issued.platformKeyId, master);
    assert.equal((await everyKey(subject, master)).some((k) => k.platformKeyId === issued.platformKeyId), false);
  });

  test(`KBOX-35 lister contract (${name}): the list never carries a key value`, async () => {
    const subject = make();
    const { issuer, master } = subject;
    const issued = await issuer.issue(requestOf(subject), 'a', master);
    const value = await issued.value.use((b) => Promise.resolve(Buffer.from(b).toString('utf8')));
    assert.equal(JSON.stringify(await everyKey(subject, master)).includes(value), false);
  });

  test(`KBOX-35 lister contract (${name}): a master the platform refuses cannot list`, async () => {
    const subject = make();
    const { lister, wrongMaster } = subject;
    await assert.rejects(() => everyKey(subject, wrongMaster));
    await assert.rejects(() => lister.listAt(subject.listedAt ?? {}, wrongMaster));
  });

  test(`KBOX-35 KBOX-51 lister contract (${name}): a listing of one location says where it is of and whether it is complete, shows an issued key until it is revoked, and carries no value`, async () => {
    const subject = make();
    const { issuer, lister, master } = subject;
    const listedAt = subject.listedAt ?? {};
    const issued = await issuer.issue(requestOf(subject), 'located', master);
    const value = await issued.value.use((b) => Promise.resolve(Buffer.from(b).toString('utf8')));
    const before = await lister.listAt(listedAt, master);
    assert.deepEqual(before.at, listedAt);
    assert.equal(typeof before.complete, 'boolean');
    assert.equal(before.keys.some((k) => k.platformKeyId === issued.platformKeyId && k.disabled !== true), true);
    assert.equal(JSON.stringify(before).includes(value), false);
    await issuer.revoke(issued.platformKeyId, master);
    const after = await lister.listAt(listedAt, master);
    assert.equal(after.complete && after.keys.some((k) => k.platformKeyId === issued.platformKeyId && k.disabled !== true), false);
  });
}
