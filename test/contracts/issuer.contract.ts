import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { Issuer, KeyLister } from '../../src/ports/issuer.ts';
import type { KeyLocation, Lent, PlatformKeyId, Scope } from '../../src/ports/types.ts';
import { bytesOf } from '../kit/index.ts';

export interface IssuerSubject {
  readonly issuer: Issuer;
  readonly master: Lent;
  /** A master the platform refuses. */
  readonly wrongMaster: Lent;
  /** Present when the issuer reveals a key once. */
  readonly lister?: KeyLister;
  /** The scope every issue request of the contract carries; `{ access: 'read' }` by default (an issuer that refuses a scope with no item names its own). */
  readonly scope?: Scope;
  /** An id in this platform's own form that it never issued; `'never-issued'` by default. */
  readonly unknownId?: PlatformKeyId;
}

/** KBOX-35 and KBOX-23: what every Issuer must do, run against the fake and each adapter over fakePlatform. */
/** `at`: the location every issue request of the contract carries (KBOX-57); none by default. */
export function issuerContract(name: string, make: () => IssuerSubject, at: KeyLocation = {}): void {
  const requestOf = (subject: IssuerSubject): { readonly scope: Scope; readonly at: KeyLocation } => ({ scope: subject.scope ?? { access: 'read' }, at });

  test(`KBOX-35 issuer contract (${name}): capabilities give a complete, consistent description of the platform`, () => {
    const subject = make();
    const { issuer, lister } = subject;
    const request = requestOf(subject);
    const caps = issuer.capabilities();
    assert.ok(['api', 'paste'].includes(caps.create));
    assert.ok(['api', 'paste'].includes(caps.revoke));
    assert.ok(caps.shape.coreLength.min > 0 && caps.shape.coreLength.max >= caps.shape.coreLength.min);
    assert.ok(['ordinary', 'admin', 'master'].includes(caps.classify(request.scope, request.at)));
    if (caps.revealOnce) assert.ok(lister !== undefined, 'KBOX-23: an issuer that reveals once needs a lister');
  });

  test(`KBOX-35 issuer contract (${name}): issue returns a key value and a platform id, and the value fits the declared shape`, async () => {
    const subject = make();
    const { issuer, master } = subject;
    const caps = issuer.capabilities();
    const issued = await issuer.issue(requestOf(subject), 'intent-one', master);
    assert.ok(issued.platformKeyId.length > 0);
    const text = Buffer.from(await bytesOf(issued.value)).toString('utf8');
    if (caps.shape.prefix !== null) assert.ok(text.startsWith(caps.shape.prefix));
    const core = text.slice(caps.shape.prefix?.length ?? 0);
    assert.ok(core.length >= caps.shape.coreLength.min && core.length <= caps.shape.coreLength.max);
  });

  test(`KBOX-35 issuer contract (${name}): two issues give two different keys`, async () => {
    const subject = make();
    const { issuer, master } = subject;
    const a = await issuer.issue(requestOf(subject), 'a', master);
    const b = await issuer.issue(requestOf(subject), 'b', master);
    assert.notEqual(a.platformKeyId, b.platformKeyId);
    assert.notEqual(Buffer.from(await bytesOf(a.value)).toString(), Buffer.from(await bytesOf(b.value)).toString());
  });

  test(`KBOX-35 issuer contract (${name}): revoke says revoked once and absent after, and a 404 is never proof`, async () => {
    const subject = make();
    const { issuer, master } = subject;
    const issued = await issuer.issue(requestOf(subject), 'a', master);
    assert.equal(await issuer.revoke(issued.platformKeyId, master), 'revoked');
    assert.equal(await issuer.revoke(issued.platformKeyId, master), 'absent');
    assert.equal(await issuer.revoke(subject.unknownId ?? 'never-issued', master), 'absent');
  });

  test(`KBOX-35 issuer contract (${name}): a master the platform refuses cannot issue or revoke`, async () => {
    const subject = make();
    const { issuer, master, wrongMaster } = subject;
    await assert.rejects(() => issuer.issue(requestOf(subject), 'a', wrongMaster));
    const issued = await issuer.issue(requestOf(subject), 'a', master);
    await assert.rejects(() => issuer.revoke(issued.platformKeyId, wrongMaster));
  });
}
