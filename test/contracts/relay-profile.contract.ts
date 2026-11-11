import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { RelayProfile } from '../../src/ports/relay-profile.ts';
import { canary, lent } from '../kit/index.ts';

/** KBOX-35 and KBOX-23: what every RelayProfile must be, run against the fake and each platform's profile. */
export function relayProfileContract(name: string, make: () => RelayProfile): void {
  test(`KBOX-35 relay profile contract (${name}): mustDeny is not empty and every rule carries a sample request`, () => {
    const profile = make();
    assert.ok(profile.mustDeny.length > 0);
    for (const rule of profile.mustDeny) {
      assert.ok(rule.samples.length > 0, `${rule.id} has no sample request`);
      for (const sample of rule.samples) assert.doesNotThrow(() => new URL(sample.url), `${rule.id}: ${sample.url}`);
    }
  });

  test(`KBOX-35 relay profile contract (${name}): rule ids are unique and every allow rule names a method, a host and a path`, () => {
    const profile = make();
    const ids = [...profile.allow.map((r) => r.id), ...profile.mustDeny.map((r) => r.id)];
    assert.equal(new Set(ids).size, ids.length);
    for (const rule of profile.allow) {
      assert.ok(rule.method.length > 0 && rule.host.length > 0 && rule.pathTemplate.startsWith('/'), rule.id);
    }
  });

  test(`KBOX-35 relay profile contract (${name}): caller token headers and request headers are lower case`, () => {
    const profile = make();
    for (const h of [...profile.callerTokenHeaders, ...profile.requestHeaders]) assert.equal(h, h.toLowerCase());
  });

  test(`KBOX-35 relay profile contract (${name}): inject puts the key into the request headers and nowhere in the client environment`, async () => {
    const profile = make();
    const c = canary();
    const key = lent(Buffer.from(Buffer.from(c.bytes).toString('hex')), 'test:1');
    const headers = new Headers();
    await profile.inject(headers, key);
    const hex = Buffer.from(c.bytes).toString('hex');
    assert.ok([...headers.values()].some((v) => v.includes(hex)), 'the key is not in any injected header');
    c.assertAbsent({ env: JSON.stringify(profile.envForClients('https://relay.example/r/x')) });
    assert.equal(JSON.stringify(profile.envForClients('https://relay.example/r/x')).includes(hex), false);
  });
}
