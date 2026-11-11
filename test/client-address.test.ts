// KBOX-43: the client address comes from one header; "new network" means the /24 of an IPv4 or the /48 of an IPv6 address.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseClientAddress } from '../src/pure/address.ts';
import { checkProperty, seedFor } from './kit/index.ts';

const seed = seedFor(process.env);
const networkOf = (header: string): string | undefined => parseClientAddress(header)?.network;

test('KBOX-43 an IPv4 address is in the /24 of its first three octets, at both ends of the range and across the boundary', () => {
  assert.equal(networkOf('203.0.113.0'), '203.0.113.0/24');
  assert.equal(networkOf('203.0.113.255'), '203.0.113.0/24');
  assert.equal(networkOf('203.0.113.77'), '203.0.113.0/24');
  assert.equal(networkOf('203.0.114.0'), '203.0.114.0/24');
  assert.equal(networkOf('203.0.112.255'), '203.0.112.0/24');
  assert.equal(networkOf('0.0.0.0'), '0.0.0.0/24');
  assert.equal(networkOf('255.255.255.255'), '255.255.255.0/24');
  assert.equal(parseClientAddress('203.0.113.77')?.address, '203.0.113.77');
});

test('KBOX-43 an IPv6 address is in the /48 of its first three groups, with compression, case and the boundary handled', () => {
  assert.equal(networkOf('2001:db8:1::'), '2001:db8:1::/48');
  assert.equal(networkOf('2001:db8:1:ffff:ffff:ffff:ffff:ffff'), '2001:db8:1::/48');
  assert.equal(networkOf('2001:DB8:1:0:0:0:0:1'), '2001:db8:1::/48');
  assert.equal(networkOf('2001:0db8:0001::1'), '2001:db8:1::/48');
  assert.equal(networkOf('2001:db8:2::'), '2001:db8:2::/48');
  assert.equal(networkOf('2001:db8:0::1'), '2001:db8::/48');
  assert.equal(networkOf('::1'), '::/48');
  assert.equal(networkOf('::'), '::/48');
  assert.equal(networkOf('fe80::1'), 'fe80::/48');
  assert.equal(networkOf('1:2:3:4:5:6:7:8'), '1:2:3::/48');
  assert.equal(networkOf('1:2:3:4:5:6:1.2.3.4'), '1:2:3::/48');
});

test('KBOX-43 an IPv4-mapped IPv6 address is the IPv4 network of the address inside it', () => {
  assert.equal(networkOf('::ffff:203.0.113.9'), '203.0.113.0/24');
  assert.equal(networkOf('::FFFF:203.0.113.9'), '203.0.113.0/24');
  assert.equal(networkOf('0:0:0:0:0:ffff:203.0.113.9'), '203.0.113.0/24');
  assert.equal(networkOf('::ffff:cb00:7109'), '203.0.113.0/24');
});

test('KBOX-43 a missing or malformed header has no address', () => {
  const bad = [
    undefined,
    '',
    ' ',
    ' 1.2.3.4',
    '1.2.3.4 ',
    '1.2.3',
    '1.2.3.4.5',
    '256.1.1.1',
    '1.2.3.256',
    '01.2.3.4',
    '1.2.3.04',
    '-1.2.3.4',
    '1.2.3.4:80',
    '1.2.3.4, 5.6.7.8',
    '1.2.3.4\n',
    'localhost',
    '[::1]',
    '[::1]:80',
    '::1%eth0',
    ':::',
    '1::2::3',
    ':1:2:3:4:5:6:7',
    '1:2:3:4:5:6:7:8:9',
    '1:2:3:4:5:6:7',
    '12345::1',
    'g::1',
    '1:2:3:4:5:6:7:1.2.3.4',
    '::1.2.3',
    '1.2.3.4::',
    '0x7f.0.0.1',
    '١.٢.٣.٤',
  ];
  for (const header of bad) assert.equal(parseClientAddress(header), undefined, JSON.stringify(header));
});

test('KBOX-43 property: two IPv4 addresses share a network exactly when their first three octets agree; IPv6 when their first 48 bits agree', () => {
  checkProperty(seed, 300, (rng) => {
    const octets = (): number[] => Array.from({ length: 4 }, () => rng.int(256));
    const a = octets();
    const b = rng.int(2) === 0 ? [...a.slice(0, 3), rng.int(256)] : octets();
    const same = networkOf(a.join('.')) === networkOf(b.join('.'));
    assert.equal(same, a.slice(0, 3).join('.') === b.slice(0, 3).join('.'));

    const groups = (): number[] => Array.from({ length: 8 }, () => rng.int(0x10000));
    const x = groups();
    const y = rng.int(2) === 0 ? [...x.slice(0, 3), ...groups().slice(3)] : groups();
    const text = (g: number[]): string => g.map((n) => n.toString(16)).join(':');
    // The first group is kept out of the IPv4-mapped form so the two shapes never mix in this check.
    const keep = (g: number[]): number[] => [g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0xffff ? 1 : (g[0] ?? 1), ...g.slice(1)];
    const [kx, ky] = [keep(x), keep(y)];
    assert.equal(networkOf(text(kx)) === networkOf(text(ky)), kx.slice(0, 3).join() === ky.slice(0, 3).join());
  });
});
