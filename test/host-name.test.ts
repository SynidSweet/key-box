// KBOX-64 (N-M5): one pure comparison of a Tailscale node name with the box's host. It drops ONE trailing dot from each side,
// lowercases ASCII, then requires exact equality, so no caller decides for itself whether the name carries a dot or capitals.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { sameHostName } from '../src/pure/host-name.ts';

const HOST = 'keybox.tail09a879.ts.net';

test('KBOX-64 the same host matches with a trailing dot, in upper case, and both at once', () => {
  assert.equal(sameHostName(HOST, HOST), true);
  assert.equal(sameHostName(`${HOST}.`, HOST), true);
  assert.equal(sameHostName(HOST.toUpperCase(), HOST), true);
  assert.equal(sameHostName(`${HOST.toUpperCase()}.`, HOST), true);
  assert.equal(sameHostName(HOST, `${HOST}.`), true, 'it is symmetric');
});

test('KBOX-64 another name never matches: a renamed node, a suffix, a prefix, empty, a lone dot, two trailing dots', () => {
  for (const other of ['keybox-1.tail09a879.ts.net.', `${HOST}.evil`, 'xkeybox.tail09a879.ts.net', '', '.', `${HOST}..`]) {
    assert.equal(sameHostName(other, HOST), false, JSON.stringify(other));
    assert.equal(sameHostName(HOST, other), false, JSON.stringify(other));
  }
});
