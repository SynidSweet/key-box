// KBOX-10: bearer tokens are `kbt_` plus 43 base64url characters (32 random bytes); the box keeps only SHA-256 of the token.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { TokenRecord } from '../src/ports/meta.ts';
import { findToken, hashToken, newToken, parseBearer } from '../src/pure/tokens.ts';
import { checkProperty, seedFor, seededRandom } from './kit/index.ts';

const seed = seedFor(process.env);
const FIXED = `kbt_${'A'.repeat(43)}`;

test('KBOX-10 a new token is kbt_ plus 43 base64url characters that decode to the 32 bytes drawn', () => {
  const rng = seededRandom(seed);
  const drawn = rng.bytes(32);
  const token = newToken({ bytes: (n) => (n === 32 ? drawn : new Uint8Array(0)) });
  assert.match(token, /^kbt_[A-Za-z0-9_-]{43}$/);
  assert.equal(token.length, 47);
  assert.deepEqual([...Buffer.from(token.slice(4), 'base64url')], [...drawn]);
  assert.notEqual(newToken(seededRandom(seed + 1)), newToken(seededRandom(seed + 2)));
});

test('KBOX-10 the stored hash is the lower-case hex SHA-256 of the whole token text', () => {
  assert.equal(hashToken(FIXED), '855e83e98f0e0e66e8057cd23e018056cbfce5aa78be14b841874c99a7e675b7');
});

test('KBOX-10 the Authorization header is read as absent, malformed or a well-formed token, and a malformed one never becomes a lookup key', () => {
  assert.deepEqual(parseBearer(undefined), { kind: 'absent' });
  assert.deepEqual(parseBearer(`Bearer ${FIXED}`), { kind: 'token', token: FIXED });
  assert.deepEqual(parseBearer(`bearer ${FIXED}`), { kind: 'token', token: FIXED });
  const malformed = [
    '',
    'Bearer',
    'Bearer ',
    `Bearer  ${FIXED}`,
    `Bearer ${FIXED} `,
    `Basic ${FIXED}`,
    FIXED,
    `Bearer ${FIXED}, Bearer ${FIXED}`,
    `Bearer kbx_${'A'.repeat(43)}`,
    `Bearer kbt_${'A'.repeat(42)}`,
    `Bearer kbt_${'A'.repeat(44)}`,
    `Bearer kbt_${'A'.repeat(42)}+`,
    `Bearer kbt_${'A'.repeat(42)}/`,
    `Bearer kbt_${'A'.repeat(42)}=`,
    `Bearer kbt_${'A'.repeat(42)}\n`,
    `Bearer kbt_${'A'.repeat(42)}é`,
    `Bearer KBT_${'A'.repeat(43)}`,
  ];
  for (const header of malformed) assert.deepEqual(parseBearer(header), { kind: 'malformed' }, JSON.stringify(header));
});

function record(label: string, token: string, scope: TokenRecord['scope'] = 'control', revoked = false): TokenRecord {
  return { label, scope, tokenSha256: hashToken(token), revoked };
}

test('KBOX-10 two tokens whose hashes share a 32-bit prefix are told apart, and a stranger with the same prefix finds nothing', () => {
  const rng = seededRandom(seed);
  const byPrefix = new Map<string, string>();
  let pair: [string, string] | undefined;
  while (pair === undefined) {
    const token = newToken(rng);
    const prefix = hashToken(token).slice(0, 8);
    const other = byPrefix.get(prefix);
    if (other === undefined) byPrefix.set(prefix, token);
    else pair = [other, token];
  }
  const [a, b] = pair;
  assert.equal(hashToken(a).slice(0, 8), hashToken(b).slice(0, 8));
  const records = [record('a', a), record('b', b, 'relay')];
  assert.equal(findToken(records, a)?.label, 'a');
  assert.equal(findToken(records, b)?.label, 'b');
  assert.equal(findToken([record('a', a)], b), undefined);
  assert.equal(findToken([], a), undefined);
});

test('KBOX-10 property: a token is found exactly when it is enrolled, whatever else is enrolled', () => {
  checkProperty(seed, 50, (rng) => {
    const tokens = Array.from({ length: 1 + rng.int(6) }, () => newToken(rng));
    const records = tokens.map((t, i) => record(`m${i}`, t));
    for (const [i, t] of tokens.entries()) assert.equal(findToken(records, t)?.label, `m${i}`);
    assert.equal(findToken(records, newToken(rng)), undefined);
  });
});
