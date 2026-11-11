// KBOX-13: forwarding rules. The first half pins the one parse of the request target (pure); the second half runs the relay
// over a real loopback fake platform through the egress gate's test connector.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalPath, canonicalQuery, parseRelayTarget } from '../src/pure/target-parse.ts';

const KEYREF = 'abc123';
const parsed = (target: string) => {
  const result = parseRelayTarget(target);
  if (!result.ok) throw new Error(`refused with ${result.code}`);
  return result.value;
};
const refusal = (target: string): string => {
  const result = parseRelayTarget(target);
  return result.ok ? 'accepted' : result.code;
};

test('KBOX-13 the canonicalisation table: every ambiguous path is bad_path', () => {
  for (const path of [
    '/v1/a%2Fb',
    '/v1/a%2fb',
    '/v1/%2e%2e/x',
    '/v1/%2E/x',
    '/v1/a%5Cb',
    '/v1/a%5cb',
    '/v1//x',
    '/v1/x/',
    '/v1/./x',
    '/v1/../x',
    '/v1/.',
    '/v1/..',
    '/v1/a;x',
    '/v1/a\\b',
    '/v1/a%00b',
    '/v1/a%0Ab',
    '/v1/a\x01b',
    '/v1/a\x7fb',
    '/v1/café',
    '/v1/caf%C3%A9',
    '/v1/a%zz',
    '/v1/a%4',
    '/v1/a%',
    '/v1/a%25b',
    '/v1/a%3Bb',
  ]) {
    assert.equal(refusal(`/r/${KEYREF}${path}`), 'bad_path', path);
  }
});

test('KBOX-13 a raw # anywhere in the target is refused, in the path as bad_path and in the query as bad_query', () => {
  assert.equal(refusal(`/r/${KEYREF}/v1/a#b`), 'bad_path');
  assert.equal(refusal(`/r/${KEYREF}/v1/a?x=1#b`), 'bad_query');
});

test('KBOX-13 escapes are decoded once per segment, rules see the decoded segments, and the sent path is the canonical re-encoding', () => {
  const target = parsed(`/r/${KEYREF}/v1/%6Frganization/a~b_c.d-e/x%3Ay%40z`);
  assert.equal(target.keyref, KEYREF);
  assert.deepEqual(target.segments, ['v1', 'organization', 'a~b_c.d-e', 'x:y@z']);
  assert.equal(canonicalPath(target.segments), '/v1/organization/a~b_c.d-e/x%3Ay%40z');
});

test('KBOX-13 the canonical encoding is idempotent: parsing a canonical path gives the same segments (round trip)', () => {
  for (const segments of [['v1', 'x'], ['a:b', 'c@d', 'e!f', "g'h", 'i(j)', 'k*l', 'm,n', 'o+p', 'q=r', 's$t', 'u&v', 'w|x', 'y"z', '{}', '[]', '<>', '^`', ' ']]) {
    assert.deepEqual(parsed(`/r/${KEYREF}${canonicalPath(segments)}`).segments, segments);
  }
});

test('KBOX-13 a keyref of 5 or 25 characters, with an upper-case letter or a symbol never routes', () => {
  for (const ref of ['abcde', 'a'.repeat(25), 'abcDef', 'abc-def', '_']) assert.equal(refusal(`/r/${ref}/v1/x`), 'not_found', ref);
  for (const ref of ['abcdef', 'a'.repeat(24)]) assert.equal(parsed(`/r/${ref}/v1/x`).keyref, ref);
  for (const target of ['/x/abcdef/v1', '/r', '/r/', '/rr/abcdef', 'r/abcdef', '/R/abcdef']) assert.equal(refusal(target), 'not_found', target);
});

test('KBOX-13 a target with nothing after the keyref is the root path', () => {
  assert.deepEqual(parsed(`/r/${KEYREF}`).segments, []);
  assert.equal(canonicalPath([]), '/');
});

test('KBOX-13 the query table: each ambiguity is bad_query', () => {
  for (const query of ['a=%zz', 'a=%4', 'a=%00', 'a=%0a', 'a=\x01', 'a=café', 'a=1;b=2', '=1', '&a=1', 'a=1&', 'a=1&&b=2', 'a=1&a=2', 'a=1&%61=2', 'a', 'a%3D1=2', 'a=%26', 'a=%3D', 'a=%25', '%25=1', 'a=%7F']) {
    assert.equal(refusal(`/r/${KEYREF}/v1/x?${query}`), 'bad_query', query);
  }
});

test('KBOX-13 query names and values are decoded once, in order, and re-encoded canonically', () => {
  const target = parsed(`/r/${KEYREF}/v1/x?al%74=media&limit=10&%24method=&o=a+b`);
  assert.deepEqual(target.query, [
    ['alt', 'media'],
    ['limit', '10'],
    ['$method', ''],
    ['o', 'a+b'],
  ]);
  assert.equal(canonicalQuery(target.query), 'alt=media&limit=10&%24method=&o=a%2Bb');
  assert.deepEqual(parsed(`/r/${KEYREF}/v1/x?`).query, []);
  assert.equal(canonicalQuery([]), '');
});
