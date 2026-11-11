// KBOX-9 / KBOX-50: canonical JSON is RFC 8785 restricted to integers: sorted keys, UTF-8, no floats, no null, no whitespace.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalJson } from '../src/pure/canonical.ts';
import { checkProperty, seedFor, seededRandom } from './kit/index.ts';
import type { SeededRandom } from './kit/index.ts';

const seed = seedFor(process.env);

test('KBOX-50 the RFC 8785 sorting and escaping example comes out byte for byte', () => {
  const input = {
    '€': 'Euro Sign',
    '\r': 'Carriage Return',
    '\u000a': 'Newline',
    '1': 'One',
    '\u0080': 'Control',
    '😂': 'Smiley',
    'ö': 'Latin Small Letter O With Diaeresis',
    'דּ': 'Hebrew Letter Dalet With Dagesh',
    '</script>': 'Browser Challenge',
  };
  assert.equal(
    canonicalJson(input),
    '{"\\n":"Newline","\\r":"Carriage Return","1":"One","</script>":"Browser Challenge","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign","😂":"Smiley","דּ":"Hebrew Letter Dalet With Dagesh"}',
  );
});

test('KBOX-50 integers, booleans, arrays and nesting; an absent member is omitted and there is no whitespace', () => {
  assert.equal(canonicalJson({ b: [1, -2, 0, { z: true, a: false }], a: 9007199254740991, u: undefined, s: 'q"\\\u0001' }), '{"a":9007199254740991,"b":[1,-2,0,{"a":false,"z":true}],"s":"q\\"\\\\\\u0001"}');
  assert.equal(canonicalJson({}), '{}');
  assert.equal(canonicalJson([]), '[]');
  assert.equal(canonicalJson('plain'), '"plain"');
});

test('KBOX-50 floats, null, NaN, bigint, undefined in an array, dates, maps, functions and lone surrogates are refused with a fixed text', () => {
  const planted = 'planted-text-that-must-not-be-quoted';
  for (const bad of [1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53, null, 10n, [undefined], { a: null }, new Date(0), new Map(), () => planted, { a: { b: Symbol(planted) } }, '\ud800', { '\udfff': 1 }, { a: planted + '\ud800' }]) {
    assert.throws(
      () => canonicalJson(bad),
      (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.equal(error.message, 'value cannot be written as canonical JSON');
        return true;
      },
    );
  }
});

function randomValue(rng: SeededRandom, depth: number): unknown {
  const pick = rng.int(depth > 3 ? 4 : 6);
  if (pick === 0) return rng.int(2_000_001) - 1_000_000;
  if (pick === 1) return rng.int(2) === 0;
  if (pick === 2) return String.fromCodePoint(...Array.from({ length: rng.int(6) }, () => 32 + rng.int(0x2fff)));
  if (pick === 3) return String.fromCharCode(...Array.from({ length: rng.int(4) }, () => rng.int(0x80)));
  if (pick === 4) return Array.from({ length: rng.int(4) }, () => randomValue(rng, depth + 1));
  return Object.fromEntries(Array.from({ length: rng.int(5) }, (_, i) => [`k${rng.int(9)}${String.fromCharCode(97 + i)}`, randomValue(rng, depth + 1)]));
}

test('KBOX-50 property: canonical text parses back to the value, and member order never changes it', () => {
  checkProperty(seed, 300, (rng) => {
    const value = randomValue(rng, 0);
    const text = canonicalJson(value);
    assert.deepEqual(JSON.parse(text), value);
    const reversed = JSON.parse(JSON.stringify(value), (_k, v: unknown) =>
      v !== null && typeof v === 'object' && !Array.isArray(v) ? Object.fromEntries(Object.entries(v).reverse()) : v,
    );
    assert.equal(canonicalJson(reversed), text);
    assert.equal(canonicalJson(JSON.parse(text)), text);
  });
  assert.equal(typeof seededRandom(seed).seed, 'number');
});
