// KBOX-66: the QR code of the setup and recover addresses on the Pi's own screen. The oracle is NOT the encoder under test:
// test/fixtures/qr/vectors.json was recorded from libqrencode 4.1.1 and decoded by zbar and ZXing-C++ (see SOURCE.md).
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { encodeQr, QrTooLongError, renderQr } from '../src/pure/qr.ts';

type Vector = { readonly name: string; readonly text: string; readonly version: number; readonly rows: readonly string[] };
const VECTORS: readonly Vector[] = JSON.parse(readFileSync(new URL('./fixtures/qr/vectors.json', import.meta.url), 'utf8'));
const vector = (name: string): Vector => {
  const v = VECTORS.find((x) => x.name === name);
  assert.ok(v, name);
  return v;
};
const asRows = (m: readonly (readonly boolean[])[]): string[] => m.map((r) => r.map((b) => (b ? '1' : '0')).join(''));

test('the encoder reproduces every recorded matrix, versions 1 to 10, at their size limits', () => {
  assert.equal(new Set(VECTORS.map((v) => v.version)).size, 10);
  for (const v of VECTORS) {
    const m = encodeQr(v.text);
    assert.equal(m.length, 17 + 4 * v.version, v.name);
    assert.deepEqual(asRows(m), v.rows, v.name);
  }
});

test('the setup and recover addresses of this host (43 and 45 bytes) and of a 100-byte host each encode', () => {
  for (const [name, bytes] of [['setup-url', 43], ['recover-url', 45], ['long-host-setup-url', 100]] as const) {
    const v = vector(name);
    assert.equal(Buffer.byteLength(v.text), bytes, name);
    assert.deepEqual(asRows(encodeQr(v.text)), v.rows, name);
  }
});

test('213 bytes encode; 214 bytes are refused with an error, never a truncated code', () => {
  assert.equal(encodeQr('x'.repeat(213)).length, 57);
  assert.throws(() => encodeQr('x'.repeat(214)), QrTooLongError);
  assert.throws(() => encodeQr('é'.repeat(107)), QrTooLongError); // 214 bytes, 107 characters
  assert.throws(() => renderQr('x'.repeat(214)), QrTooLongError);
});

test('an empty input is refused: there is no code for nothing', () => {
  assert.throws(() => encodeQr(''), QrTooLongError);
});

test('the error carries no input text', () => {
  const secret = 'S3CR3T'.repeat(60);
  assert.throws(() => encodeQr(secret), (e: Error) => e instanceof QrTooLongError && !e.message.includes('S3CR3T'));
});

/** Reads half-block text back into a grid of dark modules (true = dark). Light modules are the filled cells. */
const parseBlocks = (lines: readonly string[]): boolean[][] => {
  const grid: boolean[][] = [];
  for (const line of lines) {
    const upper: boolean[] = [];
    const lower: boolean[] = [];
    for (const ch of line) {
      assert.ok('█▀▄ '.includes(ch), `unexpected character ${JSON.stringify(ch)}`);
      upper.push(ch === ' ' || ch === '▄');
      lower.push(ch === ' ' || ch === '▀');
    }
    grid.push(upper, lower);
  }
  return grid;
};

test('the renderer gives half-block text with a quiet zone of 4, then the address as text', () => {
  const v = vector('setup-url');
  const out = renderQr(v.text);
  const lines = out.split('\n');
  assert.equal(lines.at(-1), '', 'ends with a newline');
  assert.equal(lines.at(-2), v.text, 'the address is printed as text under the code');
  assert.equal(lines.at(-3), '', 'one blank line between');
  const code = lines.slice(0, -3);
  const n = v.rows.length;
  assert.ok(code.every((l) => [...l].length === n + 8), 'width is the matrix plus 4 modules each side');
  const grid = parseBlocks(code);
  assert.equal(grid.length, 2 * Math.ceil((n + 8) / 2));
  assert.ok(grid.slice(0, 4).every((r) => r.every((d) => !d)), 'quiet zone above');
  assert.ok(grid.slice(n + 4).every((r) => r.every((d) => !d)), 'quiet zone below (and any padding row)');
  for (const r of grid) {
    assert.ok(r.slice(0, 4).every((d) => !d) && r.slice(n + 4).every((d) => !d), 'quiet zone left and right');
  }
  assert.deepEqual(asRows(grid.slice(4, n + 4).map((r) => r.slice(4, n + 4))), v.rows);
});

test('an odd-sized code gets a light padding row, and every version renders back to its fixture', () => {
  for (const v of VECTORS) {
    const lines = renderQr(v.text).split('\n');
    const n = v.rows.length;
    const grid = parseBlocks(lines.slice(0, lines.length - 3));
    assert.deepEqual(asRows(grid.slice(4, n + 4).map((r) => r.slice(4, n + 4))), v.rows, v.name);
  }
});

test('no runtime dependency: the package has none and the module imports nothing', () => {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as Record<string, unknown>;
  assert.equal(pkg['dependencies'], undefined);
  const src = readFileSync(new URL('../src/pure/qr.ts', import.meta.url), 'utf8');
  assert.equal(/^\s*import\s/m.test(src), false);
});
