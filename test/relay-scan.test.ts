// KBOX-14: response handling. The first half drives the pure streaming scanner (held values in every form, credential
// shapes, the hold counted in the stripped view, candidate decisions); the second half runs the relay over a fake upstream.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { scanForms } from '../src/pure/forms.ts';
import type { Form } from '../src/pure/forms.ts';
import { createResponseScanner, parseCredentialShapes } from '../src/pure/scanner.ts';
import type { CredentialShapes, ResponseScanner } from '../src/pure/scanner.ts';
import { checkProperty, seedFor } from './kit/index.ts';
import type { SeededRandom } from './kit/index.ts';

const shapesParsed = parseCredentialShapes(JSON.parse(readFileSync(new URL('../src/data/credential-shapes.json', import.meta.url), 'utf8')) as unknown);
if (!shapesParsed.ok) throw new Error('src/data/credential-shapes.json does not parse');
const SHAPES: CredentialShapes = shapesParsed.value;

/** A held value with no credential shape of its own: only the value forms can catch it. */
const VALUE = 'Qm9vbGVh/bkZsYWdQ+YXJ0eTQ3OTE2Mjg1';
const formsOf = (value: string): readonly Form[] => {
  const result = scanForms(value);
  if (!result.ok) throw new Error(`no forms: ${result.code}`);
  return result.forms;
};
const scannerFor = (values: readonly string[] = [VALUE]): ResponseScanner => createResponseScanner(values.flatMap(formsOf), SHAPES);

interface Run {
  readonly hit: 'value' | 'credential' | undefined;
  /** The most raw bytes ever released before the hit (or the end). */
  readonly released: number;
}

/** Feeds `chunks`; ends cleanly when `clean`. Stops at the first hit, as the relay does. */
function run(scanner: ResponseScanner, chunks: readonly Uint8Array[], clean = true): Run {
  let released = 0;
  for (const chunk of chunks) {
    const step = scanner.feed(chunk);
    if (step.kind === 'hit') return { hit: step.reason, released };
    released = Math.max(released, step.releasable);
  }
  if (!clean) return { hit: undefined, released };
  const last = scanner.end();
  if (last.kind === 'hit') return { hit: last.reason, released };
  return { hit: undefined, released: Math.max(released, last.releasable) };
}

const bytes = (text: string): Uint8Array => Buffer.from(text, 'utf8');
const splitAt = (data: Uint8Array, ...cuts: number[]): Uint8Array[] => {
  const points = [0, ...cuts, data.length];
  return points.slice(1).map((end, i) => data.subarray(points[i] ?? 0, end));
};
const randomChunks = (data: Uint8Array, rng: SeededRandom): Uint8Array[] => {
  const out: Uint8Array[] = [];
  for (let at = 0; at < data.length; ) {
    const size = 1 + rng.int(40);
    out.push(data.subarray(at, at + size));
    at += size;
  }
  return out;
};

/** The value encoded the way an upstream might carry it, inside `before` and `after` text encoded the same way. */
const ENCODINGS: Readonly<Record<string, (text: string) => string>> = {
  raw: (t) => t,
  'base64 alignment 0': (t) => Buffer.from(t).toString('base64'),
  'base64 alignment 1': (t) => Buffer.from(`x${t}`).toString('base64'),
  'base64 alignment 2': (t) => Buffer.from(`xy${t}`).toString('base64'),
  'base64url alignment 1': (t) => Buffer.from(`x${t}`).toString('base64url'),
  hex: (t) => Buffer.from(t).toString('hex'),
  'hex upper': (t) => Buffer.from(t).toString('hex').toUpperCase(),
  percent: (t) => encodeURIComponent(t),
  'percent lower': (t) => encodeURIComponent(t).replace(/%[0-9A-F]{2}/g, (s) => s.toLowerCase()),
  json: (t) => JSON.stringify(`"${t}"/`).slice(1, -1),
  'u-escaped': (t) => [...t].map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join(''),
};

test('KBOX-14 a held value is withheld in raw, base64 (three alignments), hex, percent, JSON and \\u forms, split across two chunks', () => {
  for (const [name, encode] of Object.entries(ENCODINGS)) {
    const body = bytes(`{"data":"${encode(`before ${VALUE} after`)}"}`);
    for (const cut of [1, Math.floor(body.length / 2), body.length - 2]) {
      assert.equal(run(scannerFor(), splitAt(body, cut)).hit, 'value', `${name} split at ${cut}`);
    }
  }
});

/** Where the copy starts in raw bytes: the first byte of the encoded `before ` text is not part of it. */
function plantedCopy(name: string, rng: SeededRandom): { readonly body: Uint8Array; readonly start: number } {
  const encode = ENCODINGS[name];
  if (encode === undefined) throw new Error(name);
  const lead = `{"pad":"${'p'.repeat(rng.int(200))}","data":"`;
  const encoded = encode(VALUE);
  const inner = name.startsWith('base64') ? encode(`zz${VALUE}`) : encoded;
  const body = bytes(`${lead}${inner}"}`);
  return { body, start: lead.length };
}

test('KBOX-14 the bytes released before the hit never include a byte of the planted copy, for every form and every split of a seeded chunking', () => {
  const seed = seedFor(process.env);
  checkProperty(seed, 40, (rng) => {
    for (const name of Object.keys(ENCODINGS)) {
      const { body, start } = plantedCopy(name, rng);
      const result = run(scannerFor(), randomChunks(body, rng));
      assert.notEqual(result.hit, undefined, name);
      assert.ok(result.released <= start, `${name}: released ${result.released} > copy start ${start}`);
    }
  });
});

/** `text` as base64 wrapped at `width` columns with `eol`, as PEM and MIME write it. */
const wrapped = (text: string, width: number, eol: string): string => (Buffer.from(text).toString('base64').match(new RegExp(`.{1,${width}}`, 'g')) ?? []).join(eol);

test('KBOX-14 wrapped copies: base64 at 64 and 76 columns with CRLF and with \\-newline never release a copy byte before the hit (the hold is counted in stripped characters)', () => {
  const long = `${VALUE}${VALUE}${VALUE}`;
  const seed = seedFor(process.env);
  checkProperty(seed, 6, (rng) => {
    for (const [width, eol] of [[64, '\r\n'], [76, '\r\n'], [64, '\\\n'], [76, '\\\r\n']] as const) {
      const lead = `{"blob":"${'q'.repeat(rng.int(300))}`;
      const body = bytes(`${lead}${wrapped(`${'w'.repeat(rng.int(3))}${long}tail`, width, eol)}"}`);
      for (let cut = 1; cut < body.length; cut += 1) {
        const result = run(scannerFor([long]), splitAt(body, cut));
        assert.notEqual(result.hit, undefined, `width ${width} cut ${cut}`);
        assert.ok(result.released <= lead.length, `width ${width} cut ${cut}: released ${result.released} > ${lead.length}`);
      }
    }
  });
});

test('KBOX-14 a wrapped sk- key never releases a byte of the key before it is withheld', () => {
  const key = `sk-${'A1b2C3d4E5'.repeat(4)}`;
  for (const eol of ['\r\n', '\\\n']) {
    const lead = '{"note":"key follows","k":"';
    const body = bytes(`${lead}${key.slice(0, 13)}${eol}${key.slice(13)}"}`);
    for (let cut = 1; cut < body.length; cut += 1) {
      const result = run(scannerFor([]), splitAt(body, cut));
      assert.equal(result.hit, 'credential', `cut ${cut}`);
      assert.ok(result.released <= lead.length, `cut ${cut}: released ${result.released}`);
    }
  }
});

test('KBOX-14 credential shapes are withheld: an sk- key, a JWT, a client_secret member and a PEM private-key header', () => {
  const jwtHeader = Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url');
  for (const body of [
    `{"key":"sk-${'a'.repeat(30)}"}`,
    `{"token":"${jwtHeader}.eyJzdWIiOiIxIn0.c2ln"}`,
    '{"client_secret":"x"}',
    '{ "client_secret" : "x" }',
    '-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----',
    '-----BEGIN PRIVATE KEY-----\nMIIB',
    `{"k":"AIza${'b'.repeat(35)}"}`,
    `{"k":"ghp_${'c'.repeat(36)}"}`,
  ]) {
    const data = bytes(body);
    for (const cut of [1, Math.floor(data.length / 2)]) assert.equal(run(scannerFor([]), splitAt(data, cut)).hit, 'credential', `${body.slice(0, 20)} cut ${cut}`);
  }
});

test('KBOX-14 an empty-string api_key member, an api_key that is not a string, and a PEM public key pass whole', () => {
  for (const body of ['{"api_key":""}', '{"api_key": null}', '{"api_key":12}', '-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----']) {
    const data = bytes(body);
    assert.deepEqual(run(scannerFor([]), [data]), { hit: undefined, released: data.length }, body);
  }
});

/** What one feed of `text` releases at once, with no end of stream. */
const releasedAtOnce = (text: string): number => {
  const step = scannerFor([]).feed(bytes(text));
  assert.equal(step.kind, 'progress', text);
  return step.kind === 'progress' ? step.releasable : -1;
};

test('KBOX-14 candidates: task-, sk-ill and ask- followed by a space are released whole at once', () => {
  for (const text of ['the task- ', 'an sk-ill ', 'ask- ']) assert.equal(releasedAtOnce(text), bytes(text).length, text);
});

test('KBOX-14 candidates: a prefix decides at its min length: sk- 19 then a space released, 20 withheld; AIza 34/35; GOCSPX- 27/28', () => {
  for (const [prefix, min] of [['sk-', 20], ['AIza', 35], ['GOCSPX-', 28]] as const) {
    const short = `x ${prefix}${'k'.repeat(min - 1)} z`;
    assert.deepEqual(run(scannerFor([]), [bytes(short)], false), { hit: undefined, released: bytes(short).length }, `${prefix} ${min - 1}`);
    assert.equal(run(scannerFor([]), [bytes(`x ${prefix}${'k'.repeat(min)} z`)], false).hit, 'credential', `${prefix} ${min}`);
  }
});

test('KBOX-14 candidates: an undecided candidate is held from its first byte, and only that', () => {
  assert.equal(releasedAtOnce(`ok sk-${'k'.repeat(10)}`), 3);
  assert.equal(releasedAtOnce('abc s'), 4);
});

test('KBOX-14 candidates: an eyJ run of 600 base64url characters with no dot is released; an eyJ header without alg is released', () => {
  const run600 = `eyJ${'A'.repeat(597)}`;
  assert.deepEqual(run(scannerFor([]), [bytes(`${run600} `)], false), { hit: undefined, released: run600.length + 1 });
  const noAlg = `${Buffer.from('{"typ":"JWT"}').toString('base64url')}.e30.c2ln`;
  assert.deepEqual(run(scannerFor([]), [bytes(`${noAlg} `)], false), { hit: undefined, released: noAlg.length + 1 });
});

test('KBOX-14 a decoy that starts like a credential and stops is released whole at the clean end', () => {
  for (const decoy of ['sk-short', 'eyJhbGci', '"client_secret":', '-----BEGIN RSA', `${VALUE.slice(0, 20)}`]) {
    const data = bytes(`{"d":"${decoy}`);
    assert.deepEqual(run(scannerFor(), [data]), { hit: undefined, released: data.length }, decoy);
  }
});

test('KBOX-14 a stream that is not ended keeps the held tail; a clean end scans it and releases it', () => {
  const data = bytes(`{"d":"${VALUE.slice(0, 25)}`);
  const scanner = scannerFor();
  const step = scanner.feed(data);
  assert.ok(step.kind === 'progress' && step.releasable <= data.length - 25, 'the tail of a possible copy is held');
  const last = scanner.end();
  assert.deepEqual(last, { kind: 'progress', releasable: data.length });
});

const highWater = (scanner: ResponseScanner, chunk: Uint8Array, times: number): number => {
  for (let i = 0; i < times; i += 1) assert.equal(scanner.feed(chunk).kind, 'progress');
  return scanner.heldHighWater();
};

test('KBOX-14 a 10 MiB run of line breaks inside a JSON string, and a 10 MiB eyJ run, keep the held bytes below a constant', () => {
  const breaks = new Uint8Array(64 * 1024).fill(0x0a);
  const lines = scannerFor();
  lines.feed(bytes('{"s":"'));
  assert.ok(highWater(lines, breaks, 160) < 2048, 'line breaks');
  const eyj = scannerFor();
  eyj.feed(bytes('{"s":"eyJ'));
  assert.ok(highWater(eyj, new Uint8Array(64 * 1024).fill(0x41), 160) < 2048, 'eyJ run');
});

test('KBOX-14 property: random JSON with one planted copy of a held value at a random offset is always caught', () => {
  const seed = seedFor(process.env);
  const words = ['id', 'name', 'items', 'ok', 'count', 'model', 'gpt', 'note', 'value', 'list'];
  checkProperty(seed, 60, (rng) => {
    const pick = (): string => words[rng.int(words.length)] ?? 'x';
    const parts: string[] = [];
    for (let i = 0; i < 1 + rng.int(30); i += 1) parts.push(`"${pick()}${i}":${rng.int(2) === 0 ? rng.int(100000) : `"${pick()} ${pick()}"`}`);
    const at = rng.int(parts.length + 1);
    const names = Object.keys(ENCODINGS);
    const encode = ENCODINGS[names[rng.int(names.length)] ?? 'raw'] ?? ((t: string) => t);
    parts.splice(at, 0, `"planted":"${encode(`>${VALUE}<`)}"`);
    const body = bytes(`{${parts.join(',')}}`);
    assert.notEqual(run(scannerFor(), randomChunks(body, rng)).hit, undefined);
  });
});
