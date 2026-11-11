// KBOX-14: response handling. The first half drives the pure streaming scanner (held values in every form, credential
// shapes, the hold counted in the stripped view, candidate decisions); the second half runs the relay over a fake upstream.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { request } from 'node:http';
import { test } from 'node:test';
import { gzipSync } from 'node:zlib';
import { scanForms } from '../src/pure/forms.ts';
import type { Form } from '../src/pure/forms.ts';
import { createResponseScanner, parseCredentialShapes } from '../src/pure/scanner.ts';
import type { CredentialShapes, ResponseScanner } from '../src/pure/scanner.ts';
import type { AuditRow } from '../src/ports/audit.ts';
import { relayErrorBody, upstreamRefusedBody } from '../src/pure/relay-errors.ts';
import { checkProperty, seedFor, waitUntil } from './kit/index.ts';
import type { SeededRandom } from './kit/index.ts';
import { relayWorld } from './support/relay-world.ts';
import type { RelayReply, RelayWorld } from './support/relay-world.ts';

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

/** `text` cut into lines of `width` characters with `eol` between them. */
const wrapText = (text: string, width: number, eol: string): string => (text.match(new RegExp(`.{1,${width}}`, 'g')) ?? []).join(eol);

test('KBOX-14 wrapped copies of the longest form (\\u-escaped) at 64 and 76 columns never release a copy byte early: a raw-byte hold of the same length would, by the removed line-break bytes', () => {
  const uEscaped = ENCODINGS['u-escaped'] ?? ((t: string) => t);
  const longest = Math.max(...formsOf(VALUE).map((f) => f.bytes.length));
  const copy = uEscaped(VALUE);
  assert.equal(copy.length, longest, 'the \\u form is the longest form, so the hold is its length minus 1');
  const seed = seedFor(process.env);
  checkProperty(seed, 3, (rng) => {
    for (const [width, eol] of [[64, '\r\n'], [76, '\r\n'], [64, '\\\n'], [76, '\n']] as const) {
      const lead = `{"blob":"${'q'.repeat(rng.int(300))}`;
      const wrappedCopy = wrapText(copy, width, eol);
      assert.ok(wrappedCopy.length > longest, 'the wrapped copy spans more raw bytes than the hold');
      const body = bytes(`${lead}${wrappedCopy}"}`);
      for (let cut = 1; cut < body.length; cut += 1) {
        const result = run(scannerFor(), splitAt(body, cut));
        assert.equal(result.hit, 'value', `width ${width} cut ${cut}`);
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

/** A PEM private-key boundary line, assembled at run time so the source holds no secret-shaped literal for the commit scan. */
const pemLine = (edge: 'BEGIN' | 'END', label: string): string => `${'-'.repeat(5)}${edge} ${label}PRIVATE KEY${'-'.repeat(5)}`;

test('KBOX-14 credential shapes are withheld: an sk- key, a JWT, a client_secret member and a PEM private-key header', () => {
  const jwtHeader = Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url');
  for (const body of [
    `{"key":"sk-${'a'.repeat(30)}"}`,
    `{"token":"${jwtHeader}.eyJzdWIiOiIxIn0.c2ln"}`,
    '{"client_secret":"x"}',
    '{ "client_secret" : "x" }',
    `${pemLine('BEGIN', 'RSA ')}\nMIIB\n${pemLine('END', 'RSA ')}`,
    `${pemLine('BEGIN', '')}\nMIIB`,
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

// ---------------------------------------------------------------- through the running relay

const MODELS = '/r/adminkey1/v1/models';
const heldText = (w: RelayWorld): string => Buffer.from(w.value).toString('utf8');
/** The longest form of the held value minus 1: the stripped characters the scanner holds back at the end of a stream. */
const holdOf = (w: RelayWorld): number => Math.max(...formsOf(heldText(w)).map((f) => f.bytes.length)) - 1;
const WITHHELD = relayErrorBody('withheld');
const relayRows = (w: RelayWorld): readonly AuditRow[] => w.lend.core.audit.read(0).entries.filter((r) => r.action === 'relay.request');
const settledRow = async (w: RelayWorld, count = 1): Promise<AuditRow> => {
  await waitUntil(() => relayRows(w).length >= count, 'the relay audit row');
  const row = relayRows(w)[count - 1];
  if (row === undefined) throw new Error('no row');
  return row;
};
const notices = (w: RelayWorld): readonly unknown[] => w.lend.core.events.after(0).filter((e) => e.kind === 'box.notice').map((e) => e.data);
/** Header names the HTTP layer itself adds to every answer, not chosen by the relay. */
const FRAMING = new Set(['date', 'connection', 'keep-alive', 'transfer-encoding']);
const chosenHeaders = (headers: RelayReply['headers']): string[] => Object.keys(headers).filter((h) => !FRAMING.has(h)).sort();
const FORCED = ['content-disposition', 'content-security-policy', 'x-content-type-options'];

test('KBOX-14 a 206, and a 200 carrying Content-Range, are 502 withheld with zero body bytes sent, audit reason partial and no owner notice', async (t) => {
  const w = await relayWorld(t);
  w.upstream.respond((_req, res) => {
    res.writeHead(206, { 'content-type': 'text/plain', 'content-range': 'bytes 0-9/100' });
    res.end('0123456789');
  });
  const partial = await w.call(MODELS);
  assert.deepEqual([partial.status, partial.body.toString()], [502, WITHHELD]);
  assert.equal((await settledRow(w)).detail['reason'], 'partial');
  w.upstream.respond((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain', 'content-range': 'bytes 0-9/100' });
    res.end('0123456789');
  });
  const ranged = await w.call(MODELS);
  assert.deepEqual([ranged.status, ranged.body.toString()], [502, WITHHELD]);
  assert.equal((await settledRow(w, 2)).detail['reason'], 'partial');
  assert.deepEqual(notices(w), []);
});

test('KBOX-14 Content-Encoding: gzip (body holding the value) and "gzip, identity" are 502 withheld with zero body bytes; identity passes', async (t) => {
  const w = await relayWorld(t);
  for (const encoding of ['gzip', 'gzip, identity', 'br']) {
    w.upstream.respond((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': encoding });
      res.end(`{"k":"${heldText(w)}"}`);
    });
    const reply = await w.call(MODELS);
    assert.deepEqual([reply.status, reply.body.toString()], [502, WITHHELD], encoding);
  }
  assert.equal((await settledRow(w, 3)).detail['reason'], 'encoded');
  w.upstream.respond((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'identity' });
    res.end('{"ok":true}');
  });
  const plain = await w.call(MODELS);
  assert.deepEqual([plain.status, plain.body.toString()], [200, '{"ok":true}']);
});

test('KBOX-14 an upstream 401 or 403 whose body quotes a key hint keeps its status and gets the fixed body, without WWW-Authenticate', async (t) => {
  const w = await relayWorld(t);
  const held = heldText(w);
  for (const status of [401, 403]) {
    w.upstream.respond((_req, res) => {
      res.writeHead(status, { 'content-type': 'application/json', 'www-authenticate': `Bearer realm="${held}"` });
      res.end(`{"error":{"message":"Incorrect API key provided: ${held.slice(0, 6)}...${held.slice(-4)}"}}`);
    });
    const reply = await w.call(MODELS);
    assert.deepEqual([reply.status, reply.body.toString(), reply.headers['www-authenticate']], [status, upstreamRefusedBody(), undefined]);
  }
});

test('KBOX-14 response headers are exactly the allow-list plus the three forced ones: Set-Cookie, Server and unlisted headers are dropped', async (t) => {
  const w = await relayWorld(t);
  w.upstream.respond((_req, res) => {
    res.writeHead(200, {
      'content-type': 'application/json',
      'content-length': '11',
      'x-request-id': 'req_123',
      'x-ratelimit-remaining': '99',
      'retry-after': '3',
      'set-cookie': 'sid=1; Secure',
      server: 'upstream/1.0',
      'x-powered-by': 'php',
      'access-control-allow-origin': '*',
      'x-other': 'x',
    });
    res.end('{"ok":true}');
  });
  const reply = await w.call(MODELS);
  assert.deepEqual(chosenHeaders(reply.headers), [...FORCED, 'content-length', 'content-type', 'retry-after', 'x-ratelimit-remaining', 'x-request-id'].sort());
  assert.deepEqual([reply.headers['x-content-type-options'], reply.headers['content-security-policy'], reply.headers['content-disposition']], ['nosniff', "sandbox; default-src 'none'", 'attachment']);
  assert.equal(reply.body.toString(), '{"ok":true}');
  const refused = await w.call('/r/adminkey1/v1/organization/admin_api_keys', { method: 'POST' });
  assert.deepEqual([refused.status, ...FORCED.map((h) => refused.headers[h] !== undefined)], [403, true, true, true]);
});

test('KBOX-14 a held value in an allowed header, or split across the last header and the body, is 502 withheld; the audit row and an owner notice follow', async (t) => {
  const w = await relayWorld(t);
  const held = heldText(w);
  w.upstream.respond((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'x-request-id': held });
    res.end('{}');
  });
  const inHeader = await w.call(MODELS);
  assert.deepEqual([inHeader.status, inHeader.body.toString()], [502, WITHHELD]);
  w.upstream.respond((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'x-request-id': held.slice(0, 16) });
    res.end(held.slice(16));
  });
  const split = await w.call(MODELS);
  assert.deepEqual([split.status, split.body.toString()], [502, WITHHELD]);
  const row = await settledRow(w, 2);
  assert.deepEqual([row.detail['code'], row.detail['reason'], row.detail['status']], ['withheld', 'value', 502]);
  await waitUntil(() => notices(w).length === 2, 'two notices');
  w.canary.assertAbsent({ 'relay journal': w.journal.join('\n') });
});

test('KBOX-14 a credential shape in the body is withheld with audit reason credential', async (t) => {
  const w = await relayWorld(t);
  w.upstream.respond((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(`{"key":"sk-${'A1b2'.repeat(10)}"}`);
  });
  const reply = await w.call(MODELS);
  assert.deepEqual([reply.status, reply.body.toString()], [502, WITHHELD]);
  assert.equal((await settledRow(w)).detail['reason'], 'credential');
});

test('KBOX-14 a hit after the head was sent cuts the stream: the caller gets no byte of the copy and upstream is disconnected', async (t) => {
  const w = await relayWorld(t);
  const lead = Buffer.from(`{"pad":"${'p'.repeat(256 * 1024)}","k":"`);
  let headSeen: () => void = () => undefined;
  const seen = new Promise<void>((resolve) => (headSeen = resolve));
  let upstreamClosed = false;
  w.upstream.respond(async (_req, res) => {
    res.socket?.once('close', () => (upstreamClosed = true));
    res.writeHead(200, { 'content-type': 'application/json' });
    res.write(lead);
    await seen;
    res.write(`${heldText(w)}"}`);
    for (let i = 0; i < 64 && !upstreamClosed; i += 1) {
      await new Promise<void>((resolve) => res.write('x'.repeat(64 * 1024), () => resolve()));
    }
    res.end();
  });
  const reply = await w.call(MODELS, { onBody: () => headSeen() });
  assert.deepEqual([reply.status, reply.complete], [200, false]);
  assert.ok(reply.body.length <= lead.length, `sent ${reply.body.length} > copy start ${lead.length}`);
  assert.ok(lead.subarray(0, reply.body.length).equals(reply.body), 'what was sent is a prefix of the clean lead');
  await waitUntil(() => upstreamClosed, 'the upstream connection to close');
  assert.equal((await settledRow(w)).detail['reason'], 'value');
});

type Cut = 'reset' | 'close without terminal chunk' | 'fewer bytes than Content-Length';
const CUTS: readonly Cut[] = ['reset', 'close without terminal chunk', 'fewer bytes than Content-Length'];

test('KBOX-14 a cut stream ends with no tail: after a prefix of the held value and a reset, early close or short body, no held byte reaches the caller, in each form', async (t) => {
  const w = await relayWorld(t);
  const held = heldText(w);
  const lead = Buffer.from(`{"pad":"${'p'.repeat(4096)}","k":"`);
  for (const [name, encode] of Object.entries(ENCODINGS)) {
    const form = encode(held);
    const prefix = Buffer.from(form.slice(0, Math.floor(form.length / 2)));
    const sent = Buffer.concat([lead, prefix]);
    for (const cut of CUTS) {
      let bodySeen: () => void = () => undefined;
      const seen = new Promise<void>((resolve) => (bodySeen = resolve));
      w.upstream.respond(async (_req, res) => {
        res.writeHead(200, cut === 'fewer bytes than Content-Length' ? { 'content-type': 'application/json', 'content-length': String(sent.length + 100) } : { 'content-type': 'application/json' });
        res.write(lead);
        await seen;
        res.write(prefix, () => {
          if (cut === 'reset') res.socket?.resetAndDestroy();
          else res.socket?.end();
        });
      });
      const reply = await w.call(MODELS, { onBody: () => bodySeen() });
      assert.deepEqual([reply.status, reply.complete], [200, false], `${name}, ${cut}: the caller sees a cut, not a clean end`);
      assert.ok(reply.body.length <= sent.length - holdOf(w), `${name}, ${cut}: ${reply.body.length} bytes reached the caller, past ${sent.length - holdOf(w)}`);
      assert.ok(sent.subarray(0, reply.body.length).equals(reply.body), `${name}, ${cut}: a prefix of what upstream sent`);
    }
  }
});

test('KBOX-14 a clean end releases the held tail: a prefix of the held value and a decoy candidate at the very end arrive whole', async (t) => {
  const w = await relayWorld(t);
  const body = `{"pad":"${'p'.repeat(4096)}","k":"${heldText(w).slice(0, 20)}","d":"sk-short`;
  w.upstream.respond((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(body);
  });
  const reply = await w.call(MODELS);
  assert.deepEqual([reply.status, reply.complete, reply.body.toString()], [200, true, body]);
});

test('KBOX-14 a response trailer carrying the held value is not passed; the body arrives whole', async (t) => {
  const w = await relayWorld(t);
  w.upstream.respond((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', trailer: 'x-trail' });
    res.write('{"ok":');
    res.addTrailers({ 'x-trail': heldText(w) });
    res.end('true}');
  });
  const reply = await w.call(MODELS);
  assert.deepEqual([reply.status, reply.complete, reply.body.toString(), reply.trailers, reply.headers['trailer']], [200, true, '{"ok":true}', {}, undefined]);
});

// ---------------------------------------------------------------- a caller that goes away, a stalled upstream, framing and headers

/** The unix-socket and pipe handles the process holds: the relay's, core's lend connections and the test client's. */
const pipeHandles = (): number => process.getActiveResourcesInfo().filter((r) => r === 'PipeWrap').length;

/** Waits until `read()` has moved at least once and then stayed put for `QUIET_POLLS` polls: a stream that has backed up. An early false "still" only makes a test less sharp, never fail it. */
const QUIET_POLLS = 10;
async function untilStill(read: () => number, what: string, timeoutMs = 10_000): Promise<void> {
  const deadline = performance.now() + timeoutMs;
  let last = -1;
  let quiet = 0;
  while (quiet < QUIET_POLLS) {
    if (performance.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise<void>((resolve) => setTimeout(resolve, 20));
    const now = read();
    quiet = now > 1 && now === last ? quiet + 1 : 0;
    last = now;
  }
}

test('KBOX-14, KBOX-50 a caller that pauses and then disconnects under backpressure still gets one audit row, leaks no lend connection and does not hold stop() up', { timeout: 30_000 }, async (t) => {
  const w = await relayWorld(t);
  const piece = Buffer.alloc(64 * 1024, 'a');
  let pieces = 0;
  w.upstream.respond(async (_req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    while (!res.destroyed) {
      pieces += 1;
      if (res.write(piece)) continue;
      await new Promise<void>((resolve) => {
        res.once('drain', resolve);
        res.once('close', resolve);
      });
    }
  });
  const handlesBefore = pipeHandles();
  const call = request({ socketPath: w.socket, path: MODELS, headers: { authorization: `Bearer ${w.pass}`, 'x-kb-client-ip': '203.0.113.9' } }, (res) => res.pause());
  call.on('error', () => undefined);
  call.end();
  // The paused caller backs the relay up, which backs the upstream up: the relay is waiting to write when the count stops moving.
  await untilStill(() => pieces, 'the relay to be held up by the paused caller');
  call.destroy();
  const row = await settledRow(w);
  assert.equal(row.detail['route'], 'relay');
  await w.upstream.lastClosed();
  await waitUntil(() => pipeHandles() <= handlesBefore, 'the scan connection to core to close');
  await w.stop();
  assert.equal(relayRows(w).length, 1, 'one audit row for the one request');
});

test('KBOX-14 a hit is cut at once, not when upstream sends its next chunk: the caller is answered while upstream is still stalled (before and after the head was sent)', { timeout: 30_000 }, async (t) => {
  const w = await relayWorld(t);
  let letGo: () => void = () => undefined;
  const stall = new Promise<void>((resolve) => (letGo = resolve));
  t.after(() => letGo());
  // before the head: the value is in the first chunk, then upstream says nothing more
  w.upstream.respond(async (_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.write(`{"k":"${heldText(w)}"}`);
    await stall;
  });
  let early: RelayReply | undefined;
  const first = w.call(MODELS).then((r) => void (early = r));
  await waitUntil(() => early !== undefined, 'the 502 before upstream continues', 2000);
  assert.deepEqual([early?.status, early?.body.toString()], [502, WITHHELD]);
  // after the head: a clean first chunk is released, then the value arrives and upstream stalls
  const lead = Buffer.from(`{"pad":"${'p'.repeat(256 * 1024)}","k":"`);
  let headSeen: () => void = () => undefined;
  const seen = new Promise<void>((resolve) => (headSeen = resolve));
  w.upstream.respond(async (_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.write(lead);
    await seen;
    res.write(`${heldText(w)}"}`);
    await stall;
  });
  let late: RelayReply | undefined;
  const second = w.call(MODELS, { onBody: () => headSeen() }).then((r) => void (late = r));
  await waitUntil(() => late !== undefined, 'the cut before upstream continues', 2000);
  assert.deepEqual([late?.status, late?.complete], [200, false]);
  letGo();
  await Promise.all([first, second]);
});

test('KBOX-14 a response Transfer-Encoding other than exactly chunked ("gzip, chunked") is 502 withheld with zero body bytes, audit reason encoded; chunked passes', async (t) => {
  const w = await relayWorld(t);
  w.upstream.respond((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain', 'transfer-encoding': 'gzip, chunked' });
    res.end(gzipSync(Buffer.from(`{"k":"${heldText(w)}"}`)));
  });
  const encoded = await w.call(MODELS);
  assert.deepEqual([encoded.status, encoded.body.toString()], [502, WITHHELD]);
  assert.equal((await settledRow(w)).detail['reason'], 'encoded');
  w.upstream.respond((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain', 'transfer-encoding': 'chunked' });
    res.write('one ');
    res.end('two');
  });
  const plain = await w.call(MODELS);
  assert.deepEqual([plain.status, plain.body.toString()], [200, 'one two']);
});

test('KBOX-14 Location is passed on a 3xx only: a 200 carrying one loses it, and the body arrives whole', async (t) => {
  const w = await relayWorld(t);
  w.upstream.respond((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain', location: 'https://elsewhere.example/x' });
    res.end('body');
  });
  const ok = await w.call(MODELS);
  assert.deepEqual([ok.status, ok.headers['location'], ok.body.toString()], [200, undefined, 'body']);
  w.upstream.respond((_req, res) => {
    res.writeHead(302, { location: 'https://elsewhere.example/x' });
    res.end();
  });
  const moved = await w.call(MODELS);
  assert.deepEqual([moved.status, moved.headers['location']], [302, 'https://elsewhere.example/x']);
});
