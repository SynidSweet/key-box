// KBOX-54: the one forms library for both scanners. Known-answer tables (devbox's own form functions as the oracle, plus
// hand-computed vectors), the substring property, the streaming matcher and its release point, wrapped copies, failure codes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { checkProperty, seedFor, seededRandom } from './kit/index.ts';
import type { SeededRandom } from './kit/index.ts';
import { coresOf, createMatcher, scanForms, shareForms, strippedView } from '../src/pure/forms.ts';
import type { Form, FormName, FormsResult, Match, Progress } from '../src/pure/forms.ts';

const seed = seedFor(process.env);
const enc = new TextEncoder();
const hexOf = (b: Uint8Array): string => Buffer.from(b).toString('hex');
const bytes = (s: string): Uint8Array => enc.encode(s);
const textOf = (b: Uint8Array): string => new TextDecoder().decode(b);

function at<T>(items: readonly T[], i: number): T {
  const item = items[i];
  if (item === undefined) throw new RangeError(`no element ${i} of ${items.length}`);
  return item;
}
function formsOrThrow(result: FormsResult): readonly Form[] {
  if (!result.ok) throw new Error(`forms refused: ${result.code}`);
  return result.forms;
}
const formNamed = (forms: readonly Form[], name: FormName): Form => {
  const found = forms.find((f) => f.name === name);
  if (found === undefined) throw new Error(`no form ${name}`);
  return found;
};
/** Every start of `needle` in `hay`, overlapping starts included. */
function occurrences(hay: Uint8Array, needle: Uint8Array): number[] {
  const out: number[] = [];
  const h = Buffer.from(hay);
  for (let i = h.indexOf(needle); i >= 0; i = h.indexOf(needle, i + 1)) out.push(i);
  return out;
}
const concat = (...parts: Uint8Array[]): Uint8Array => Buffer.concat(parts);

// ---------------------------------------------------------------- the oracle tables

interface OracleCase {
  readonly label: string;
  readonly valueHex: string;
  readonly prefix: string | null;
  readonly cores: readonly { readonly core: string; readonly hex: string }[];
  readonly forms: readonly { readonly core: string; readonly name: string; readonly hex: string }[];
}
const oracle = JSON.parse(readFileSync(new URL('./fixtures/forms/oracle.json', import.meta.url), 'utf8')) as { readonly cases: readonly OracleCase[] };
const optionsOf = (c: OracleCase): { prefix?: string } => (c.prefix === null ? {} : { prefix: c.prefix });
const valueOf = (c: OracleCase): string => Buffer.from(c.valueHex, 'hex').toString('utf8');
const SHARE_NAMES: ReadonlySet<string> = new Set(['raw', 'b64-0', 'b64-1', 'b64-2', 'b64url-0', 'b64url-1', 'b64url-2']);

test('KBOX-54 the oracle file holds every kind of value the forms treat differently', () => {
  assert.ok(oracle.cases.length >= 16);
  const names = new Set(oracle.cases.flatMap((c) => c.forms.map((f) => f.name)));
  for (const n of ['raw', 'b64-0', 'b64-1', 'b64-2', 'b64url-0', 'b64url-1', 'b64url-2', 'hex', 'HEX', 'percent', 'json', 'json-slash', 'u-lower', 'u-upper']) {
    assert.ok(names.has(n), `the oracle has no ${n} form`);
  }
  assert.ok(oracle.cases.some((c) => c.cores.some((core) => core.core === 'decoded')));
});

for (const c of oracle.cases) {
  test(`KBOX-54 cores and scanForms equal devbox's forms for: ${c.label}`, () => {
    const value = valueOf(c);
    assert.deepEqual(coresOf(value, optionsOf(c)).map((core) => hexOf(bytes(core))), c.cores.map((core) => core.hex));
    const got = formsOrThrow(scanForms(value, optionsOf(c))).map((f) => ({ core: f.core, name: f.name, hex: hexOf(f.bytes) }));
    assert.deepEqual(got, c.forms);
  });

  test(`KBOX-54 shareForms are raw plus the six base64 interiors of each core, for: ${c.label}`, () => {
    const got = formsOrThrow(shareForms(valueOf(c), optionsOf(c))).map((f) => ({ core: f.core, name: f.name, hex: hexOf(f.bytes) }));
    assert.deepEqual(got, c.forms.filter((f) => SHARE_NAMES.has(f.name)));
  });
}

test('KBOX-54 hand-computed vectors: a 3-byte core "Man" in base64 at the three alignments, hex and u-escapes', () => {
  const forms = formsOrThrow(scanForms('Man'));
  const text = (name: FormName): string => textOf(formNamed(forms, name).bytes);
  assert.equal(text('raw'), 'Man');
  assert.equal(text('b64-0'), 'TWFu');
  assert.equal(text('b64-1'), '1hb');
  assert.equal(text('b64-2'), 'NYW');
  assert.equal(text('b64url-1'), '1hb');
  assert.equal(text('hex'), '4d616e');
  assert.equal(text('HEX'), '4D616E');
  assert.equal(text('u-lower'), '\\u004d\\u0061\\u006e');
  assert.equal(text('u-upper'), '\\u004D\\u0061\\u006E');
  assert.deepEqual(forms.map((f) => f.name).filter((n) => n === 'percent' || n === 'json' || n === 'json-slash'), []);
});

test('KBOX-54 hand-computed vectors: a 2-byte core "ab" has a two-character interior at every alignment', () => {
  const forms = formsOrThrow(scanForms('ab'));
  const text = (name: FormName): string => textOf(formNamed(forms, name).bytes);
  assert.equal(text('b64-0'), 'YW');
  assert.equal(text('b64-1'), 'Fi');
  assert.equal(text('b64-2'), 'hY');
  assert.equal(text('hex'), '6162');
});

test('KBOX-54 hand-computed vectors: the + of base64 is - in the url forms, and a slash gets percent and json forms', () => {
  // "~~~" is 7e 7e 7e = 011111 100111 111001 111110 = 31 39 57 62 = "fn5" then "+" (standard) or "-" (url)
  const tildes = formsOrThrow(scanForms('~~~'));
  assert.equal(textOf(formNamed(tildes, 'b64-0').bytes), 'fn5+');
  assert.equal(textOf(formNamed(tildes, 'b64url-0').bytes), 'fn5-');
  const slash = formsOrThrow(scanForms('a/b'));
  assert.deepEqual(slash.filter((f) => f.name === 'percent').map((f) => textOf(f.bytes)), ['a%2Fb', 'a%2fb']);
  assert.deepEqual(slash.filter((f) => f.name === 'json-slash').map((f) => textOf(f.bytes)), ['a\\/b']);
  assert.deepEqual(slash.filter((f) => f.name === 'json').map((f) => textOf(f.bytes)), []);
});

test('KBOX-54 cores: a JWT gives its signature, a known or declared prefix the rest, a URL its password as written and decoded', () => {
  const part = (s: string): string => Buffer.from(s).toString('base64url');
  const sig = part('0123456789abcdefghijklmnopqrstuv');
  assert.deepEqual(coresOf(`${part('{"alg":"HS256"}')}.${part('{"sub":"x"}')}.${sig}`), [sig]);
  const noAlg = `${part('{"typ":"JWT"}')}.${part('{"sub":"x"}')}.${sig}`;
  assert.deepEqual(coresOf(noAlg), [noAlg]);
  assert.deepEqual(coresOf(`${part('["alg"]')}.${part('{}')}.${sig}`), [`${part('["alg"]')}.${part('{}')}.${sig}`]);
  assert.deepEqual(coresOf(`${part('not json')}.${part('{}')}.${sig}`), [`${part('not json')}.${part('{}')}.${sig}`]);
  assert.deepEqual(coresOf('sb_secret_Zk3Lm9Qw'), ['Zk3Lm9Qw']);
  assert.deepEqual(coresOf('GOCSPX-abcDEF'), ['abcDEF']);
  assert.deepEqual(coresOf('tok_abcdef', { prefix: 'tok_' }), ['abcdef']);
  assert.deepEqual(coresOf('tok_abcdef'), ['tok_abcdef']);
  assert.deepEqual(coresOf('postgres://u:p%41ss@h/x'), ['p%41ss', 'pAss']);
  assert.deepEqual(coresOf('postgres://u:plain@h/x'), ['plain']);
  assert.deepEqual(coresOf('https://u@h/x'), ['https://u@h/x']);
  assert.deepEqual(coresOf('mailto:u:pw@h'), ['mailto:u:pw@h']);
  assert.deepEqual(coresOf('x://:onlypw@h'), ['onlypw']);
  assert.deepEqual(coresOf('x://a:b@c@h/p'), ['b@c']);
});

// ---------------------------------------------------------------- failure paths: fixed codes, never a part of the value

test('KBOX-54 failure paths return fixed codes: empty value, empty core, a core shorter than any form window, a NUL', () => {
  const refusals: readonly (readonly [string, string])[] = [
    ['', 'empty'],
    ['sb_secret_', 'empty'],
    ['x://user:@host/p', 'empty'],
    ['a', 'short-core'],
    ['sb_secret_Q', 'short-core'],
    ['x://u:%41@h/p', 'short-core'],
    ['abc\u0000def', 'nul'],
  ];
  for (const [value, code] of refusals) {
    for (const make of [scanForms, shareForms]) {
      assert.deepEqual(make(value), { ok: false, code }, `${JSON.stringify(value)} through ${make.name}`);
    }
  }
});

test('KBOX-54 the smallest accepted core is two bytes; a two-byte core has every form non-empty', () => {
  for (const value of ['ab', '\u00e9']) {
    const forms = formsOrThrow(scanForms(value));
    assert.ok(forms.length >= 11);
    for (const f of forms) assert.ok(f.bytes.length > 0, `${f.name} is empty`);
  }
});

test('KBOX-54 a refusal carries no part of the value, and a bad matcher call fails with fixed text', () => {
  const secret = 'KB54-ZZ-unique-value-text';
  const failure = scanForms(`${secret}\u0000`);
  assert.equal(JSON.stringify(failure).includes('KB54'), false);
  assert.deepEqual(Object.keys(failure).sort(), ['code', 'ok']);
  const good = formsOrThrow(scanForms(secret));
  assert.throws(() => createMatcher([{ name: 'raw', core: 'written', bytes: new Uint8Array(0) }]), (e: unknown) => e instanceof RangeError && !String(e).includes('KB54'));
  const matcher = createMatcher(good);
  matcher.end();
  assert.throws(() => matcher.feed(bytes('x')), RangeError);
  assert.throws(() => matcher.end(), RangeError);
});

// ---------------------------------------------------------------- property: every form of a core is inside the same encoding of prefix, core, suffix

const CORE_CHARS: readonly string[] = [...Array.from({ length: 0x7e - 0x20 + 1 }, (_, i) => String.fromCharCode(0x20 + i)).filter((c) => c !== ':'), '\n', '\t'];
const WIDE_CHARS: readonly string[] = [...CORE_CHARS, '\u00e9', '\u00f1', '\u20ac', '\u{1f600}', '\u00ff'];
function randomText(rng: SeededRandom, alphabet: readonly string[], min: number, max: number): string {
  let out = '';
  for (let n = min + rng.int(max - min + 1); n > 0; n -= 1) out += at(alphabet, rng.int(alphabet.length));
  return out;
}
const strictPercent = (s: string): string => encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
const lowerEscapes = (s: string): string => s.replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase());
const percentStyles: readonly ((s: string) => string)[] = [
  strictPercent,
  (s) => strictPercent(s).replaceAll('%2F', '/'),
  encodeURIComponent,
];
const everyCharEscaped = (s: string, upper: boolean): string =>
  Array.from({ length: s.length }, (_, i) => {
    const hex = s.charCodeAt(i).toString(16).padStart(4, '0');
    return `\\u${upper ? hex.toUpperCase() : hex}`;
  }).join('');

test('KBOX-54 property: every form of a core is found inside the same encoding of prefix, core and suffix, at some alignment', () => {
  checkProperty(seed, 400, (rng) => {
    const core = randomText(rng, WIDE_CHARS, 2, 40);
    const prefix = randomText(rng, WIDE_CHARS, 0, 11);
    const suffix = randomText(rng, WIDE_CHARS, 0, 11);
    const whole = prefix + core + suffix;
    const forms = formsOrThrow(scanForms(core));
    const inside = (names: readonly FormName[], encoded: string): void => {
      const hit = forms.some((f) => names.includes(f.name) && encoded.includes(textOf(f.bytes)));
      assert.ok(hit, `${names.join('|')} of core ${JSON.stringify(core)} not inside encoding of ${JSON.stringify(whole)}`);
    };
    const align = Buffer.byteLength(prefix) % 3;
    inside(['raw'], whole);
    inside([`b64-${align}` as FormName], Buffer.from(whole).toString('base64'));
    inside([`b64url-${align}` as FormName], Buffer.from(whole).toString('base64url'));
    inside(['hex'], Buffer.from(whole).toString('hex'));
    inside(['HEX'], Buffer.from(whole).toString('hex').toUpperCase());
    for (const style of percentStyles) {
      inside(['percent', 'raw'], style(whole));
      inside(['percent', 'raw'], lowerEscapes(style(whole)));
    }
    inside(['u-lower'], everyCharEscaped(whole, false));
    inside(['u-upper'], everyCharEscaped(whole, true));
  });
});

test('KBOX-54 property: the json and json-slash forms of an ASCII core are inside the JSON string of prefix, core and suffix', () => {
  checkProperty(seed, 400, (rng) => {
    const core = randomText(rng, CORE_CHARS.concat(['"', '\\', '/', '/']), 2, 40);
    const prefix = randomText(rng, CORE_CHARS.concat(['/', '"']), 0, 11);
    const suffix = randomText(rng, CORE_CHARS.concat(['/', '\\']), 0, 11);
    const forms = formsOrThrow(scanForms(core));
    const json = JSON.stringify(prefix + core + suffix).slice(1, -1);
    assert.ok(forms.some((f) => (f.name === 'json' || f.name === 'raw') && json.includes(textOf(f.bytes))), `json of ${JSON.stringify(core)}`);
    const slashed = json.replaceAll('/', '\\/');
    assert.ok(forms.some((f) => (f.name === 'json-slash' || f.name === 'json' || f.name === 'raw') && slashed.includes(textOf(f.bytes))), `json-slash of ${JSON.stringify(core)}`);
    if (core.includes('/')) assert.ok(forms.some((f) => f.name === 'json-slash' && slashed.includes(textOf(f.bytes))), 'a core with a slash needs the json-slash form');
  });
});

test('KBOX-54 property: the share forms of a core are the raw form and the six base64 interiors, found at the right alignment', () => {
  checkProperty(seed, 200, (rng) => {
    const core = randomText(rng, WIDE_CHARS, 2, 40);
    const prefix = randomText(rng, WIDE_CHARS, 0, 11);
    const forms = formsOrThrow(shareForms(core));
    assert.deepEqual(forms.map((f) => f.name), ['raw', 'b64-0', 'b64-1', 'b64-2', 'b64url-0', 'b64url-1', 'b64url-2']);
    const align = Buffer.byteLength(prefix) % 3;
    const whole = Buffer.from(prefix + core).toString('base64');
    assert.ok(whole.includes(textOf(formNamed(forms, `b64-${align}` as FormName).bytes)));
  });
});

// ---------------------------------------------------------------- the stripped view

const decodeView = (raw: string): { text: string; offsets: readonly number[] } => {
  const view = strippedView(bytes(raw));
  return { text: textOf(view.bytes).replaceAll('\u0000', '|'), offsets: view.offsets };
};

test('KBOX-54 stripped view: whitespace and the backslash-newline pattern of at most 4 bytes are removed, with a map back to raw offsets', () => {
  assert.deepEqual(decodeView('ab\r\ncd'), { text: 'abcd', offsets: [0, 1, 4, 5] });
  assert.deepEqual(decodeView('ab\ncd'), { text: 'abcd', offsets: [0, 1, 3, 4] });
  assert.deepEqual(decodeView('ab\\\ncd'), { text: 'abcd', offsets: [0, 1, 4, 5] });
  assert.deepEqual(decodeView('ab\\\r\ncd'), { text: 'abcd', offsets: [0, 1, 5, 6] });
  assert.deepEqual(decodeView('a b\tc\u000bd\u000ce'), { text: 'abcde', offsets: [0, 2, 4, 6, 8] });
  assert.deepEqual(decodeView('ab    cd'), { text: 'abcd', offsets: [0, 1, 6, 7] });
  assert.deepEqual(decodeView('ab\\\r\n cd'), { text: 'abcd', offsets: [0, 1, 6, 7] });
});

test('KBOX-54 stripped view: a backslash not before a line break stays, and so does the first of two', () => {
  assert.deepEqual(decodeView('ab\\cd'), { text: 'ab\\cd', offsets: [0, 1, 2, 3, 4] });
  assert.deepEqual(decodeView('ab\\\\\ncd'), { text: 'ab\\cd', offsets: [0, 1, 2, 5, 6] });
  assert.deepEqual(decodeView('ab\\\rcd'), { text: 'ab\\cd', offsets: [0, 1, 2, 4, 5] });
  assert.deepEqual(decodeView('ab\\'), { text: 'ab\\', offsets: [0, 1, 2] });
  assert.deepEqual(decodeView('ab\\\r'), { text: 'ab\\', offsets: [0, 1, 2] });
  assert.deepEqual(decodeView(''), { text: '', offsets: [] });
});

test('KBOX-54 stripped view: a run longer than 4 bytes is kept as ONE separator byte, at the run\'s first raw offset', () => {
  assert.deepEqual(decodeView('ab     cd'), { text: 'ab|cd', offsets: [0, 1, 2, 7, 8] });
  assert.deepEqual(decodeView('ab\\\r\n  cd'), { text: 'ab|cd', offsets: [0, 1, 2, 7, 8] });
  assert.deepEqual(decodeView('ab\r\n\r\n\r\ncd'), { text: 'ab|cd', offsets: [0, 1, 2, 8, 9] });
  assert.deepEqual(decodeView('ab' + ' '.repeat(100) + 'cd'), { text: 'ab|cd', offsets: [0, 1, 2, 102, 103] });
  assert.deepEqual(decodeView('ab  \t  \n\n'), { text: 'ab|', offsets: [0, 1, 2] });
});

// ---------------------------------------------------------------- the streaming matcher

/** Feeds `data` cut at `cuts` (ascending offsets), then ends the stream. */
function run(forms: readonly Form[], data: Uint8Array, cuts: readonly number[]): { steps: readonly { fed: number; progress: Progress }[]; matches: readonly Match[] } {
  const matcher = createMatcher(forms);
  const steps: { fed: number; progress: Progress }[] = [];
  let from = 0;
  for (const cut of [...cuts, data.length]) {
    steps.push({ fed: cut, progress: matcher.feed(data.subarray(from, cut)) });
    from = cut;
  }
  steps.push({ fed: data.length, progress: matcher.end() });
  return { steps, matches: steps.flatMap((s) => s.progress.matches) };
}
const everyCut = (n: number): number[] => Array.from({ length: Math.max(0, n - 1) }, (_, i) => i + 1);
const filler = (rng: SeededRandom, n: number): Uint8Array => bytes(randomText(rng, [...'abcdefghijklmnopqrstuvwxyz0123456789 \n'], n, n));

test('KBOX-54 matcher: a copy in one chunk is found once, with its raw offsets and the index of its form', () => {
  const forms = formsOrThrow(scanForms('Zr7Qp-L2xW9vKm'));
  const target = formNamed(forms, 'hex');
  const data = bytes(`log line ${textOf(target.bytes)} tail`);
  const { matches } = run(forms, data, []);
  const own = matches.filter((m) => m.name === 'hex');
  assert.deepEqual(own, [{ index: forms.indexOf(target), name: 'hex', start: 9, end: 9 + target.bytes.length }]);
});

test('KBOX-54 matcher: no form means nothing is held back and nothing is found', () => {
  const { steps, matches } = run([], bytes('anything at all'), [5]);
  assert.deepEqual(matches, []);
  assert.deepEqual(steps.map((s) => s.progress.releasable), [5, 15, 15]);
});

test('KBOX-54 matcher: a raw copy that holds a space is found in the raw view, which the stripped view cannot show', () => {
  const forms = formsOrThrow(scanForms('two words here'));
  const { matches } = run(forms, bytes('xx two words here yy'), everyCut(20));
  assert.deepEqual(matches.filter((m) => m.name === 'raw'), [{ index: 0, name: 'raw', start: 3, end: 17 }]);
});

test('KBOX-54 matcher: a copy whose last byte is a backslash before a newline is found, and held until then, at every split', () => {
  const forms = formsOrThrow(scanForms('abcdefghij\\'));
  const json = formNamed(forms, 'json');
  assert.equal(textOf(json.bytes).endsWith('\\\\'), true);
  const data = bytes(`..${textOf(json.bytes)}\n..`);
  const start = 2;
  const end = start + json.bytes.length;
  for (const cut of everyCut(data.length)) {
    const { steps, matches } = run([json], data, [cut]);
    assert.deepEqual(matches, [{ index: 0, name: 'json', start, end }], `cut ${cut}`);
    const first = at(steps, 0);
    if (first.progress.matches.length === 0) assert.ok(first.progress.releasable <= start, `cut ${cut} released ${first.progress.releasable}`);
  }
});

test('KBOX-54 a copy that starts with a backslash still waiting for its line break is held, even when the form is only two bytes long', () => {
  const form: Form = { name: 'raw', core: 'written', bytes: bytes('\\X') };
  const data = bytes('\\\rXb');
  const planted: Planted = { data, start: 0, end: 3 };
  assertSafeAtEverySplit([form], planted, 0, 'two-byte form');
});

// ---------------------------------------------------------------- property: split anywhere, found exactly once, the release point never passes a copy

const COPY_CHARS = [...'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.~+/=-'];
interface Wrap {
  readonly label: string;
  readonly width: number;
  readonly sep: string;
}
const WRAPS: readonly Wrap[] = [
  { label: 'unwrapped', width: Number.POSITIVE_INFINITY, sep: '' },
  { label: '64 columns CRLF', width: 64, sep: '\r\n' },
  { label: '76 columns CRLF', width: 76, sep: '\r\n' },
  { label: '64 columns LF', width: 64, sep: '\n' },
  { label: '64 columns backslash-LF', width: 64, sep: '\\\n' },
  { label: '76 columns backslash-CRLF', width: 76, sep: '\\\r\n' },
  { label: '20 columns CRLF plus two spaces', width: 20, sep: '\r\n  ' },
];
function wrapped(form: Uint8Array, wrap: Wrap): string {
  const text = textOf(form);
  let out = '';
  for (let i = 0; i < text.length; i += wrap.width) out += (i === 0 ? '' : wrap.sep) + text.slice(i, i + wrap.width);
  return out;
}
interface Planted {
  readonly data: Uint8Array;
  readonly start: number;
  readonly end: number;
}
function plant(rng: SeededRandom, form: Uint8Array, wrap: Wrap): Planted {
  const head = filler(rng, 3 + rng.int(25));
  const body = bytes(wrapped(form, wrap));
  const tail = filler(rng, 3 + rng.int(25));
  return { data: concat(head, body, tail), start: head.length, end: head.length + body.length };
}

/** One stream of cuts: found exactly once, the release point only forward, and no byte of a copy released before it is found. */
function assertSafeStream(forms: readonly Form[], planted: Planted, planIndex: number, cuts: readonly number[], why: string): void {
  const { steps, matches } = run(forms, planted.data, cuts);
  const own = matches.filter((m) => m.index === planIndex);
  assert.deepEqual(own, [{ index: planIndex, name: at(forms, planIndex).name, start: planted.start, end: planted.end }], `${why}: found exactly once`);
  let found = false;
  let last = 0;
  for (const step of steps) {
    if (step.progress.matches.some((m) => m.index === planIndex)) found = true;
    assert.ok(step.progress.releasable >= last, `${why}: the release point went back`);
    assert.ok(step.progress.releasable <= step.fed, `${why}: released bytes not yet fed`);
    last = step.progress.releasable;
    if (!found) assert.ok(step.progress.releasable <= planted.start, `${why}: after ${step.fed} bytes the release point ${step.progress.releasable} passed the copy at ${planted.start}`);
  }
  assert.equal(at(steps, steps.length - 1).progress.releasable, planted.data.length, `${why}: a clean end releases everything`);
}
/** The release-point property at EVERY two-chunk split, and fed one byte at a time. */
function assertSafeAtEverySplit(forms: readonly Form[], planted: Planted, planIndex: number, why: string): void {
  const cuts = everyCut(planted.data.length);
  for (const cut of cuts) assertSafeStream(forms, planted, planIndex, [cut], `${why}, split at ${cut}`);
  assertSafeStream(forms, planted, planIndex, cuts, `${why}, byte by byte`);
}
/** True when a hold of (form length - 1) RAW bytes would have released a byte of the copy at some split before it was complete. */
const rawHoldLeaks = (formLength: number, planted: Planted): boolean =>
  everyCut(planted.end).some((fed) => Math.max(0, fed - (formLength - 1)) > planted.start);

test('KBOX-54 property: a copy split at EVERY chunk boundary is found exactly once and the release point never passes its start (wrapped copies included)', () => {
  let rawHoldWouldLeak = 0;
  checkProperty(seed, 8, (rng) => {
    const core = randomText(rng, COPY_CHARS, 60, 72);
    const all = formsOrThrow(scanForms(core));
    const base64Forms = all.filter((f) => f.name.startsWith('b64'));
    for (const wrap of WRAPS) {
      const form = at(base64Forms, rng.int(base64Forms.length));
      const planted = plant(rng, form.bytes, wrap);
      // a matcher over this one form: its hold is the form's own length minus 1
      assertSafeAtEverySplit([form], planted, 0, `${wrap.label}, one form ${form.name}`);
      // the same copy against every form of the core: the hold is the longest form's
      assertSafeAtEverySplit(all, planted, all.indexOf(form), `${wrap.label}, every form, ${form.name}`);
      // an independent check that the scenario has teeth: a raw-byte hold would have released part of a wrapped copy
      if (wrap.sep !== '' && rawHoldLeaks(form.bytes.length, planted)) rawHoldWouldLeak += 1;
    }
  });
  assert.ok(rawHoldWouldLeak > 0, 'no wrapped scenario would have fooled a raw-byte hold');
});

test('KBOX-54 property: the same holds for forms made of backslashes, and for a copy followed by a backslash-newline', () => {
  checkProperty(seed, 8, (rng) => {
    const core = randomText(rng, COPY_CHARS, 24, 36);
    const all = formsOrThrow(scanForms(core));
    for (const name of ['u-lower', 'u-upper'] as const) {
      const form = formNamed(all, name);
      const head = filler(rng, 3 + rng.int(20));
      const tail = bytes('\\\n..');
      const planted: Planted = { data: concat(head, form.bytes, tail), start: head.length, end: head.length + form.bytes.length };
      assertSafeAtEverySplit(all, planted, all.indexOf(form), name);
    }
  });
});

// ---------------------------------------------------------------- wrapped copies are found in the stripped view and map back

test('KBOX-54 a wrapped copy (base64 at 64 and 76 columns with CRLF, backslash-newline) is found only in the stripped view and maps back to its raw offsets', () => {
  const rng = seededRandom(seed);
  const core = randomText(rng, COPY_CHARS, 60, 72);
  const forms = formsOrThrow(scanForms(core));
  const form = formNamed(forms, 'b64-0');
  for (const wrap of WRAPS.filter((w) => w.sep !== '')) {
    const planted = plant(rng, form.bytes, wrap);
    assert.equal(occurrences(planted.data, form.bytes).length, 0, `${wrap.label}: the raw bytes must not hold the copy`);
    const view = strippedView(planted.data);
    const at0 = occurrences(view.bytes, form.bytes);
    assert.equal(at0.length, 1, `${wrap.label}: found once in the stripped view`);
    const first = at(at0, 0);
    assert.equal(at(view.offsets, first), planted.start, `${wrap.label}: start maps back`);
    assert.equal(at(view.offsets, first + form.bytes.length - 1) + 1, planted.end, `${wrap.label}: end maps back`);
    const { matches } = run([form], planted.data, [Math.floor(planted.data.length / 2)]);
    assert.deepEqual(matches, [{ index: 0, name: 'b64-0', start: planted.start, end: planted.end }], wrap.label);
  }
});

// ---------------------------------------------------------------- a whitespace run longer than 4 bytes ends every copy

test('KBOX-54 a run of at most 4 line-break or space bytes is joined, a run of 5 is not: at, below and above the limit, at every split', () => {
  const core = 'Qw3Lm9ZkTv7XbN2rYp';
  const forms = formsOrThrow(scanForms(core));
  const raw = formNamed(forms, 'raw');
  const runs: readonly (readonly [string, boolean])[] = [
    ['', true],
    [' ', true],
    ['    ', true],
    ['     ', false],
    ['\r\n', true],
    ['\\\r\n', true],
    ['\\\r\n ', true],
    ['\\\r\n  ', false],
    ['\r\n\r\n', true],
    ['\r\n\r\n\n', false],
    ['\t\t\t\t\t\t', false],
  ];
  for (const [ws, joined] of runs) {
    const text = `xx${core.slice(0, 9)}${ws}${core.slice(9)}yy`;
    const data = bytes(text);
    for (const cuts of [[], ...everyCut(data.length).map((c) => [c])]) {
      const found = run([raw], data, cuts).matches;
      if (joined) assert.deepEqual(found, [{ index: 0, name: 'raw', start: 2, end: text.length - 2 }], `${JSON.stringify(ws)} cuts ${cuts.join()}`);
      else assert.deepEqual(found, [], `${JSON.stringify(ws)} cuts ${cuts.join()}`);
    }
  }
});

test('KBOX-54 the held raw bytes of a 10 MiB run of line breaks are constant, not growing with the run', () => {
  const forms = formsOrThrow(scanForms('Qw3Lm9ZkTv7XbN2rYpAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'));
  const longest = Math.max(...forms.map((f) => f.bytes.length));
  const matcher = createMatcher(forms);
  const chunk = Buffer.from('\r\n'.repeat(32 * 1024));
  matcher.feed(bytes('head'));
  let fed = 4;
  const held: number[] = [];
  for (let sent = 0; sent < 10 * 1024 * 1024; sent += chunk.length) {
    const progress = matcher.feed(chunk);
    assert.deepEqual(progress.matches, []);
    fed += chunk.length;
    held.push(fed - progress.releasable);
  }
  assert.ok(held.length >= 160);
  assert.ok(Math.max(...held) <= longest - 1, `held ${Math.max(...held)} raw bytes, the longest form is ${longest}`);
  assert.deepEqual(new Set(held.slice(1)).size, 1, 'the held count changes from chunk to chunk');
  const last = matcher.end();
  assert.equal(last.releasable, fed);
});

// ---------------------------------------------------------------- decoys

test('KBOX-54 a decoy that differs in one interior core byte is never found, in any form, at any alignment', () => {
  checkProperty(seed, 60, (rng) => {
    const core = randomText(rng, COPY_CHARS, 24, 40);
    const at1 = 1 + rng.int(core.length - 2);
    const other = at(COPY_CHARS.filter((c) => c !== core.charAt(at1)), rng.int(COPY_CHARS.length - 1));
    const decoy = core.slice(0, at1) + other + core.slice(at1 + 1);
    const real = formsOrThrow(scanForms(core));
    const decoyForms = formsOrThrow(scanForms(decoy));
    const text = concat(...decoyForms.map((f) => concat(f.bytes, bytes(' | '))));
    assert.deepEqual(run(real, text, []).matches, [], `core ${core} decoy ${decoy}`);
    assert.equal(run(decoyForms, text, []).matches.length >= decoyForms.length, true, 'the decoy forms are in the text');
  });
});

test('KBOX-54 a decoy that differs only in the first or last core byte can match a base64 interior and nothing else', () => {
  const core = 'Qw3Lm9ZkTv7XbN2rYpAa';
  const decoys = ['aw3Lm9ZkTv7XbN2rYpAa', 'Qw3Lm9ZkTv7XbN2rYpA`'];
  const real = formsOrThrow(scanForms(core));
  for (const decoy of decoys) {
    const text = concat(...formsOrThrow(scanForms(decoy)).map((f) => concat(f.bytes, bytes(' | '))));
    const names = new Set(run(real, text, []).matches.map((m) => m.name));
    for (const name of names) assert.ok(name.startsWith('b64'), `${decoy} matched the ${name} form`);
    assert.ok(names.size > 0, `${decoy}: an edge byte can sit outside an interior (documented limit of the interiors)`);
  }
});
