// KBOX-6 (intake and approval): the tar the box takes, the content hash H it computes itself, POST /api/updates, the
// install_update executor and the trust requests core sends to root. kb-install itself is tested in install-helper.test.ts.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { parseTar } from '../src/pure/tar.ts';
import { releaseHash, releaseText } from '../src/pure/release-hash.ts';
import { gitGlobalHeader, tarOf } from './support/tar.ts';
import type { TarEntrySpec } from './support/tar.ts';

const C = 'c0ffee'.padEnd(40, '0');
const sha = (s: string | Uint8Array): string => createHash('sha256').update(s).digest('hex');

const refusesTar = (entries: readonly TarEntrySpec[], code: string, why: string): void => {
  const parsed = parseTar(tarOf(entries));
  assert.deepEqual(parsed, { ok: false, code }, why);
};

// --- the tar refusal table --------------------------------------------------------------------------------------------

test('KBOX-6 a git-archive style tar (one global pax header first, directories, files) parses to its files and modes', () => {
  const parsed = parseTar(tarOf([gitGlobalHeader(C), { name: 'src/', type: '5', mode: 0o775 }, { name: 'src/a.ts', body: 'one\n', mode: 0o664 }, { name: 'run.sh', body: '#!/bin/sh\n', mode: 0o775 }]));
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;
  assert.deepEqual(
    parsed.entries.map((e) => (e.kind === 'dir' ? ['dir', e.path] : ['file', e.path, e.executable, Buffer.from(e.bytes).toString()])),
    [['dir', 'src'], ['file', 'src/a.ts', false, 'one\n'], ['file', 'run.sh', true, '#!/bin/sh\n']],
  );
});

for (const [flag, why] of [['1', 'a hard link'], ['2', 'a symlink'], ['3', 'a character device'], ['4', 'a block device'], ['6', 'a FIFO'], ['7', 'a contiguous file'], ['S', 'an unknown type']] as const) {
  test(`KBOX-6 ${why} in the tar is refused entry_type`, () => refusesTar([{ name: 'x', type: flag, linkname: flag === '1' || flag === '2' ? '/etc/shadow' : '' }], 'entry_type', why));
}

test('KBOX-6 a pax x header, a GNU long name or long link header and a second g header are refused extended_header', () => {
  refusesTar([{ name: 'PaxHeader/x', type: 'x', body: '11 path=a\n' }, { name: 'a', body: 'a' }], 'extended_header', 'pax x');
  refusesTar([{ name: '././@LongLink', type: 'L', body: 'long' }, { name: 'a', body: 'a' }], 'extended_header', 'GNU L');
  refusesTar([{ name: '././@LongLink', type: 'K', body: 'long' }, { name: 'a', body: 'a' }], 'extended_header', 'GNU K');
  refusesTar([gitGlobalHeader(C), gitGlobalHeader(C), { name: 'a', body: 'a' }], 'extended_header', 'a second g header');
  refusesTar([{ name: 'a', body: 'a' }, gitGlobalHeader(C)], 'extended_header', 'a g header that is not the first entry');
});

const badNames: readonly (readonly [string | Uint8Array, string])[] = [
  ['/etc/passwd', 'an absolute path'],
  ['../up', 'a path with ..'],
  ['a/../../up', 'a path with .. inside'],
  ['a/./b', 'a path with a . segment'],
  ['a//b', 'an empty segment'],
  ['a\nb', 'a newline'],
  ['a\tb', 'a tab (another control byte)'],
  ['a\u007fb', 'DEL'],
  ['a\\b', 'a backslash'],
  [Uint8Array.from([0x61, 0xff, 0x62]), 'invalid UTF-8'],
  [Uint8Array.from([0x61, 0xc0, 0xaf]), 'an overlong UTF-8 slash'],
];
for (const [name, why] of badNames) test(`KBOX-6 a tar path with ${why} is refused name`, () => refusesTar([{ name, body: 'x' }], 'name', why));

test('KBOX-6 a NUL inside a tar name field is refused name (the name does not end at the first NUL with more bytes after it)', () => {
  refusesTar([{ name: Uint8Array.from([0x61, 0x00, 0x62]), body: 'x' }], 'name', 'a NUL then more name bytes');
});

test('KBOX-6 a duplicate path, a directory listed twice and a file under a file are refused duplicate', () => {
  refusesTar([{ name: 'a', body: '1' }, { name: 'a', body: '2' }], 'duplicate', 'a file twice');
  refusesTar([{ name: 'd/', type: '5' }, { name: 'd/', type: '5' }], 'duplicate', 'a directory twice');
  refusesTar([{ name: 'a', body: '1' }, { name: 'a/b', body: '2' }], 'duplicate', 'a file under a file');
  refusesTar([{ name: 'a/b', body: '2' }, { name: 'a', body: '1' }], 'duplicate', 'a file over an implied directory');
});

test('KBOX-6 a 255-byte path is accepted and a 256-byte path is refused name', () => {
  const at = (n: number): TarEntrySpec => ({ prefix: 'p'.repeat(n - 101), name: 'n'.repeat(100), body: 'x' });
  assert.equal(parseTar(tarOf([at(255)])).ok, true);
  refusesTar([at(256)], 'name', '256 bytes');
});

test('KBOX-6 5,000 entries are accepted and 5,001 are refused too_many', () => {
  const many = (n: number): TarEntrySpec[] => Array.from({ length: n }, (_, i) => ({ name: `d${i}/`, type: '5' }));
  assert.equal(parseTar(tarOf(many(5000))).ok, true);
  refusesTar(many(5001), 'too_many', '5,001 entries');
});

test('KBOX-6 20 MiB of file bytes are accepted and 20 MiB + 1 is refused too_large', () => {
  const mib = 1024 * 1024;
  assert.equal(parseTar(tarOf([{ name: 'a', body: new Uint8Array(20 * mib - 1) }, { name: 'b', body: 'x' }])).ok, true);
  refusesTar([{ name: 'a', body: new Uint8Array(20 * mib) }, { name: 'b', body: 'x' }], 'too_large', '20 MiB + 1');
});

test('KBOX-6 a truncated tar is refused truncated: a cut body, a cut header, no end block', () => {
  const whole = tarOf([{ name: 'a', body: 'x'.repeat(600) }]);
  assert.deepEqual(parseTar(whole.subarray(0, 700)), { ok: false, code: 'truncated' }, 'cut body');
  assert.deepEqual(parseTar(whole.subarray(0, 300)), { ok: false, code: 'truncated' }, 'cut header');
  assert.deepEqual(parseTar(tarOf([{ name: 'a', body: 'x' }], { end: false })), { ok: false, code: 'truncated' }, 'no end block');
  assert.deepEqual(parseTar(new Uint8Array(0)), { ok: false, code: 'truncated' }, 'empty input');
});

test('KBOX-6 a wrong checksum, a base-256 size, a missing ustar magic and bytes after the end are refused bad_header', () => {
  refusesTar([{ name: 'a', body: 'x', badChecksum: true }], 'bad_header', 'checksum');
  refusesTar([{ name: 'a', body: 'x', base256Size: true }], 'bad_header', 'base-256 size');
  const noMagic = tarOf([{ name: 'a', body: 'x' }]);
  noMagic.fill(0, 257, 263);
  assert.deepEqual(parseTar(noMagic), { ok: false, code: 'bad_header' }, 'no magic');
  const trailing = tarOf([{ name: 'a', body: 'x' }]);
  trailing[trailing.length - 1] = 1;
  assert.deepEqual(parseTar(trailing), { ok: false, code: 'bad_header' }, 'a non-zero byte after the end block');
  refusesTar([{ name: 'd/', type: '5', body: 'data' }], 'bad_header', 'a directory with a body');
});

// --- the content hash -------------------------------------------------------------------------------------------------

test('KBOX-6 the content hash matches a vector computed here from the spec text: sorted bytewise, <mode> <sha256> <path>, 0755 only with the owner-execute bit', () => {
  const files = [
    { path: 'src/z.ts', executable: false, sha256: sha('z') },
    { path: 'run.sh', executable: true, sha256: sha('#!/bin/sh\n') },
    { path: 'src/a.ts', executable: false, sha256: sha('a') },
    { path: 'Src.md', executable: false, sha256: sha('S') },
    { path: 'é.txt', executable: false, sha256: sha('e') },
  ];
  // Bytewise: 'S' (0x53) < 'r' (0x72) < 's' (0x73) < 0xc3 (the first byte of é).
  const text = `0644 ${sha('S')} Src.md\n0755 ${sha('#!/bin/sh\n')} run.sh\n0644 ${sha('a')} src/a.ts\n0644 ${sha('z')} src/z.ts\n0644 ${sha('e')} é.txt\n`;
  assert.equal(releaseText(files), text);
  assert.equal(releaseHash(files), sha(text));
});

test('KBOX-6 a file with group or other execute bits only is 0644 in the hash text', () => {
  const parsed = parseTar(tarOf([{ name: 'g', body: 'x', mode: 0o654 }, { name: 'o', body: 'x', mode: 0o645 }, { name: 'u', body: 'x', mode: 0o744 }]));
  assert.ok(parsed.ok);
  assert.deepEqual(parsed.entries.map((e) => (e.kind === 'file' ? e.executable : 'dir')), [false, false, true]);
});
