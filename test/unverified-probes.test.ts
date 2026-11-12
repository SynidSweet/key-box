// KBOX-42: the `unverified` list of every registry entry is exactly the ids its probe report still marks STILL UNVERIFIED. Passes on the
// empty registry; shown on fixtures to refuse a list that disagrees with its report in either direction.
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { REGISTRY } from '../src/platforms/registry.ts';
import { readTextIfPresent, walk } from './arch/tree.ts';
import { platformGaps, unverifiedDisagreement } from './support/probe-status.ts';

const REPORT = [
  '# probe',
  '| id | rule | probe | observed | status |',
  '| --- | --- | --- | --- | --- |',
  '| `google.auth` | KBOX-41 | POST /token with a throwaway key | 200, names only | VERIFIED |',
  '| `google.page` | KBOX-41 | GET /keys | 404 | STILL UNVERIFIED |',
  '| `google.rate` | KBOX-41 | burst of 10 | 200 every time | REFUTED |',
].join('\n');

test('KBOX-42 every entry of the real registry lists exactly the ids its probe report marks STILL UNVERIFIED', async () => {
  for (const entry of REGISTRY) {
    const report = await readTextIfPresent(fileURLToPath(new URL('..', import.meta.url)), `docs/probes/${entry.id}.md`);
    assert.equal(unverifiedDisagreement(entry, report), undefined);
  }
});

test('KBOX-42 a list that matches its report passes', () => {
  assert.equal(unverifiedDisagreement({ id: 'google', unverified: ['google.page'] }, REPORT), undefined);
});

test('KBOX-42 an id the report does not mark STILL UNVERIFIED (verified, refuted or absent) is refused', () => {
  assert.match(unverifiedDisagreement({ id: 'google', unverified: ['google.page', 'google.auth'] }, REPORT) ?? '', /google\.auth/);
  assert.match(unverifiedDisagreement({ id: 'google', unverified: ['google.page', 'google.rate'] }, REPORT) ?? '', /google\.rate/);
  assert.match(unverifiedDisagreement({ id: 'google', unverified: ['google.page', 'google.gone'] }, REPORT) ?? '', /google\.gone/);
});

test('KBOX-42 a report line marked STILL UNVERIFIED that the list leaves out is refused', () => {
  assert.match(unverifiedDisagreement({ id: 'google', unverified: [] }, REPORT) ?? '', /google\.page/);
});

test('KBOX-42 a missing report is refused for a platform that lists ids', () => {
  assert.match(unverifiedDisagreement({ id: 'google', unverified: ['google.page'] }, undefined) ?? '', /missing/);
  assert.equal(unverifiedDisagreement({ id: 'google', unverified: [] }, undefined), undefined);
});

test('KBOX-42 a STILL UNVERIFIED row whose prose names another id counts for its own id only', () => {
  const report = ['| `a.one` | KBOX-1 | like `b.two` | see b.two | STILL UNVERIFIED |', '| `b.two` | KBOX-1 | GET /x | 200 | VERIFIED |'].join('\n');
  assert.equal(unverifiedDisagreement({ id: 'a', unverified: ['a.one'] }, report), undefined);
  assert.match(unverifiedDisagreement({ id: 'a', unverified: ['a.one', 'b.two'] }, report) ?? '', /b\.two/);
});

test('KBOX-42 a VERIFIED row whose prose says STILL UNVERIFIED is verified, and a prose line outside the table counts for nothing', () => {
  const report = ['The rest is STILL UNVERIFIED a.two until a live probe.', '| `a.one` | KBOX-1 | a note: the length is STILL UNVERIFIED | 200 | VERIFIED |'].join('\n');
  assert.equal(unverifiedDisagreement({ id: 'a', unverified: [] }, report), undefined);
  assert.match(unverifiedDisagreement({ id: 'a', unverified: ['a.one'] }, report) ?? '', /a\.one/);
});

test('KBOX-42 an id in a table row that is not the first cell, and an id with a longer id around it, do not count', () => {
  const report = '| `a.one-more` | KBOX-1 | `a.one` | 404 | STILL UNVERIFIED |';
  assert.match(unverifiedDisagreement({ id: 'a', unverified: ['a.one'] }, report) ?? '', /a\.one/);
});

test('KBOX-42 every src/platforms folder that holds more than unverified.json has a registry entry, and every entry has its folder and probe report', async () => {
  const root = fileURLToPath(new URL('..', import.meta.url));
  const files = await walk(root, 'src/platforms');
  const probes = await walk(root, 'docs/probes');
  assert.deepEqual(platformGaps(REGISTRY.map((e) => e.id), files, probes), []);
});

test('KBOX-42 platformGaps: built code without an entry, an entry without a folder, an entry without a probe report', () => {
  const probes = ['docs/probes/google.md'];
  assert.deepEqual(platformGaps([], ['src/platforms/registry.ts', 'src/platforms/google/unverified.json'], probes), [], 'probed and not built is exempt');
  assert.match(platformGaps([], ['src/platforms/google/unverified.json', 'src/platforms/google/issuer.ts'], probes).join(), /google.*no registry entry/);
  assert.match(platformGaps(['google'], ['src/platforms/registry.ts'], probes).join(), /google.*no folder/);
  assert.match(platformGaps(['google'], ['src/platforms/google/issuer.ts'], []).join(), /google.*no docs\/probes\/google\.md/);
  assert.deepEqual(platformGaps(['google'], ['src/platforms/google/issuer.ts', 'src/platforms/google/unverified.json'], probes), []);
});
