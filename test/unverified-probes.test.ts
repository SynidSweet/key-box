// KBOX-42: the `unverified` list of every registry entry is exactly the ids its probe report still marks STILL UNVERIFIED. Passes on the
// empty registry; shown on fixtures to refuse a list that disagrees with its report in either direction.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { REGISTRY } from '../src/platforms/registry.ts';
import { unverifiedDisagreement } from './support/probe-status.ts';

const REPORT = ['# probe', '- google.auth: POST /token with a throwaway key, 200, names only: VERIFIED', '- google.page: GET /keys, 404: STILL UNVERIFIED', '- google.rate: REFUTED'].join('\n');

test('KBOX-42 every entry of the real registry lists exactly the ids its probe report marks STILL UNVERIFIED', async () => {
  for (const entry of REGISTRY) {
    const report = await readFile(new URL(`../docs/probes/${entry.id}.md`, import.meta.url), 'utf8').catch((): undefined => undefined);
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
