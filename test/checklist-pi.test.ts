// KBOX-48 (revision 5): the owner's setup checklist for the Raspberry Pi and Tailscale box, its recovery cases and its two runbooks.
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import test from 'node:test';
import { FIXED } from '../src/pure/words.ts';

const checklist = readFileSync(new URL('../docs/setup-checklist.md', import.meta.url), 'utf8');
const platforms = readdirSync(new URL('../src/platforms/', import.meta.url), { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name);

/** The text from a heading line to the next heading of the same or a higher level. */
function section(title: string): string {
  const start = checklist.indexOf(`## ${title}`);
  assert.ok(start >= 0, `a section titled ${title}`);
  const rest = checklist.slice(start + 3);
  const end = rest.search(/\n## /);
  return end < 0 ? rest : rest.slice(0, end);
}

test('KBOX-48 the checklist has the three recovery cases of section 4, equal to FIXED.recover*', () => {
  const text = section('If you lose access');
  for (const words of [FIXED.recoverReinstalled, FIXED.recoverLostPhone, FIXED.recoverBoxGone]) assert.ok(text.includes(words), words);
  assert.match(FIXED.recoverReinstalled, /wait for "Key box ready", and within 30 minutes open `?\/recover/);
  assert.match(FIXED.recoverLostPhone, /remove the lost phone on Tailscale's Machines page/);
  assert.match(FIXED.recoverBoxGone, /If the card dies/);
});

test('KBOX-48 the checklist has the eight owner steps in order, and none of Oracle', () => {
  const steps = [...(checklist.split('\n## ')[0] ?? '').matchAll(/^(\d+)\. /gm)].map((m) => Number(m[1]));
  assert.deepEqual(steps.slice(0, 8), [1, 2, 3, 4, 5, 6, 7, 8]);
  assert.doesNotMatch(checklist, /oracle|dedyn|desec|cloud-init user data|security list/i);
});

test('KBOX-48 "If the box is stolen" lists its four owner steps in order, keys first', () => {
  const text = section('If the box is stolen');
  const marks = ['1. **Desk:**', '2. **Each platform', '3. **Tailscale admin console', '4. **Phone:**'].map((m) => text.indexOf(m));
  assert.ok(marks.every((i) => i >= 0), `all four steps present: ${marks}`);
  assert.deepEqual([...marks].sort((a, b) => a - b), marks, 'in order');
  assert.ok(text.includes('Report the box stolen'));
});

test('KBOX-48 the stolen-box runbook has one rule row for each platform in src/platforms, each dated', () => {
  const text = section('If the box is stolen');
  assert.ok(platforms.length >= 7);
  for (const platform of platforms) {
    const row = text.split('\n').find((l) => l.toLowerCase().startsWith(`| ${platform} |`));
    assert.ok(row, `a table row for ${platform}`);
  }
  assert.match(text, /read 2026-\d\d-\d\d/);
});

test('KBOX-48 "If the card dies" names mission control\'s re-link and the old card', () => {
  const text = section('If the card dies');
  assert.match(text, /mission control/i);
  assert.match(text, /re-link|link is ended and made again/i);
  assert.match(text, /Machines/);
  assert.match(text, /cuts? the old card in two/i);
});

test('KBOX-48 I3: the checklist links to no box address', () => {
  assert.doesNotMatch(checklist, /\]\(https:\/\/keybox/);
  assert.doesNotMatch(checklist, /<https:\/\/keybox/);
  assert.doesNotMatch(checklist, /https:\/\/keybox\.[a-z0-9.-]*\.ts\.net/);
});

test('KBOX-48 the checklist keeps the Google-synced authenticator sentence and says there is no http exemption', () => {
  assert.ok(checklist.includes('an **authenticator app synced only to the owner\'s Google account, which is never signed in on the workstation, devbox or Helsinki**'));
  assert.ok(checklist.includes('no `http` exemption'));
});

test('KBOX-48 the Google section says the first JWKS upload is made from the box\'s own page on the phone, never from an agent file', () => {
  const text = section('For each Google Cloud project the box makes API keys in (KBOX-59)');
  assert.match(text, /issuer/i);
  assert.match(text, /jwks/i);
  assert.match(text, /never from a file an agent prepared/i);
});
