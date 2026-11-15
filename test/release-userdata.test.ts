// release-v2 (KBOX-48): the setup file (`user-data`) a release publishes is deploy/cloud-init.yaml with exactly the five value lines of
// /root/keybox-release.env filled in, and every other line byte-identical. Pure: no file but the repo's own template is read.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { readReleaseValues, renderUserData } from '../src/pure/release-userdata.ts';
import type { ReleaseValues } from '../src/pure/release-userdata.ts';

const template = readFileSync(new URL('../deploy/cloud-init.yaml', import.meta.url), 'utf8');

const GOOD: ReleaseValues = {
  KB_REPO: 'SynidSweet/key-box',
  KB_DOMAIN: 'keybox.tail09a879.ts.net',
  KB_COMMIT: 'a'.repeat(40),
  KB_RELEASE: 'b'.repeat(64),
  KB_TIME_FLOOR: '1794787200',
};

const render = (values: Readonly<Record<string, string>>) => renderUserData(template, values);

function filled(values: Readonly<Record<string, string>> = GOOD): string {
  const out = render(values);
  assert.ok(out.ok, `expected a rendering, got ${JSON.stringify(out)}`);
  return out.text;
}

test('release-v2 the rendering differs from the template in exactly the five value lines', () => {
  const before = template.split('\n');
  const after = filled().split('\n');
  assert.equal(after.length, before.length);
  const changed = before.flatMap((line, i) => (line === after[i] ? [] : [{ from: line.trim(), to: (after[i] ?? '').trim() }]));
  assert.deepEqual(
    changed.map((c) => c.to),
    [
      'KB_REPO=SynidSweet/key-box',
      'KB_DOMAIN=keybox.tail09a879.ts.net',
      `KB_COMMIT=${'a'.repeat(40)}`,
      `KB_RELEASE=${'b'.repeat(64)}`,
      'KB_TIME_FLOOR=1794787200',
    ],
  );
  assert.deepEqual(
    changed.map((c) => c.from.split('=')[0]),
    ['KB_REPO', 'KB_DOMAIN', 'KB_COMMIT', 'KB_RELEASE', 'KB_TIME_FLOOR'],
  );
});

test('release-v2 the indent of each filled line is the template line\'s own', () => {
  const lines = filled().split('\n');
  for (const key of Object.keys(GOOD)) assert.ok(lines.some((l) => l.startsWith(`      ${key}=`)), key);
});

test('release-v2 round trip: the values read back from the rendering are the values given', () => {
  assert.deepEqual(readReleaseValues(filled()), { ok: true, values: GOOD });
});

test('release-v2 the template itself reads back as its placeholders', () => {
  const read = readReleaseValues(template);
  assert.ok(read.ok);
  assert.equal(read.values.KB_REPO, 'OWNER/key-box');
  assert.equal(read.values.KB_TIME_FLOOR, '0');
});

const without = (key: string): Record<string, string> => Object.fromEntries(Object.entries(GOOD).filter(([k]) => k !== key));

for (const key of Object.keys(GOOD)) {
  test(`release-v2 a missing ${key} is refused`, () => {
    assert.deepEqual(render(without(key)), { ok: false, error: 'missing_value' });
  });
}

test('release-v2 an unknown key is refused', () => {
  assert.deepEqual(render({ ...GOOD, NODE_SHA256: 'c'.repeat(64) }), { ok: false, error: 'unknown_key' });
  assert.deepEqual(render({ ...GOOD, kb_repo: 'x/y' }), { ok: false, error: 'unknown_key' });
});

const BAD: ReadonlyArray<readonly [string, string, string]> = [
  ['KB_REPO', 'nowhere', 'bad_repo'],
  ['KB_REPO', 'a/b/c', 'bad_repo'],
  ['KB_REPO', 'owner/na me', 'bad_repo'],
  ['KB_REPO', 'owner/name\nKB_COMMIT=x', 'bad_repo'],
  ['KB_REPO', '', 'bad_repo'],
  ['KB_DOMAIN', 'CHANGE-ME', 'bad_domain'],
  ['KB_DOMAIN', 'Keybox.Tail.ts.net', 'bad_domain'],
  ['KB_DOMAIN', 'a.ts.net\nx', 'bad_domain'],
  ['KB_COMMIT', 'a'.repeat(39), 'bad_commit'],
  ['KB_COMMIT', 'A'.repeat(40), 'bad_commit'],
  ['KB_COMMIT', 'g'.repeat(40), 'bad_commit'],
  ['KB_RELEASE', 'b'.repeat(63), 'bad_release'],
  ['KB_RELEASE', 'B'.repeat(64), 'bad_release'],
  ['KB_TIME_FLOOR', '-1', 'bad_time_floor'],
  ['KB_TIME_FLOOR', '1.5', 'bad_time_floor'],
  ['KB_TIME_FLOOR', '0x10', 'bad_time_floor'],
  ['KB_TIME_FLOOR', '007', 'bad_time_floor'],
  ['KB_TIME_FLOOR', '', 'bad_time_floor'],
  ['KB_TIME_FLOOR', '99999999999999999999', 'bad_time_floor'],
];
for (const [key, value, error] of BAD) {
  test(`release-v2 ${key}=${JSON.stringify(value)} is refused as ${error}`, () => {
    assert.deepEqual(render({ ...GOOD, [key]: value }), { ok: false, error });
  });
}

test('release-v2 a template without exactly one line per key is refused', () => {
  const noRepoLine = template.replace(/^ {6}KB_REPO=.*\n/m, '');
  assert.deepEqual(renderUserData(noRepoLine, GOOD), { ok: false, error: 'template_lines' });
  const twice = template.replace(/^( {6}KB_COMMIT=.*\n)/m, '$1$1');
  assert.deepEqual(renderUserData(twice, GOOD), { ok: false, error: 'template_lines' });
  assert.deepEqual(renderUserData('#cloud-config\n', GOOD), { ok: false, error: 'template_lines' });
  assert.deepEqual(readReleaseValues(noRepoLine), { ok: false, error: 'template_lines' });
});

test('release-v2 a line of the same name outside the env block is not a value line', () => {
  // The runcmd's last item starts with KB_DOMAIN=...; only the write_files block counts.
  assert.ok(template.includes('KB_DOMAIN="$KB_DOMAIN"'));
  assert.ok(filled().includes('KB_DOMAIN="$KB_DOMAIN"'));
});
