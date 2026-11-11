// KBOX-45: process layout, sockets and unit hardening: a text check of deploy/*.service and deploy/keybox-tmpfiles.conf.
// The started-process half, with real users and modes, is test/journeys/process-split.test.ts.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { directives, missingDirectives, parseTmpfiles, words } from './kit/index.ts';

const deploy = new URL('../deploy/', import.meta.url).pathname;
const read = (name: string): string => readFileSync(join(deploy, name), 'utf8');

const HARDENING = { LimitCORE: '0', NoNewPrivileges: 'yes', ProtectSystem: 'strict', PrivateTmp: 'yes', UMask: '0007' } as const;

test('KBOX-45 the tmpfiles file makes the three runtime directories 2750 with the owner and group of the spec, and the two root-owned installer directories 0755', () => {
  const lines = parseTmpfiles(read('keybox-tmpfiles.conf'));
  const byPath = new Map(lines.map((l) => [l.path, l]));
  const expected: [string, string, string, string][] = [
    ['/run/keybox', '2750', 'keybox', 'caddy'],
    ['/run/keyrelay', '2750', 'keyrelay', 'caddy'],
    ['/run/keybox-lend', '2750', 'keybox', 'keyrelay'],
    ['/etc/keybox', '0755', 'root', 'root'],
    ['/var/lib/keybox-install', '0755', 'root', 'root'],
    ['/var/lib/keybox', '0700', 'keybox', 'keybox'],
  ];
  assert.deepEqual([...byPath.keys()].sort(), expected.map(([p]) => p).sort(), 'no directory beyond the spec');
  for (const [path, mode, user, group] of expected) assert.deepEqual(byPath.get(path), { type: 'd', path, mode, user, group }, path);
});

test('KBOX-45 no directory of the tmpfiles file is group-writable or world-accessible, and each runtime directory has its own group', () => {
  const lines = parseTmpfiles(read('keybox-tmpfiles.conf'));
  const runtime = lines.filter((l) => l.path.startsWith('/run/'));
  assert.equal(runtime.length, 3);
  for (const l of runtime) {
    const mode = parseInt(l.mode, 8);
    assert.equal(mode & 0o2000, 0o2000, `${l.path} is setgid, so a socket takes the directory's group and no chown is needed`);
    assert.equal(mode & 0o027, 0, `${l.path} is not group-writable or world-accessible`);
  }
  assert.equal(new Set(runtime.map((l) => `${l.user}:${l.group}`)).size, 3, 'one directory serves one group');
  for (const l of lines.filter((x) => x.path.startsWith('/etc/') || x.path.startsWith('/var/lib/keybox-install'))) {
    assert.deepEqual([l.user, l.group, l.mode], ['root', 'root', '0755']);
  }
});

test('KBOX-45 keybox.service and keyrelay.service carry the hardening directives, their own user, and only their own writable directories', () => {
  const core = read('keybox.service');
  const relay = read('keyrelay.service');
  assert.deepEqual(missingDirectives(core, { ...HARDENING, User: 'keybox', Group: 'keybox' }), []);
  assert.deepEqual(missingDirectives(relay, { ...HARDENING, User: 'keyrelay', Group: 'keyrelay', InaccessiblePaths: '/var/lib/keybox' }), []);
  assert.deepEqual(words(directives(core, 'Service').get('ReadWritePaths')).sort(), ['/run/keybox', '/run/keybox-lend', '/var/lib/keybox']);
  assert.deepEqual(words(directives(relay, 'Service').get('ReadWritePaths')), ['/run/keyrelay']);
  assert.deepEqual(words(directives(relay, 'Service').get('RestrictAddressFamilies')), ['AF_UNIX', 'AF_INET', 'AF_INET6']);
  assert.deepEqual(words(directives(relay, 'Service').get('InaccessiblePaths')), ['/var/lib/keybox']);
  for (const [name, unit] of [['keybox.service', core], ['keyrelay.service', relay]] as const) {
    const exec = directives(unit, 'Service').get('ExecStart') ?? [];
    assert.equal(exec.length, 1, name);
    assert.match(exec[0] ?? '', /^\/opt\/keybox\/current\/bin\/node \/opt\/keybox\/current\/src\/main-(core|relay)\.ts$/, `${name} runs the running release`);
  }
});

test('KBOX-3 keybox.service sets KB_LEND_SOCKET, or core opens no lend socket and every relay call answers 503; keyrelay.service names the same socket', () => {
  const environment = (name: string): string[] => words(directives(read(name), 'Service').get('Environment'));
  const lendSocket = (name: string): string[] => environment(name).filter((w) => w.startsWith('KB_LEND_SOCKET='));
  assert.deepEqual(lendSocket('keybox.service'), ['KB_LEND_SOCKET=/run/keybox-lend/lend.sock']);
  assert.deepEqual(lendSocket('keyrelay.service'), lendSocket('keybox.service'));
});

test('KBOX-45 no unit puts anyone in another\'s group: the only SupplementaryGroups of any deploy unit is the root kb-code unit\'s tty', () => {
  const units = readdirSync(deploy).filter((f) => f.endsWith('.service'));
  assert.ok(units.includes('keybox.service') && units.includes('keyrelay.service'));
  for (const name of units) {
    const groups = words(directives(read(name), 'Service').get('SupplementaryGroups'));
    if (name === 'kb-code.service') assert.deepEqual(groups, ['tty']);
    else assert.deepEqual(groups, [], name);
  }
});

test('KBOX-45 the unit check names a missing directive and a stray group on a planted unit', () => {
  const planted = '[Service]\nUser=keybox\nNoNewPrivileges=no\nSupplementaryGroups=caddy\n';
  assert.deepEqual(missingDirectives(planted, { User: 'keybox', NoNewPrivileges: 'yes', LimitCORE: '0' }), ['NoNewPrivileges=yes', 'LimitCORE=0']);
  assert.deepEqual(words(directives(planted, 'Service').get('SupplementaryGroups')), ['caddy']);
  assert.deepEqual(parseTmpfiles('# c\n\nd /run/x 2750 a b -\n'), [{ type: 'd', path: '/run/x', mode: '2750', user: 'a', group: 'b' }]);
});
