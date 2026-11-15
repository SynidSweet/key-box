// KBOX-64, KBOX-65: the start order of the units under deploy/ (design 3.6a), read from their After= and Before= lines. Each
// check is a function over unit texts, run on the real units and on a planted bad unit (as deploy-units.test.ts does), so a check
// that can no longer fail is itself caught.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { directives, words } from './kit/index.ts';

const deploy = new URL('../deploy/', import.meta.url).pathname;
/** Every deploy/*.service, by file name. */
const realUnits = (): Map<string, string> => new Map(readdirSync(deploy).filter((f) => f.endsWith('.service')).map((f) => [f, readFileSync(join(deploy, f), 'utf8')]));
const withUnit = (units: ReadonlyMap<string, string>, name: string, text: string): Map<string, string> => new Map([...units, [name, text]]);
/** The values of a Unit-section key, as words. */
const unitWords = (text: string, key: string): string[] => words(directives(text, 'Unit').get(key));
const serviceWords = (text: string, key: string): string[] => words(directives(text, 'Service').get(key));

/** Start-order edges `[first, second]`: `After=X` in U is X before U, `Before=X` in U is U before X. */
function edges(units: ReadonlyMap<string, string>): [string, string][] {
  return [...units].flatMap(([name, text]) => [
    ...unitWords(text, 'After').map((x): [string, string] => [x, name]),
    ...unitWords(text, 'Before').map((x): [string, string] => [name, x]),
  ]);
}

/** Whether `to` starts after `from`, directly or through other units. */
function startsAfter(units: ReadonlyMap<string, string>, from: string, to: string): boolean {
  const next = edges(units);
  const seen = new Set<string>();
  const walk = (at: string): boolean => {
    if (at === to) return true;
    if (seen.has(at)) return false;
    seen.add(at);
    return next.some(([a, b]) => a === at && walk(b));
  };
  return next.some(([a, b]) => a === from && walk(b));
}

// (a) no cycle
const orderCycles = (units: ReadonlyMap<string, string>): string[] => [...new Set(edges(units).flatMap(([a]) => (startsAfter(units, a, a) ? [a] : [])))];
// (b) no time-sync.target
const timeSyncUsers = (units: ReadonlyMap<string, string>): string[] =>
  [...units].filter(([, text]) => ['After', 'Before', 'Requires', 'Wants', 'BindsTo', 'PartOf', 'Requisite'].some((k) => unitWords(text, k).includes('time-sync.target'))).map(([n]) => n);
// (c) kb-firewall is early
function firewallFaults(units: ReadonlyMap<string, string>): string[] {
  const text = units.get('kb-firewall.service');
  if (text === undefined) return ['kb-firewall.service is missing'];
  const faults: string[] = [];
  if (!(directives(text, 'Unit').get('DefaultDependencies') ?? []).includes('no')) faults.push('DefaultDependencies=no');
  if (!unitWords(text, 'Before').includes('network-pre.target')) faults.push('Before=network-pre.target');
  return faults;
}
// (d) the two screen units
function screenFaults(units: ReadonlyMap<string, string>): string[] {
  return ['kb-join.service', 'kb-ready.service'].flatMap((name) => {
    const text = units.get(name);
    if (text === undefined) return [`${name} is missing`];
    const service = directives(text, 'Service');
    return [
      ...(serviceWords(text, 'TimeoutStartSec').includes('infinity') ? [] : [`${name}: TimeoutStartSec=infinity`]),
      ...(serviceWords(text, 'TTYPath').includes('/dev/tty1') ? [] : [`${name}: TTYPath=/dev/tty1`]),
      ...['DeviceAllow', 'SupplementaryGroups'].filter((k) => service.has(k)).map((k) => `${name}: no ${k}`),
    ];
  });
}
// (e) every listener requires the join and the firewall
const listens = (text: string): boolean => (directives(text, 'Service').get('ExecStart') ?? []).some((e) => /\/src\/main-(core|relay)\.ts$|\/bin\/caddy run /.test(e));
function listenerFaults(units: ReadonlyMap<string, string>): string[] {
  return [...units].filter(([, text]) => listens(text)).flatMap(([name, text]) =>
    ['kb-join.service', 'kb-firewall.service'].filter((need) => !(unitWords(text, 'Requires').includes(need) && unitWords(text, 'After').includes(need))).map((need) => `${name}: After= and Requires= ${need}`));
}
// (f) the installer's rollback never waits on the join
const RESTARTED = ['kb-join.service', 'keybox.service', 'keyrelay.service', 'caddy.service'];
function installerFaults(units: ReadonlyMap<string, string>): string[] {
  return [
    ...RESTARTED.filter((u) => startsAfter(units, u, 'kb-install.service')).map((u) => `kb-install.service is ordered after ${u}`),
    ...(startsAfter(units, 'kb-install.service', 'kb-join.service') ? [] : ['kb-join.service is not ordered after kb-install.service']),
  ];
}

test('KBOX-64 the After and Before lines of every deploy unit form no cycle, and a planted cycle is named', () => {
  const units = realUnits();
  assert.ok(units.size >= 8, 'the real units were read');
  assert.deepEqual(orderCycles(units), []);
  const planted = withUnit(withUnit(units, 'a.service', '[Unit]\nAfter=b.service\n'), 'b.service', '[Unit]\nBefore=a.service\nAfter=c.service\n[Service]\n');
  assert.deepEqual(orderCycles(planted), []);
  assert.ok(orderCycles(withUnit(planted, 'c.service', '[Unit]\nAfter=a.service\n')).length > 0, 'c after a, a after b, b after c');
});

test('KBOX-64 no deploy unit names time-sync.target as a dependency, and a planted one is named', () => {
  assert.deepEqual(timeSyncUsers(realUnits()), []);
  for (const key of ['After', 'Requires', 'Wants']) assert.deepEqual(timeSyncUsers(withUnit(realUnits(), 'x.service', `[Unit]\n${key}=network.target time-sync.target\n`)), ['x.service'], key);
});

test('KBOX-65 kb-firewall.service has DefaultDependencies=no and Before=network-pre.target, and a unit missing either is named', () => {
  assert.deepEqual(firewallFaults(realUnits()), []);
  assert.deepEqual(firewallFaults(withUnit(realUnits(), 'kb-firewall.service', '[Unit]\nBefore=network-pre.target\n')), ['DefaultDependencies=no']);
  assert.deepEqual(firewallFaults(withUnit(realUnits(), 'kb-firewall.service', '[Unit]\nDefaultDependencies=no\n')), ['Before=network-pre.target']);
});

test('KBOX-64 kb-join and kb-ready wait without a time limit on tty1 and carry no DeviceAllow or SupplementaryGroups; a planted fault is named', () => {
  assert.deepEqual(screenFaults(realUnits()), []);
  const planted = withUnit(realUnits(), 'kb-ready.service', '[Unit]\n[Service]\nTimeoutStartSec=90\nTTYPath=/dev/ttyAMA0\nDeviceAllow=/dev/tty1 w\nSupplementaryGroups=tty\n');
  assert.deepEqual(screenFaults(planted), ['kb-ready.service: TimeoutStartSec=infinity', 'kb-ready.service: TTYPath=/dev/tty1', 'kb-ready.service: no DeviceAllow', 'kb-ready.service: no SupplementaryGroups']);
});

test('KBOX-64 every unit that listens (core, relay, Caddy) is ordered after and requires kb-join and kb-firewall; a planted listener without them is named', () => {
  assert.deepEqual(listenerFaults(realUnits()), []);
  const planted = withUnit(realUnits(), 'keybox.service', '[Unit]\nAfter=kb-join.service\nRequires=kb-firewall.service\n[Service]\nExecStart=/opt/keybox/current/bin/node /opt/keybox/current/src/main-core.ts\n');
  assert.deepEqual(listenerFaults(planted), ['keybox.service: After= and Requires= kb-join.service', 'keybox.service: After= and Requires= kb-firewall.service']);
  assert.deepEqual(listenerFaults(withUnit(realUnits(), 'x.service', '[Unit]\n[Service]\nExecStart=/opt/keybox/current/bin/node /opt/keybox/current/src/cli/kb-code.ts boot\n')), [], 'a unit that does not listen needs neither');
});

test('KBOX-64 kb-install.service is never ordered after kb-join or a unit it restarts, and kb-join is ordered after kb-install; planted faults are named', () => {
  assert.deepEqual(installerFaults(realUnits()), []);
  const after = withUnit(realUnits(), 'kb-install.service', '[Unit]\nAfter=caddy.service\n');
  assert.deepEqual(installerFaults(after), ['kb-join.service', 'keybox.service', 'keyrelay.service', 'caddy.service'].map((u) => `kb-install.service is ordered after ${u}`), 'caddy, and everything that must start before caddy');
  const before = withUnit(realUnits(), 'kb-join.service', '[Unit]\nBefore=kb-install.service\n');
  assert.ok(installerFaults(before).includes('kb-install.service is ordered after kb-join.service'));
  assert.deepEqual(installerFaults(withUnit(realUnits(), 'kb-join.service', '[Unit]\n')), ['kb-join.service is not ordered after kb-install.service']);
});
