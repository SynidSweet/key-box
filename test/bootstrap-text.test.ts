// KBOX-1, KBOX-44, KBOX-46, KBOX-48 and the kb-install units of KBOX-6: text checks of the bootstrap (cloud-init), the
// Caddyfile, the units, runtime.lock and the setup checklist, and the route table of core. What only the real instance can
// show (the Run Command plugin command, Caddy's real header handling, the console device, the apt mirror) is UNVERIFIED
// and reported by the builder, never run here.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { FIXED } from '../src/pure/words.ts';
import { parseRuntimeLock } from '../src/pure/runtime-lock.ts';
import { coreRoutes } from '../src/main-core.ts';
import { createUpdater } from '../src/shell/updater.ts';
import { directives, missingDirectives } from './kit/index.ts';
import { approveWorld } from './support/approve-world.ts';

const read = (path: string): string => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const cloudInit = read('deploy/cloud-init.yaml');
const checklist = read('docs/setup-checklist.md');
const caddy = read('deploy/Caddyfile');

// --- KBOX-1 ------------------------------------------------------------------------------------------------------------

test('KBOX-1 the bootstrap removes the ssh packages, masks sshd, removes the default user\'s keys and installs no authorized key', () => {
  assert.match(cloudInit, /^\s*-\s*apt-get purge -y openssh-server openssh-client\s*$/m);
  assert.match(cloudInit, /^\s*-\s*systemctl mask --now ssh\.service ssh\.socket\s*$/m);
  assert.match(cloudInit, /^\s*-\s*rm -f \/home\/ubuntu\/\.ssh\/authorized_keys \/root\/\.ssh\/authorized_keys\s*$/m);
  assert.doesNotMatch(cloudInit, /ssh_authorized_keys|ssh-rsa|ssh-ed25519|ecdsa-sha2/);
  assert.match(cloudInit, /^ssh_pwauth: false$/m);
});

test('KBOX-1 the bootstrap disables the Run Command plugin (its exact command UNVERIFIED) and leaves the monitoring plugin on', () => {
  const lines = cloudInit.split('\n');
  const runCommand = lines.filter((l) => /Run Command/i.test(l) || /runcommand/i.test(l));
  assert.ok(runCommand.some((l) => /disable/i.test(l)), 'a line disables the Run Command plugin');
  assert.ok(runCommand.some((l) => /UNVERIFIED/.test(l)), 'the command is marked UNVERIFIED');
  assert.equal(lines.some((l) => /monitoring/i.test(l) && /disable|stop|mask/i.test(l) && !/^\s*#/.test(l)), false, 'nothing disables monitoring');
});

test('KBOX-1 core\'s route table has no shell, exec, debug, eval or console route', async (t) => {
  const w = await approveWorld(t);
  const updater = createUpdater({ stagingDir: '/nonexistent', resultsDir: '/nonexistent', currentLink: '/nonexistent', propose: (i) => w.core.approvals.propose(i), approvals: () => w.core.approvals, events: w.parts.events });
  const routes = coreRoutes(w.parts.routes, w.core.routes, updater.routes);
  assert.ok(routes.length > 20, 'the table is the real one');
  assert.ok(routes.some((r) => r.path === '/api/updates'));
  assert.deepEqual(routes.filter((r) => /shell|exec|debug|eval|console|cmd|run\b/i.test(r.path)).map((r) => r.path), []);
});

// --- KBOX-44 -----------------------------------------------------------------------------------------------------------

test('KBOX-44 the Caddyfile serves 443 only with TLS-ALPN-01, routes keys.<domain> to core and api.keys.<domain> /api/* to core and /r/* to relay', () => {
  for (const needle of [
    'auto_https disable_redirects',
    'disable_http_challenge',
    'keys.{$KB_DOMAIN}:443',
    'api.keys.{$KB_DOMAIN}:443',
    'handle /api/*',
    'handle /r/*',
    'reverse_proxy unix//run/keybox/http.sock',
    'reverse_proxy unix//run/keyrelay/http.sock',
  ])
    assert.ok(caddy.includes(needle), needle);
  assert.doesNotMatch(caddy, /:80\b|http:\/\//);
});

test('KBOX-44 every reverse_proxy sets X-KB-Client-Ip from Caddy\'s own view and drops X-Forwarded-For, X-Real-IP and Forwarded', () => {
  // Each block ends at its first line holding only `}` (a placeholder like {remote_host} closes nothing).
  const blocks = caddy.split('reverse_proxy ').slice(1).map((b) => b.slice(0, b.search(/\n\s*\}\s*\n/)));
  assert.equal(blocks.length, 3, 'core twice (two names), relay once');
  for (const b of blocks)
    for (const line of ['header_up X-KB-Client-Ip {remote_host}', 'header_up -X-Forwarded-For', 'header_up -X-Real-IP', 'header_up -Forwarded', 'header_up -X-Forwarded-Proto', 'header_up -X-Forwarded-Host']) assert.ok(b.includes(line), line);
});

test('KBOX-44 runtime.lock pins each binary by sha256 with an official URL', () => {
  const lock = parseRuntimeLock(read('runtime.lock'));
  assert.ok(lock, 'runtime.lock parses');
  assert.deepEqual(lock.map((b) => b.name).sort(), ['caddy', 'node']);
  for (const b of lock) assert.match(b.url, b.name === 'node' ? /^https:\/\/nodejs\.org\/dist\/v24\./ : /^https:\/\/github\.com\/caddyserver\/caddy\/releases\/download\//);
});

// --- KBOX-46 -----------------------------------------------------------------------------------------------------------

test('KBOX-46 the relay unit denies link-local, private and loopback addresses and allows only the resolver stub', () => {
  const service = directives(read('deploy/keyrelay.service'), 'Service');
  const deny = (service.get('IPAddressDeny') ?? []).join(' ').split(/\s+/);
  for (const range of ['link-local', 'localhost', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', 'fc00::/7', '169.254.0.0/16', 'fe80::/10']) assert.ok(deny.includes(range), range);
  assert.deepEqual(service.get('IPAddressAllow'), ['127.0.0.53/32']);
});

test('KBOX-46 the checklist lists the exact security-list rows, and the update and setup pages say the limits stop no approved malicious update', () => {
  for (const row of ['| Ingress | TCP | 0.0.0.0/0 | 443 |', '| Egress | TCP | 0.0.0.0/0 | 443 |', '| Egress | UDP | 169.254.169.254/32 | 53 |', '| Egress | TCP | 169.254.169.254/32 | 53 |', '| Egress | UDP | 169.254.169.254/32 | 123 |'])
    assert.ok(checklist.includes(row), row);
  assert.equal(FIXED.egressLimits, 'These limits do not stop an approved update that is malicious.');
  assert.ok(read('src/web/setup.html').includes(FIXED.egressLimits));
  assert.ok(checklist.includes('no `http` exemption'), 'an http apt mirror is never allowed');
});

// --- KBOX-48 -----------------------------------------------------------------------------------------------------------

test('KBOX-48 the cloud-init names commit C and hash H of release 1 and four pinned hashes', () => {
  assert.match(cloudInit, /^\s*KB_COMMIT=[0-9a-f]{40}$/m);
  assert.match(cloudInit, /^\s*KB_RELEASE=[0-9a-f]{64}$/m);
  for (const name of ['NODE_ARCHIVE_SHA256', 'NODE_SHA256', 'CADDY_ARCHIVE_SHA256', 'CADDY_SHA256']) assert.match(cloudInit, new RegExp(`^\\s*${name}=[0-9a-f]{64}$`, 'm'), name);
  for (const step of ['codeload.github.com', 'sha256sum -c', 'keybox-tmpfiles.conf', 'kb-install.path', 'kb-code.service', '/opt/keybox/current/src/cli/kb-code.ts setup']) assert.ok(cloudInit.includes(step), step);
});

test('KBOX-48 the cloud-init calls no host but the declared ones and holds no value', () => {
  const hosts = new Set([...cloudInit.matchAll(/https?:\/\/([A-Za-z0-9.-]+)/g)].map((m) => m[1]));
  assert.deepEqual([...hosts].sort(), ['codeload.github.com', 'github.com', 'nodejs.org', 'ports.ubuntu.com'].sort());
  assert.doesNotMatch(cloudInit, /http:\/\//, 'no plain http, apt included');
  assert.doesNotMatch(cloudInit, /kbt_[A-Za-z0-9_-]{20,}|BEGIN [A-Z ]*PRIVATE KEY|sk-[A-Za-z0-9]{20,}/);
});

test('KBOX-48 the checklist has the Google-synced authenticator sentence, no hardware key requirement and no "cloud sync off"', () => {
  assert.ok(checklist.includes('an **authenticator app synced only to the owner\'s Google account, which is never signed in on the workstation, devbox or Helsinki**'));
  assert.doesNotMatch(checklist, /cloud sync off/i);
  assert.doesNotMatch(checklist, /hardware key (is )?(required|needed)|requires? a hardware key/i);
});

test('KBOX-48 the checklist states the two recovery cases in the words of KBOX-20 and marks the three design section 12 items UNVERIFIED', () => {
  assert.ok(checklist.includes(FIXED.recoverReinstalled));
  assert.ok(checklist.includes(FIXED.recoverLostPhone));
  for (const item of ['deSEC authenticator app', 'TLS-ALPN-01 for a `dedyn.io` name', 'DNSSEC']) assert.match(checklist, new RegExp(`${item.replace(/[.*+?^${}()|[\]\\`]/g, '\\$&')}[^\\n]*UNVERIFIED`), item);
});

// --- kb-install's units (KBOX-6) ---------------------------------------------------------------------------------------

test('KBOX-6 kb-install.service is a root oneshot, sandboxed, with no network, run from current, 120 s timeout and no start limit', () => {
  const unit = read('deploy/kb-install.service');
  assert.deepEqual(
    missingDirectives(unit, { Type: 'oneshot', User: 'root', NoNewPrivileges: 'yes', ProtectSystem: 'strict', PrivateNetwork: 'yes', TimeoutStartSec: '120s', ReadWritePaths: '/opt/keybox /var/lib/keybox/staging /etc/keybox /var/lib/keybox-install' }),
    [],
  );
  assert.deepEqual(directives(unit, 'Unit').get('StartLimitIntervalSec'), ['0']);
  const exec = directives(unit, 'Service').get('ExecStart') ?? [];
  assert.deepEqual(exec, ['/opt/keybox/current/bin/node /opt/keybox/current/src/cli/kb-install.ts']);
});

test('KBOX-6 kb-install.path starts the service on any *.request in staging, with no start limit', () => {
  const unit = read('deploy/kb-install.path');
  assert.deepEqual(directives(unit, 'Path').get('PathExistsGlob'), ['/var/lib/keybox/staging/*.request']);
  assert.deepEqual(directives(unit, 'Path').get('Unit'), ['kb-install.service']);
  assert.deepEqual(directives(unit, 'Unit').get('StartLimitIntervalSec'), ['0']);
});

test('KBOX-6 kb-install.service also runs at every boot, so a switch a kill or power cut left half done is rolled back to its base', () => {
  assert.deepEqual(directives(read('deploy/kb-install.service'), 'Install').get('WantedBy'), ['multi-user.target']);
  const enable = /^\s*systemctl enable --now (.*)$/m.exec(read('deploy/cloud-init.yaml'))?.[1]?.split(' ') ?? [];
  assert.ok(enable.includes('kb-install.service'), 'cloud-init enables the service itself, not only its path unit');
});
