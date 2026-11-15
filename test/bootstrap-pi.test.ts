// KBOX-48, KBOX-46, KBOX-65, KBOX-67 on the Raspberry Pi: the first-start setup (deploy/cloud-init.yaml), the firewall file, the
// NTS-only chrony file, plain DNS and the Tailscale apt source. Text checks and fixture runs of the real scripts under fake
// `timedatectl`, `date`, `apt-get`, `systemctl`, `nft` and friends on a PATH in a temp dir, with $KB_FS_ROOT at a temp tree and a
// plain file for tty1 (design 3.1, 3.5, 3.6a). Nothing here runs a real apt-get, systemctl, tailscale or chronyc. What only the
// real Pi can show (that the chrony mask holds back the package's start, U24) stays UNVERIFIED.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import { directives, missingDirectives, runShell, tempDir } from './kit/index.ts';

const repo = new URL('../', import.meta.url).pathname;
const read = (path: string): string => readFileSync(join(repo, path), 'utf8');
const cloudInit = read('deploy/cloud-init.yaml');

// --- reading cloud-init -------------------------------------------------------------------------------------------------

/** The items of a top-level cloud-config list (`runcmd`, `bootcmd`), each as the script text cloud-init hands to sh. */
function listItems(section: string): string[] {
  const lines = cloudInit.split('\n');
  const from = lines.indexOf(`${section}:`);
  assert.ok(from >= 0, `cloud-init has ${section}`);
  const items: string[] = [];
  for (const line of lines.slice(from + 1)) {
    if (/^\S/.test(line)) break;
    if (/^ {2}#/.test(line)) continue;
    if (/^ {2}- \|$/.test(line)) items.push('');
    else if (/^ {2}- /.test(line)) items.push(line.slice(4));
    else if (line.startsWith('    ') || line === '') items[items.length - 1] = `${items.at(-1) ?? ''}${line.slice(4)}\n`;
    else assert.fail(`unreadable ${section} line: ${line}`);
  }
  return items;
}

/** Every code line (no comment, no blank) of the items, trimmed, in script order. */
const codeLines = (items: readonly string[]): string[] =>
  items.flatMap((i) => i.split('\n')).map((l) => l.trim()).filter((l) => l !== '' && !l.startsWith('#'));

const runcmd = listItems('runcmd');
const lines = codeLines(runcmd);
const at = (re: RegExp, from = 0): number => {
  const i = lines.findIndex((l, n) => n >= from && re.test(l));
  assert.ok(i >= 0, `runcmd has a line matching ${re.source}`);
  return i;
};
const firstFetch = (): number => at(/\bapt-get (-y )?(update|upgrade|install)\b/);

// --- hardening, time, packages: the text ------------------------------------------------------------------------------

test('KBOX-48 the Pi image is hardened: no default user, root locked, ssh and snapd purged, cloud-init quiet on tty1, no early apt step', () => {
  assert.match(cloudInit, /^users: \[\]$/m);
  assert.match(cloudInit, /^package_update: false$/m);
  assert.match(cloudInit, /^package_upgrade: false$/m);
  assert.match(cloudInit, /^output: \{all: '>> \/var\/log\/cloud-init-output\.log'\}$/m);
  assert.doesNotMatch(cloudInit, /^packages:/m, 'cloud-init installs no package itself: its own apt step would race the clock');
  assert.ok(lines.some((l) => /^if id ubuntu >\/dev\/null 2>&1; then userdel -r ubuntu; fi$/.test(l)), 'the default user goes when it exists');
  assert.ok(lines.includes('passwd -l root'));
  assert.ok(lines.includes('apt-get purge -y snapd'));
  assert.ok(lines.includes('apt-get purge -y openssh-server openssh-client'));
});

test('KBOX-48 the first runcmd item holds set -eu, the re-run guard and the trap; the trap removes policy-rc.d and never unmasks', () => {
  const first = runcmd[0] ?? '';
  assert.match(first, /^set -eu$/m);
  assert.match(first, /\[ -e "\$K\/var\/lib\/kb-bootstrap\/step" \]/, 'the guard looks for the step file');
  assert.match(first, /a second run/);
  assert.match(first, /^trap \S+ EXIT$/m);
  assert.match(first, /policy-rc\.d/);
  assert.doesNotMatch(first, /unmask/, 'a stop leaves the chrony mask in place');
  assert.match(first, /Key box setup stopped at: \$/);
});

test('KBOX-65 the stage-0 time wait comes before any apt-get that fetches, and systemd-timesyncd is disabled right after it, before any fetch', () => {
  const wait = at(/timedatectl/);
  const disable = at(/^systemctl disable --now systemd-timesyncd$/);
  assert.ok(wait < firstFetch(), 'the wait comes before every apt-get that fetches (update, upgrade, install)');
  assert.ok(disable > wait && disable < firstFetch());
  assert.equal(lines[disable - 1], 'done', 'the disable comes right after the wait loop');
});

test('KBOX-48 ssh goes first (design 3.6a): the purge, the mask and the authorized_keys removal, in that order, under their own step, before the stage-0 wait; snapd stays after it', () => {
  const purge = at(/^apt-get purge -y openssh-server openssh-client$/);
  const mask = at(/^systemctl mask --now ssh\.service ssh\.socket$/);
  const rm = at(/^rm -f \/home\/ubuntu\/\.ssh\/authorized_keys \/root\/\.ssh\/authorized_keys$/);
  const step = at(/^step ssh\b/);
  const wait = at(/timedatectl/);
  assert.ok(step < purge && purge < mask && mask < rm && rm < wait);
  assert.ok(at(/^apt-get purge -y snapd$/) > wait, 'the snapd purge stays in hardening, after the wait');
  assert.ok(step > at(/^trap \S+ EXIT$/), 'after strict mode, guard and trap');
});

test('KBOX-65 apt waits up to 30 minutes for the package lock a first-boot apt-daily may hold, by a file cloud-init writes before runcmd', () => {
  assert.match(cloudInit, /  - path: \/etc\/apt\/apt\.conf\.d\/50keybox-lock\n    permissions: '0644'\n    content: \|\n      DPkg::Lock::Timeout "1800";\n/);
});

test('KBOX-65 step 4 installs unattended-upgrades and nftables and not chrony; chrony comes only with tailscale in step 6', () => {
  const step4 = at(/apt-get install -y unattended-upgrades nftables$/);
  assert.doesNotMatch(lines[step4] ?? '', /chrony/);
  const chronyInstalls = lines.flatMap((l, n) => (/apt-get install\b.*\bchrony\b/.test(l) ? [n] : []));
  assert.deepEqual(chronyInstalls.map((n) => lines[n]), ['apt-get install -y chrony tailscale']);
  assert.ok(step4 < (chronyInstalls[0] ?? 0));
});

test('KBOX-67 the KB_DOMAIN drop-in loop lists the seven units, comes before daemon-reload and before every enable or start, and no unit is started directly', () => {
  const loop = at(/^for u in keybox keyrelay caddy kb-install kb-join kb-ready kb-code; do mkdir -p "\/etc\/systemd\/system\/\$u\.service\.d" && printf /);
  const reload = at(/systemctl daemon-reload/);
  assert.ok(loop < reload);
  for (const [n, l] of lines.entries()) if (/^systemctl (enable|start)\b/.test(l)) assert.ok(loop < n && reload < n, l);
  assert.ok(lines.some((l) => /Environment=KB_TIME_FLOOR=%s.*kb-join\.service\.d/.test(l)), 'KB_TIME_FLOOR reaches kb-join');
  assert.equal(lines.filter((l) => /^(keybox|keyrelay|caddy)\b/.test(l)).length, 0, 'no line starts keybox, keyrelay or caddy directly');
});

test('KBOX-65 the firewall is enabled before the chrony mask and policy-rc.d, and chrony stays masked until its NTS-only file exists', () => {
  const firewall = at(/^systemctl enable --now kb-firewall\.service kb-install\.path kb-install\.service$/);
  const mask = at(/^systemctl mask chrony\.service$/);
  const policy = at(/^printf .*policy-rc\.d/);
  assert.ok(firewall < mask && firewall < policy);
  const steps = [
    mask,
    policy,
    at(/^apt-get install -y chrony tailscale$/),
    at(/^rm -f "\$K\/usr\/sbin\/policy-rc\.d"$/, policy + 1),
    at(/^cp "\$K\/opt\/keybox\/current\/deploy\/chrony\.conf" "\$K\/etc\/chrony\/chrony\.conf"$/),
    at(/^cp "\$K\/opt\/keybox\/current\/deploy\/tailscaled\.defaults" "\$K\/etc\/default\/tailscaled"$/),
    at(/^systemctl unmask chrony\.service$/),
    at(/^systemctl restart chrony tailscaled$/),
  ];
  assert.deepEqual([...steps].sort((a, b) => a - b), steps, 'mask, policy-rc.d, install, policy-rc.d removal, both copies, unmask, restart, in that order');
  for (const l of lines.slice(mask + 1, steps[6])) assert.doesNotMatch(l, /^systemctl (start|enable|restart|reload)\b.*chrony/, `nothing starts chrony while it is masked: ${l}`);
});

test('KBOX-67 kb-bench runs before kb-join is enabled, the enabled marker follows at once, and kb-ready starts before the setup line, which names KB_DOMAIN', () => {
  const bench = at(/kb-bench/);
  const enable = at(/^systemctl enable kb-join\.service kb-ready\.service kb-code\.service keybox\.service keyrelay\.service caddy\.service$/);
  assert.ok(bench < enable);
  assert.match(lines[enable + 1] ?? '', /kb-bootstrap\/enabled/);
  const ready = at(/^systemctl start kb-ready\.service$/);
  const setup = at(/\/opt\/keybox\/current\/src\/cli\/kb-code\.ts setup$/);
  assert.ok(enable < ready && ready < setup);
  assert.match(lines[setup] ?? '', /^KB_DOMAIN="?\$KB_DOMAIN"? /);
});

test('KBOX-48 the download, H check and install lines are byte-identical to release 1 apart from the loop list and the lines the Pi adds after them', () => {
  const release = (runcmd.find((i) => i.includes('codeload.github.com')) ?? '').split('\n');
  const keep = [
    'set -eu',
    '. /root/keybox-release.env',
    'cd /root && umask 022',
    `curl --proto '=https' -fsSLo src.tar.gz "https://codeload.github.com/\${KB_REPO}/tar.gz/\${KB_COMMIT}"`,
    `curl --proto '=https' -fsSLo node.tar.gz "https://nodejs.org/dist/v24.11.1/node-v24.11.1-linux-arm64.tar.gz"`,
    `curl --proto '=https' -fsSLo caddy.tar.gz "https://github.com/caddyserver/caddy/releases/download/v2.10.2/caddy_2.10.2_linux_arm64.tar.gz"`,
    `printf '%s  node.tar.gz\\n%s  caddy.tar.gz\\n' "$NODE_ARCHIVE_SHA256" "$CADDY_ARCHIVE_SHA256" | sha256sum -c`,
    'mkdir src && tar xzf src.tar.gz -C src --strip-components=1 --no-same-owner',
    `[ -z "$(cd src && find . \\( \\( ! -type f ! -type d \\) -o -name '*[[:cntrl:]\\\\]*' \\) -print -quit)" ]`,
    `H=$(cd src && find . -type f | sed 's|^\\./||' | LC_ALL=C sort | while IFS= read -r f; do m=0644; case $(stat -c %A "$f") in ???[xs]*) m=0755;; esac; printf '%s %s %s\\n' "$m" "$(sha256sum < "$f" | cut -c1-64)" "$f"; done | sha256sum | cut -c1-64)`,
    '[ "$H" = "$KB_RELEASE" ]',
    'R=/opt/keybox/releases/$KB_RELEASE && mkdir -p "$R/bin" && cp -a src/. "$R/"',
    `tar xzf node.tar.gz --strip-components=2 -C "$R/bin" node-v24.11.1-linux-arm64/bin/node && tar xzf caddy.tar.gz -C "$R/bin" caddy`,
    `printf '%s  %s\\n%s  %s\\n' "$NODE_SHA256" "$R/bin/node" "$CADDY_SHA256" "$R/bin/caddy" | sha256sum -c`,
    'chown -R root:root /opt/keybox && chmod -R go-w /opt/keybox && ln -sfn "$R" /opt/keybox/current',
    `for u in keybox keyrelay caddy; do id "$u" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$u"; done`,
    'cp "$R"/deploy/*.service "$R"/deploy/kb-install.path /etc/systemd/system/ && cp "$R/deploy/keybox-tmpfiles.conf" /etc/tmpfiles.d/keybox.conf',
    'mkdir -p /etc/caddy && cp "$R/deploy/Caddyfile" /etc/caddy/Caddyfile',
  ];
  const code = release.map((l) => l.replace(/^ {4}/, '')).filter((l) => l.trim() !== '' && !l.trim().startsWith('#'));
  assert.deepEqual(code.slice(0, keep.length), keep);
});

// --- fixture runs of the whole runcmd script --------------------------------------------------------------------------------

const DOMAIN = 'keybox.tail1234.ts.net';
const FLOOR = 1_700_000_000;

interface BootOptions {
  /** `timedatectl` says "no" this many times before "yes". */
  readonly syncAfter?: number;
  /** `date +%s` answers a time before the floor this many times. */
  readonly staleDates?: number;
  /** Extra environment for the script, e.g. a fake that fails. */
  readonly env?: Readonly<Record<string, string>>;
  /** Files that exist before the run, under the root. */
  readonly files?: Readonly<Record<string, string>>;
}

interface Boot {
  readonly status: number | null;
  readonly stderr: string;
  readonly root: string;
  readonly events: readonly string[];
  readonly console: string;
  readonly file: (path: string) => string | undefined;
}

const FAKES: Readonly<Record<string, string>> = {
  timedatectl: `n=$(cat "$DIR/sync.n" 2>/dev/null || echo 0); echo $((n + 1)) > "$DIR/sync.n"
echo "timedatectl $*" >> "$EVENTS"
if [ "$n" -lt "\${FAKE_SYNC_AFTER:-0}" ]; then echo no; else echo yes; fi`,
  date: `n=$(cat "$DIR/date.n" 2>/dev/null || echo 0); echo $((n + 1)) > "$DIR/date.n"
if [ "$n" -lt "\${FAKE_STALE_DATES:-0}" ]; then echo ${FLOOR - 1000}; else echo ${FLOOR + 1000}; fi`,
  sleep: `echo "sleep $*" >> "$EVENTS"`,
  'apt-get': `echo "apt-get $*" >> "$EVENTS"
case " $* " in
  *" install "*" chrony "*)
    if [ -e "$DIR/mask/chrony.service" ]; then m=masked; else m=unmasked; fi
    if [ -e "$KB_FS_ROOT/usr/sbin/policy-rc.d" ]; then p=policy-rc.d; else p=no-policy-rc.d; fi
    echo "state at chrony install: $m $p" >> "$EVENTS"
    [ -z "\${FAKE_APT_FAIL_CHRONY:-}" ] || exit 100
    mkdir -p "$KB_FS_ROOT/etc/chrony"
    printf 'pool ntp.ubuntu.com iburst maxsources 4\\n' > "$KB_FS_ROOT/etc/chrony/chrony.conf"
    printf '# packaged default\\n' > "$KB_FS_ROOT/etc/default/tailscaled";;
esac`,
  systemctl: `echo "systemctl $*" >> "$EVENTS"
mkdir -p "$DIR/mask"
case "$1" in
  mask) shift; for u in "$@"; do : > "$DIR/mask/$u"; done;;
  unmask) shift; for u in "$@"; do rm -f "$DIR/mask/$u"; done
    if grep -q ' nts$' "$KB_FS_ROOT/etc/chrony/chrony.conf" 2>/dev/null; then echo "state at unmask: chrony.conf is NTS only" >> "$EVENTS"; else echo "state at unmask: chrony.conf is not NTS only" >> "$EVENTS"; fi;;
esac`,
  nft: `echo "nft $*" >> "$EVENTS"; [ -z "\${FAKE_NFT_FAIL:-}" ] || { echo "nft: syntax error" >&2; exit 1; }`,
  userdel: `echo "userdel $*" >> "$EVENTS"`,
  passwd: `echo "passwd $*" >> "$EVENTS"`,
  rfkill: `echo "rfkill $*" >> "$EVENTS"`,
  setterm: `echo "setterm $*" >> "$EVENTS"`,
  sysctl: `echo "sysctl $*" >> "$EVENTS"`,
  id: `[ "$1" = ubuntu ] && [ -n "\${FAKE_UBUNTU:-}" ]`,
  'kb-node': `echo "node $* KB_DOMAIN=\${KB_DOMAIN:-}" >> "$EVENTS"`,
};

const BASE_DIRS = ['boot/firmware', 'usr/sbin', 'etc/default', 'etc/sysctl.d', 'etc/apt/sources.list.d', 'etc/apt/apt.conf.d', 'usr/share/keyrings', 'etc/systemd', 'dev', 'root', 'var/lib'];

/** Runs the runcmd script as cloud-init does (one sh script) over a fixture root, with the release download step stood in for. */
async function bootstrap(t: TestContext, options: BootOptions = {}, script: readonly string[] = runcmd): Promise<Boot> {
  const dir = await tempDir(t);
  const root = join(dir, 'root');
  mkdirSync(join(dir, 'bin'));
  for (const d of BASE_DIRS) mkdirSync(join(root, d), { recursive: true });
  const put = (path: string, content: string): void => {
    mkdirSync(join(root, path, '..'), { recursive: true });
    writeFileSync(join(root, path), content);
  };
  put('root/keybox-release.env', `KB_DOMAIN=${DOMAIN}\nKB_TIME_FLOOR=${FLOOR}\n`);
  put('boot/firmware/config.txt', '[all]\narm_64bit=1\n');
  put('boot/firmware/cmdline.txt', 'console=serial0,115200 console=tty1 root=LABEL=writable rootfstype=ext4\n');
  put('dev/tty1', '');
  for (const [path, content] of Object.entries(options.files ?? {})) put(path, content);
  for (const [name, body] of Object.entries(FAKES)) writeFileSync(join(dir, 'bin', name), `#!/bin/sh\n${body}\n`, { mode: 0o755 });
  const standIn = `mkdir -p "$K/opt/keybox/current" "$K/var/lib/keybox"\ncp -r "${join(repo, 'deploy')}" "$K/opt/keybox/current/deploy"\necho "release step stood in" >> "$EVENTS"\n`;
  // The release download is real network and real /opt; the ssh key removal names real home directories. Both are stood in for.
  const standInFor = (i: string): string =>
    i.includes('codeload.github.com') ? standIn : i.startsWith('rm -f /home/ubuntu/.ssh/authorized_keys') ? 'rm -f "$K/home/ubuntu/.ssh/authorized_keys" "$K/root/.ssh/authorized_keys"' : i;
  const text = script.map(standInFor).join('\n');
  const env: Record<string, string> = {
    PATH: `${join(dir, 'bin')}:${process.env['PATH'] ?? ''}`,
    DIR: dir,
    EVENTS: join(dir, 'events.log'),
    KB_FS_ROOT: root,
    KB_NODE: join(dir, 'bin', 'kb-node'),
    FAKE_SYNC_AFTER: String(options.syncAfter ?? 0),
    FAKE_STALE_DATES: String(options.staleDates ?? 0),
    ...options.env,
  };
  const run = runShell(`${Object.entries(env).map(([k, v]) => `export ${k}='${v}'`).join('\n')}\n${text}`, dir);
  const readIf = (p: string): string | undefined => (existsSync(p) ? readFileSync(p, 'utf8') : undefined);
  return {
    status: run.status,
    stderr: run.stderr,
    root,
    events: (readIf(join(dir, 'events.log')) ?? '').split('\n').filter((l) => l !== ''),
    console: readIf(join(root, 'dev/tty1')) ?? '',
    file: (path) => readIf(join(root, path)),
  };
}

test('KBOX-65 the stage-0 time wait waits while timesyncd reports no sync and while the time is before the floor, then goes on', async (t) => {
  const b = await bootstrap(t, { syncAfter: 2, staleDates: 2 });
  assert.equal(b.status, 0, b.stderr);
  const sleeps = b.events.filter((e) => e.startsWith('sleep')).length;
  assert.ok(sleeps >= 4, `it waited at least four rounds (two without sync, two before the floor), saw ${sleeps}`);
  const disable = b.events.indexOf('systemctl disable --now systemd-timesyncd');
  assert.ok(disable > b.events.lastIndexOf('timedatectl show -p NTPSynchronized --value'), 'timesyncd is stopped after the last time check');
  assert.ok(disable < b.events.findIndex((e) => /^apt-get (-y )?(update|upgrade|install)\b/.test(e)), 'and before any apt-get that fetches');
  const purge = b.events.indexOf('apt-get purge -y openssh-server openssh-client');
  assert.ok(purge >= 0 && purge < b.events.indexOf('timedatectl show -p NTPSynchronized --value'), 'ssh is purged before the time wait');
  assert.match(b.console, /Key box setup, 1 of 5: getting the time/);
});

test('KBOX-65 a whole run holds chrony masked through the install and unmasks it only after the NTS-only file is copied over the package\'s', async (t) => {
  const b = await bootstrap(t);
  assert.equal(b.status, 0, b.stderr);
  const e = b.events;
  const install = e.indexOf('state at chrony install: masked policy-rc.d');
  assert.ok(install > 0, `chrony was masked, and policy-rc.d was in place, when its package was installed: ${e.join(' | ')}`);
  assert.ok(e.indexOf('systemctl mask chrony.service') < install);
  const unmask = e.indexOf('systemctl unmask chrony.service');
  assert.ok(unmask > install);
  assert.equal(e[unmask + 1], 'state at unmask: chrony.conf is NTS only', 'the package\'s plain-NTP file was replaced before the unmask');
  assert.equal(e.filter((x) => /^systemctl (start|enable|restart).*chrony/.test(x) && e.indexOf(x) < unmask).length, 0, 'nothing started chrony while it was masked');
  assert.ok(e.indexOf('systemctl restart chrony tailscaled') > unmask);
  assert.equal(existsSync(join(b.root, 'usr/sbin/policy-rc.d')), false, 'policy-rc.d is gone once the install is done');
  assert.equal(b.file('etc/chrony/chrony.conf'), read('deploy/chrony.conf'));
  assert.equal(b.file('etc/default/tailscaled'), read('deploy/tailscaled.defaults'));
});

test('KBOX-48 a whole run does each hardening step and each later step in order: default user, root, gettys, radios, console settings, units, join', async (t) => {
  const b = await bootstrap(t, { env: { FAKE_UBUNTU: '1' } });
  assert.equal(b.status, 0, b.stderr);
  const e = b.events;
  for (const call of ['userdel -r ubuntu', 'passwd -l root', 'apt-get purge -y snapd', 'systemctl mask getty@tty1.service autovt@tty1.service serial-getty@ttyS0.service', 'rfkill block wifi bluetooth', 'setterm --blank 0']) assert.ok(e.some((x) => x.startsWith(call)), call);
  const config = b.file('boot/firmware/config.txt') ?? '';
  for (const l of ['dtoverlay=disable-wifi', 'dtoverlay=disable-bt', 'hdmi_force_hotplug=1', 'gpu_mem=16']) assert.equal(config.split('\n').filter((x) => x === l).length, 1, l);
  assert.match(b.file('boot/firmware/cmdline.txt') ?? '', /^console=serial0,115200 console=tty1 root=LABEL=writable rootfstype=ext4 consoleblank=0\n$/);
  assert.match(b.file('etc/sysctl.d/60-keybox.conf') ?? '', /^kernel\.printk = 3 4 1 3\nkernel\.sysrq = 0\n$/);
  assert.match(b.file('etc/systemd/system.conf.d/60-keybox.conf') ?? '', /^\[Manager\]\nShowStatus=no\n$/);
  const calls = ['systemctl enable --now kb-firewall.service', 'systemctl enable kb-join.service', 'systemctl start kb-ready.service'].map((p) => e.findIndex((x) => x.startsWith(p)));
  assert.ok(calls.every((n) => n >= 0), `every call happened: ${e.join(' | ')}`);
  assert.deepEqual([...calls].sort((a, b) => a - b), calls, 'firewall, enable, start, in that order');
  assert.deepEqual(e.filter((x) => x.startsWith('node ')), [`node /opt/keybox/current/src/cli/kb-bench.ts KB_DOMAIN=`, `node /opt/keybox/current/src/cli/kb-code.ts setup KB_DOMAIN=${DOMAIN}`]);
  assert.match(b.console, /Key box setup, 5 of 5: joining Tailscale/);
  assert.equal(b.file('var/lib/kb-bootstrap/enabled'), '');
  assert.ok(b.file('var/lib/kb-bootstrap/step') !== undefined);
  assert.equal(b.file('var/lib/kb-bootstrap/stopped'), undefined);
});

test('KBOX-48 the Pi\'s own files are put in place by the release step and checked: the nftables file is syntax-checked before its service is enabled', async (t) => {
  const b = await bootstrap(t);
  assert.equal(b.status, 0, b.stderr);
  assert.equal(b.file('etc/keybox/nftables.nft'), read('deploy/keybox-nftables.nft'));
  assert.equal(b.file('etc/systemd/resolved.conf.d/keybox.conf'), read('deploy/resolved-keybox.conf'));
  assert.ok(b.events.indexOf('systemctl restart systemd-resolved') > 0);
  assert.equal(b.file('etc/apt/sources.list.d/tailscale.sources'), read('deploy/tailscale.sources'));
  assert.equal(b.file('usr/share/keyrings/tailscale-archive-keyring.asc'), read('deploy/tailscale-archive-keyring.asc'));
  assert.ok(b.events.findIndex((x) => x.startsWith('nft -c -f')) < b.events.indexOf('systemctl enable --now kb-firewall.service kb-install.path kb-install.service'));
});

test('KBOX-48 a failing middle step writes "Key box setup stopped at: <step>" to the console and to stopped, and removes policy-rc.d, leaving chrony masked', async (t) => {
  const b = await bootstrap(t, { env: { FAKE_APT_FAIL_CHRONY: '1' } });
  assert.notEqual(b.status, 0, 'the chrony install failed, so the script failed');
  assert.match(b.console, /Key box setup stopped at: \S[^\n]*\. Write the card again\.$/m);
  const stopped = b.file('var/lib/kb-bootstrap/stopped') ?? '';
  assert.match(stopped, /^Key box setup stopped at: \S[^\n]*\. Write the card again\.\n$/);
  assert.equal(existsSync(join(b.root, 'usr/sbin/policy-rc.d')), false, 'the trap removed policy-rc.d');
  assert.equal(b.events.includes('systemctl unmask chrony.service'), false, 'the trap leaves the chrony mask in place');
  assert.equal(b.events.some((x) => x.startsWith('systemctl enable kb-join')), false, 'nothing after the stop ran');
  assert.equal(b.file('var/lib/kb-bootstrap/enabled'), undefined);
});

test('KBOX-48 a nftables file the check refuses stops the bootstrap before the firewall service is enabled', async (t) => {
  const b = await bootstrap(t, { env: { FAKE_NFT_FAIL: '1' } });
  assert.notEqual(b.status, 0);
  assert.equal(b.events.some((x) => x.startsWith('systemctl enable --now kb-firewall')), false);
  assert.match(b.file('var/lib/kb-bootstrap/stopped') ?? '', /^Key box setup stopped at: /);
});

test('KBOX-48 a second run, with the step file already there, stops at once with "a second run" and runs nothing', async (t) => {
  const b = await bootstrap(t, { files: { 'var/lib/kb-bootstrap/step': 'release\n' } });
  assert.notEqual(b.status, 0);
  assert.match(b.console, /Key box setup stopped at: a second run\. Write the card again\./);
  assert.match(b.file('var/lib/kb-bootstrap/stopped') ?? '', /a second run/);
  assert.deepEqual(b.events, [], 'no command ran');
  assert.equal(b.file('var/lib/kb-bootstrap/step'), 'release\n', 'the earlier step name is kept');
});

// --- bootcmd -----------------------------------------------------------------------------------------------------------------

async function bootcmd(t: TestContext, files: Readonly<Record<string, string>>): Promise<{ readonly status: number | null; readonly console: string; readonly cutOff: string | undefined }> {
  const dir = await tempDir(t);
  const root = join(dir, 'root');
  mkdirSync(join(root, 'dev'), { recursive: true });
  mkdirSync(join(root, 'var/lib'), { recursive: true });
  writeFileSync(join(root, 'dev/tty1'), '');
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(join(root, path, '..'), { recursive: true });
    writeFileSync(join(root, path), content);
  }
  const run = runShell(`KB_FS_ROOT='${root}'; export KB_FS_ROOT\n${listItems('bootcmd').join('\n')}`, dir);
  const cut = join(root, 'var/lib/kb-bootstrap/cut-off');
  return { status: run.status, console: readFileSync(join(root, 'dev/tty1'), 'utf8'), cutOff: existsSync(cut) ? readFileSync(cut, 'utf8') : undefined };
}

test('KBOX-48 bootcmd names the cut-off step on the console and in cut-off when step is there and enabled is not', async (t) => {
  const r = await bootcmd(t, { 'var/lib/kb-bootstrap/step': 'release\n' });
  assert.equal(r.status, 0);
  const line = 'Key box setup was cut off at: release (a power cut?). Write the card again.\n';
  assert.equal(r.console, line);
  assert.equal(r.cutOff, line);
});

test('KBOX-48 bootcmd says nothing when both markers are there, and nothing on a first boot where neither is', async (t) => {
  const both = await bootcmd(t, { 'var/lib/kb-bootstrap/step': 'enable\n', 'var/lib/kb-bootstrap/enabled': '' });
  assert.deepEqual([both.status, both.console, both.cutOff], [0, '', undefined]);
  const neither = await bootcmd(t, {});
  assert.deepEqual([neither.status, neither.console, neither.cutOff], [0, '', undefined]);
});

// --- deploy files ------------------------------------------------------------------------------------------------------------

/** The rule lines of one chain of the firewall file, whitespace collapsed. */
function chainRules(name: 'input' | 'output'): string[] {
  const text = read('deploy/keybox-nftables.nft');
  const body = new RegExp(`chain ${name} \\{([^}]*(?:\\{[^}]*\\}[^}]*)*)\\n\\t\\}`).exec(text)?.[1];
  assert.ok(body !== undefined, `the file has chain ${name}`);
  return body.split('\n').map((l) => l.trim().replace(/\s+/g, ' ')).filter((l) => l !== '' && !l.startsWith('type '));
}

test('KBOX-65 the firewall file has its own table, never flushes the ruleset, and declares, deletes then defines the table so a second load gives one copy', () => {
  const text = read('deploy/keybox-nftables.nft');
  const code = text.split('\n').filter((l) => !l.trim().startsWith('#')).map((l) => l.trim()).filter((l) => l !== '');
  assert.deepEqual(code.slice(0, 3), ['table inet keybox', 'delete table inet keybox', 'table inet keybox {']);
  assert.doesNotMatch(code.join('\n'), /flush ruleset/);
  assert.equal(code.filter((l) => /^table /.test(l)).length, 2, 'one declaration and one definition');
  assert.equal(code.filter((l) => /^table /.test(l) && !/^table inet keybox( \{)?$/.test(l)).length, 0, 'no other table is touched');
  assert.match(text, /chain input \{\n\t\ttype filter hook input priority filter; policy drop;/);
  assert.match(text, /chain output \{\n\t\ttype filter hook output priority filter; policy drop;/);
});

test('KBOX-65 the firewall file accepts new inbound only tcp 443 and 8443 on tailscale0 and nothing on other interfaces', () => {
  assert.deepEqual(chainRules('input'), [
    'iifname "lo" accept',
    'ct state established,related accept',
    'iifname "tailscale0" tcp dport { 443, 8443 } ct state new accept',
    'iifname != "tailscale0" udp sport 67 udp dport 68 accept',
    'iifname != "tailscale0" udp sport 547 udp dport 546 accept',
    'iifname != "tailscale0" icmpv6 type { nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept',
  ]);
  assert.equal(chainRules('input').filter((r) => /dport/.test(r) && !/dport (\{ 443, 8443 \}|68|546)/.test(r)).length, 0, 'no other port is opened inbound');
  assert.equal(chainRules('input').some((r) => /dport[^{]*\b(22|80|2019|5252)\b/.test(r)), false);
});

test('KBOX-65 the firewall file accepts new outbound tcp 443, tcp 4460 and udp 123 only to non-private addresses', () => {
  const rules = chainRules('output');
  assert.deepEqual(rules, [
    'oifname "lo" accept',
    'ct state established,related accept',
    'oifname "tailscale0" drop',
    'udp dport { 53, 67, 547 } accept',
    'tcp dport 53 accept',
    'meta l4proto { icmp, ipv6-icmp } accept',
    'udp sport 41641 accept',
    'ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 } drop',
    'ip6 daddr { fc00::/7, fe80::/10 } drop',
    'tcp dport { 443, 4460 } accept',
    'udp dport { 123, 3478 } accept',
  ]);
  const lastDrop = Math.max(...rules.flatMap((r, n) => (/ daddr \{.*\} drop$/.test(r) ? [n] : [])));
  const firstNonPrivate = Math.min(...rules.flatMap((r, n) => (/^(tcp|udp) dport \{ (443|123)/.test(r) ? [n] : [])));
  assert.ok(lastDrop < firstNonPrivate, 'both private-range drops come before the accepts that are only for the rest');
  assert.ok((rules.indexOf('oifname "tailscale0" drop')) < rules.indexOf('udp dport { 53, 67, 547 } accept'), 'nothing new leaves on tailscale0');
});

/** Whether this machine can load an nftables file inside a throwaway user and network namespace (no root, no host change). */
const sandbox = (): boolean => runShell('command -v nft >/dev/null && unshare -Urn true', repo).status === 0;

test('KBOX-65 the real nft loads the firewall file twice in a throwaway network namespace and keeps one copy of the table; a broken file is refused', async (t) => {
  if (!sandbox()) return t.skip('no nft or no unprivileged namespace here: the text checks above stand in');
  const dir = await tempDir(t);
  const file = join(repo, 'deploy/keybox-nftables.nft');
  const twice = runShell(`unshare -Urn sh -c 'nft -f "${file}" && nft -f "${file}" && nft list ruleset'`, dir);
  assert.equal(twice.status, 0, twice.stderr);
  assert.equal(twice.stdout.match(/^table inet keybox \{/gm)?.length, 1, 'one copy after two loads');
  writeFileSync(join(dir, 'broken.nft'), read('deploy/keybox-nftables.nft').replace('policy drop;', 'policy dorp;'));
  assert.notEqual(runShell(`unshare -Urn nft -c -f "${join(dir, 'broken.nft')}"`, dir).status, 0, 'the check is not vacuous');
});

test('KBOX-65 kb-firewall.service loads the file before the network, needs no default dependencies, and is wanted by sysinit.target', () => {
  const unit = read('deploy/kb-firewall.service');
  assert.deepEqual(missingDirectives(unit, { Type: 'oneshot', RemainAfterExit: 'yes', ExecStart: '/usr/sbin/nft -f /etc/keybox/nftables.nft' }), []);
  const u = directives(unit, 'Unit');
  assert.deepEqual([u.get('DefaultDependencies'), u.get('After'), u.get('Before'), u.get('Wants')], [['no'], ['local-fs.target'], ['network-pre.target'], ['network-pre.target']]);
  assert.deepEqual(directives(unit, 'Install').get('WantedBy'), ['sysinit.target']);
});

test('KBOX-65 chrony.conf has exactly three NTS servers and no plain source: no pool, no sourcedir, no leapsectz, and the NTS-only settings', () => {
  const conf = read('deploy/chrony.conf').split('\n').filter((l) => l.trim() !== '' && !l.startsWith('#'));
  assert.deepEqual(conf.filter((l) => l.startsWith('server ')), ['server time.cloudflare.com iburst nts', 'server nts.netnod.se iburst nts', 'server ptbtime1.ptb.de iburst nts']);
  assert.equal(conf.filter((l) => /^(pool|sourcedir|leapsectz|peer|refclock|confdir)\b/.test(l)).length, 0);
  for (const l of ['authselectmode require', 'minsources 2', 'nocerttimecheck 1', 'makestep 1 3']) assert.equal(conf.filter((c) => c === l).length, 1, l);
});

test('KBOX-65 the resolved drop-in turns DNS over TLS and DNSSEC off, so names never depend on the clock', () => {
  const resolve = directives(read('deploy/resolved-keybox.conf'), 'Resolve');
  assert.deepEqual([resolve.get('DNSOverTLS'), resolve.get('DNSSEC')], [['no'], ['no']]);
});

/** The v4 fingerprint of the first key packet of an armoured OpenPGP key: SHA-1 over 0x99, the 2-byte length and the packet body. */
function fingerprint(armoured: string): string {
  const body = armoured.split('\n').filter((l) => l !== '' && !l.startsWith('-----') && !l.startsWith('=') && !l.includes(': '));
  const bytes = Buffer.from(body.join(''), 'base64');
  assert.equal(bytes[0], 0x99, 'an old-format public key packet with a 2-byte length');
  const length = bytes.readUInt16BE(1);
  return createHash('sha1').update(Buffer.concat([Buffer.from([0x99]), bytes.subarray(1, 3), bytes.subarray(3, 3 + length)])).digest('hex').toUpperCase();
}

test('KBOX-46 the Tailscale apt source is a deb822 file signed by the key file that ships with it, and that key is Tailscale\'s published one', () => {
  const sources = read('deploy/tailscale.sources').split('\n').filter((l) => l.trim() !== '' && !l.startsWith('#'));
  assert.deepEqual(sources, ['Types: deb', 'URIs: https://pkgs.tailscale.com/stable/ubuntu', 'Suites: noble', 'Components: main', 'Signed-By: /usr/share/keyrings/tailscale-archive-keyring.asc']);
  const key = read('deploy/tailscale-archive-keyring.asc');
  assert.match(key, /^-----BEGIN PGP PUBLIC KEY BLOCK-----\n/);
  assert.equal(fingerprint(key), '2596A99EAAB33821893C0A79458CA832957F5868', 'the repository signing key Tailscale publishes (Tailscale Inc. package repository signing key)');
});

test('KBOX-46 unattended-upgrades also takes Tailscale\'s packages, by the origin its Release file names', () => {
  assert.match(cloudInit, /path: \/etc\/apt\/apt\.conf\.d\/52keybox-tailscale\n/);
  assert.match(cloudInit, /Unattended-Upgrade::Origins-Pattern \{ "origin=Tailscale,codename=noble"; \};/);
});

test('KBOX-67 the release env file carries the time floor the stage-0 wait and kb-join read', () => {
  assert.match(cloudInit, /^\s*KB_TIME_FLOOR=\d+$/m);
});
