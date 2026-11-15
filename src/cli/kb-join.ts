// kb-join (KBOX-64): the root oneshot that gets an authenticated time, joins Tailscale, checks the box's own name and writes the time
// gate file; `kb-join ready` (kb-ready.service) then waits for the certificate. Everything it shows goes to the tty file (/dev/tty1 on
// the box) and nothing to stdout or stderr. A transient Tailscale state only ever waits; the one terminal state is a wrong name seen on
// two reads 30 s apart. Every module below is a static import, so reaching `--self-check` loaded them all.
import { spawn, spawnSync } from 'node:child_process';
import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { uptime } from 'node:os';
import { dirname, isAbsolute, join } from 'node:path';
import { connect } from 'node:tls';
import { DOMAIN_NAME } from '../pure/actions.ts';
import { sameHostName } from '../pure/host-name.ts';
import { decodeJsonBody } from '../pure/schemas.ts';
import { TIME_OK_FILE } from '../pure/time-gate.ts';
import type { Clock } from '../ports/clock.ts';
import { systemClock, systemScheduler } from '../shell/clock.ts';

const SELF_CHECK = '--self-check';
const LINE_START = '\r\x1b[2K';
const POLL_MS = 5_000;
const WRONG_NAME_RECHECK_MS = 30_000;
const NO_LOGIN_MS = 60_000;
const SOURCES = 3;
const HTTPS_PORT = 8443;
/** The budgets of design 3.8 that kb-ready judges (availability budgets: a miss is a fact, never a stop). */
const BUDGET = { copy_ms: 30_000, self_check_ms: 5_000, update_memory_kib: 65_536, core_start_ms: 20_000, relay_start_ms: 10_000 } as const;
const UP_ARGS = ['up', '--qr', '--hostname=keybox', '--advertise-tags=tag:keybox', '--ssh=false', '--accept-dns=false', '--accept-routes=false'] as const;

const L1 = (name: string): string =>
  `This box joined Tailscale as "${name}" because another machine already has the name "keybox". In Tailscale's Machines page, remove that other machine, then rename this one to "keybox". Then restart this box (unplug it and plug it back in).`;
const TAG_LINE = 'This box does not carry the tag keybox with key expiry off. Fix it on its Machines page; the box goes on by itself.';
const NO_LONGER = 'This box is no longer in Tailscale. It has to be set up again (guide: If the card dies).';

export interface JoinDeps {
  /** The environment the commands are started with (their PATH finds chronyc, tailscale and nft). */
  readonly env: NodeJS.ProcessEnv;
  readonly clock: Clock;
  readonly wait: (ms: number) => Promise<void>;
  /** The file standing for tty1. */
  readonly tty: string;
  /** Where the time gate file is written; the default is the one constant, so production writes only that path. */
  readonly okFile?: string;
  readonly factsFile: string;
  readonly trustFile: string;
  /** `/var/lib/keybox-install`: its `rehearsal.*` entries are removed at the start of a run. */
  readonly installDir: string;
  /** KB_DOMAIN: the expected host. */
  readonly domain: string;
  /** KB_TIME_FLOOR in milliseconds; 0 when the drop-in sets none. */
  readonly timeFloorMs: number;
}

export interface ReadyDeps {
  readonly env: NodeJS.ProcessEnv;
  readonly clock: Clock;
  readonly wait: (ms: number) => Promise<void>;
  readonly tty: string;
  readonly factsFile: string;
  readonly domain: string;
  /** One TLS check of https://<domain>:8443/ against 127.0.0.1, chain and name verified. */
  readonly tlsOk: () => Promise<boolean>;
  readonly meminfoFile: string;
  readonly uptimeMs: () => number;
  /** When the socket file was made (ms since the epoch), NaN when it is not there. */
  readonly socketBornMs: (path: string) => number;
  readonly coreSocket: string;
  readonly relaySocket: string;
}

// ------------------------------------------------------------------------------------------------ the screen and the commands

class Screen {
  #last: string | undefined;
  #base: string | undefined;
  #since = 0;

  readonly #tty: string;
  readonly #clock: Clock;

  constructor(tty: string, clock: Clock) {
    this.#tty = tty;
    this.#clock = clock;
  }

  /** One line, rewritten in place, with the minutes elapsed since its text last changed. */
  status(text: string): void {
    if (text !== this.#base) {
      this.#base = text;
      this.#since = this.#clock.now();
    }
    const minutes = Math.floor((this.#clock.now() - this.#since) / 60_000);
    const line = minutes >= 1 ? `${text} (${minutes} min)` : text;
    if (line === this.#last) return;
    this.#last = line;
    appendFileSync(this.#tty, LINE_START + line);
  }

  /** Output of a command, as it comes. */
  raw(chunk: Buffer): void {
    if (this.#last !== undefined) appendFileSync(this.#tty, '\n');
    appendFileSync(this.#tty, chunk);
    this.#last = undefined;
  }

  end(): void {
    appendFileSync(this.#tty, '\n');
  }
}

interface Ran {
  readonly ok: boolean;
  readonly stdout: string;
}

/** A command that is not there, or that exits non-zero, is a not-ok result: tailscaled and chrony are allowed to be late. */
function run(env: NodeJS.ProcessEnv, command: string, args: readonly string[]): Ran {
  const done = spawnSync(command, [...args], { env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  return { ok: done.error === undefined && done.status === 0, stdout: done.stdout };
}

/** `tailscale up --qr ...`: its output goes to the tty as it comes (the QR code must show while it waits for the login). */
function runUp(deps: JoinDeps, screen: Screen): Promise<{ readonly ok: boolean; readonly first: string }> {
  return new Promise((resolve) => {
    const child = spawn('tailscale', [...UP_ARGS], { env: deps.env, stdio: ['ignore', 'pipe', 'pipe'] });
    let errText = '';
    let outText = '';
    child.stdout.on('data', (chunk: Buffer) => {
      outText += chunk.toString('utf8');
      screen.raw(chunk);
    });
    child.stderr.on('data', (chunk: Buffer) => {
      errText += chunk.toString('utf8');
      screen.raw(chunk);
    });
    const first = (): string => (errText + outText).split('\n').find((l) => l.trim() !== '')?.trim() ?? 'no message';
    child.once('error', (e) => resolve({ ok: false, first: e.message }));
    child.once('close', (code) => resolve({ ok: code === 0, first: first() }));
  });
}

// ------------------------------------------------------------------------------------------------ facts

type Json = Record<string, unknown>;
const isObject = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Reads the facts file (an absent or unreadable one starts empty: facts are names and numbers, never a gate), changes it, and
 * replaces it whole, world-readable. */
function updateFacts(path: string, change: (facts: Json) => void): void {
  const decoded = existsSync(path) ? decodeJsonBody(readFileSync(path)) : { ok: false as const };
  const facts: Json = decoded.ok && isObject(decoded.value) ? decoded.value : {};
  change(facts);
  mkdirSync(dirname(path), { recursive: true });
  const next = `${path}.new`;
  writeFileSync(next, `${JSON.stringify(facts)}\n`);
  chmodSync(next, 0o644);
  renameSync(next, path);
}

// ------------------------------------------------------------------------------------------------ tailscale's answer

type Read =
  | { readonly kind: 'unreadable' }
  | { readonly kind: 'state'; readonly backend: string; readonly dns: string | undefined; readonly tags: readonly string[] | undefined; readonly expiry: boolean };

/** `tailscale status --json`, parsed at the edge. The field names are Tailscale's [UNVERIFIED: U23]. */
function readStatus(env: NodeJS.ProcessEnv): Read {
  const done = run(env, 'tailscale', ['status', '--json']);
  const decoded = done.ok ? decodeJsonBody(Buffer.from(done.stdout)) : { ok: false as const };
  if (!decoded.ok || !isObject(decoded.value) || typeof decoded.value['BackendState'] !== 'string') return { kind: 'unreadable' };
  const self = decoded.value['Self'];
  const selfObject = isObject(self) ? self : undefined;
  const dns = typeof selfObject?.['DNSName'] === 'string' ? selfObject['DNSName'] : undefined;
  const rawTags = selfObject?.['Tags'];
  const tags = Array.isArray(rawTags) && rawTags.every((x) => typeof x === 'string') ? (rawTags as string[]) : undefined;
  const rawExpiry = selfObject?.['KeyExpiry'];
  const expiry = typeof rawExpiry === 'string' && rawExpiry !== '' && !rawExpiry.startsWith('0001-');
  return { kind: 'state', backend: decoded.value['BackendState'], dns, tags, expiry };
}

interface Trust {
  readonly exists: boolean;
  readonly host: string | undefined;
}

function readTrust(path: string): Trust {
  if (!existsSync(path)) return { exists: false, host: undefined };
  const decoded = decodeJsonBody(readFileSync(path));
  const host = decoded.ok && isObject(decoded.value) && typeof decoded.value['domain'] === 'string' ? decoded.value['domain'] : undefined;
  return { exists: true, host };
}

// ------------------------------------------------------------------------------------------------ join

/** Sources that passed selection: with `authselectmode require` those are authenticated ones. */
function answering(env: NodeJS.ProcessEnv): number {
  const listed = run(env, 'chronyc', ['-n', '-c', 'sources']);
  return listed.stdout.split('\n').filter((row) => ['*', '+', '-'].includes(row.split(',')[1] ?? '')).length;
}

/** Stage 1: waits for as long as it takes, and returns the number of authenticated sources. */
async function timeStage(deps: JoinDeps, screen: Screen): Promise<number> {
  for (;;) {
    const before = answering(deps.env);
    screen.status(`Key box, step 1 of 4: getting the time from secure time servers (${before} of ${SOURCES} answer)`);
    const synced = run(deps.env, 'chronyc', ['-n', 'waitsync', '60', '1']).ok;
    const sources = answering(deps.env);
    if (synced && sources >= 2) {
      if (deps.clock.now() >= deps.timeFloorMs) return sources;
      screen.status('Key box, step 1 of 4: the time servers report a time before this release; check the network cable');
    } else {
      screen.status(`Key box, step 1 of 4: getting the time from secure time servers (${sources} of ${SOURCES} answer)`);
    }
    await deps.wait(POLL_MS);
  }
}

/** Removes what a first-boot rehearsal cut off by a power cut left on the card. */
function removeRehearsalDebris(dir: string): void {
  if (!existsSync(dir)) return;
  for (const entry of readdirSync(dir)) if (entry.startsWith('rehearsal.')) rmSync(join(dir, entry), { recursive: true, force: true });
}

export async function runJoin(deps: JoinDeps): Promise<number> {
  const screen = new Screen(deps.tty, deps.clock);
  const step2 = (text: string): void => screen.status(`Key box, step 2 of 4: ${text}`);
  removeRehearsalDebris(deps.installDir);
  const sources = await timeStage(deps, screen);
  writeFileSync(deps.okFile ?? TIME_OK_FILE, '');

  let upStarted = false;
  /** A wrong name seen on the previous read, waiting for the second one. */
  let wrongName: string | undefined;
  for (;;) {
    const read = readStatus(deps.env);
    if (read.kind === 'unreadable') {
      wrongName = undefined;
      step2('waiting for Tailscale to start');
      await deps.wait(POLL_MS);
      continue;
    }
    const trust = readTrust(deps.trustFile);
    const hosts = trust.host === undefined ? [deps.domain] : [deps.domain, trust.host];
    const named = read.dns !== undefined && read.dns !== '';
    if (read.backend === 'Running' && named) {
      const dns = read.dns ?? '';
      if (!hosts.every((h) => sameHostName(dns, h))) {
        if (wrongName !== undefined && sameHostName(wrongName, dns)) {
          // Only the pinned host differs: the name is the expected one, so the "another machine has it" text would be wrong.
          screen.status(sameHostName(dns, deps.domain) ? `This box's Tailscale name is "${dns}", not the name it was set up with ("${trust.host ?? ''}"). Fix the name on Tailscale's Machines page, then restart this box.` : L1(dns.split('.')[0] ?? dns));
          screen.end();
          return 1;
        }
        wrongName = dns;
        screen.status('Key box, step 3 of 4: checking its name');
        await deps.wait(WRONG_NAME_RECHECK_MS);
        continue;
      }
      wrongName = undefined;
      if (read.tags?.length !== 1 || read.tags[0] !== 'tag:keybox' || read.expiry) {
        screen.status(TAG_LINE);
        await deps.wait(WRONG_NAME_RECHECK_MS);
        continue;
      }
      const nft = run(deps.env, 'nft', ['list', 'table', 'inet', 'keybox']).ok;
      updateFacts(deps.factsFile, (facts) => {
        facts['join'] = { name: dns, tags: read.tags, key_expiry: 'none', nts_sources: sources, nft_table: nft };
      });
      screen.end();
      return 0;
    }
    wrongName = undefined;
    if (read.backend === 'Running' || read.backend === 'NoState' || read.backend === 'Starting') {
      step2('waiting for Tailscale to connect');
    } else if (read.backend === 'NeedsLogin' && !trust.exists) {
      step2('scan this code with your phone to add the key box to Tailscale');
      if (!upStarted) {
        const up = await runUp(deps, screen);
        if (up.ok) {
          upStarted = true;
          continue;
        }
        screen.status(`Key box, step 2 of 4: Tailscale did not accept this box (${up.first}); trying again in 60 s`);
        await deps.wait(NO_LOGIN_MS);
        continue;
      }
    } else if ((read.backend === 'NeedsLogin' || read.backend === 'Stopped') && trust.exists) {
      screen.status(NO_LONGER);
      await deps.wait(NO_LOGIN_MS);
      continue;
    } else if (read.backend === 'NeedsMachineAuth') {
      step2("approve this box on Tailscale's Machines page");
    } else {
      step2(`waiting for Tailscale (state: ${read.backend})`);
    }
    await deps.wait(POLL_MS);
  }
}

// ------------------------------------------------------------------------------------------------ ready

/** Unit activation to socket, in ms; null when the unit, its time or the socket cannot be read. */
function startMs(deps: ReadyDeps, unit: string, socket: string): number | null {
  const shown = run(deps.env, 'systemctl', ['show', '-P', 'ActiveEnterTimestampMonotonic', unit]);
  const activeUs = Number(shown.stdout.trim());
  const born = deps.socketBornMs(socket);
  if (!shown.ok || !Number.isFinite(activeUs) || activeUs <= 0 || !Number.isFinite(born)) return null;
  return Math.round(born - (deps.clock.now() - deps.uptimeMs() + activeUs / 1000));
}

function memAvailableKib(file: string): number | null {
  const match = existsSync(file) ? /^MemAvailable:\s+(\d+) kB$/m.exec(readFileSync(file, 'utf8')) : null;
  return match === null ? null : Number(match[1]);
}

interface OverItem {
  readonly item: string;
  readonly measured: number;
  readonly budget: number;
  readonly unit: 'ms' | 'KiB';
}

const OWN_ITEMS = /^(update\..*|core\.start|relay\.start)$/;
const num = (v: unknown): number | undefined => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);

/** The update.* items of bench.over (the bench's numbers against 3.8's budgets) and the start items. */
function overItems(update: Json, memKib: number | null, core: number | null, relay: number | null): OverItem[] {
  const over: OverItem[] = [];
  const copy = num(update['copy_ms']);
  const selfCheck = num(update['self_check_ms']);
  const peak = num(update['peak_rss_kb']);
  if (copy !== undefined && copy > BUDGET.copy_ms) over.push({ item: 'update.copy', measured: copy, budget: BUDGET.copy_ms, unit: 'ms' });
  if (selfCheck !== undefined && selfCheck > BUDGET.self_check_ms) over.push({ item: 'update.self_check', measured: selfCheck, budget: BUDGET.self_check_ms, unit: 'ms' });
  if (memKib !== null && peak !== undefined && memKib - peak < BUDGET.update_memory_kib) over.push({ item: 'update.memory', measured: memKib - peak, budget: BUDGET.update_memory_kib, unit: 'KiB' });
  if (core !== null && core > BUDGET.core_start_ms) over.push({ item: 'core.start', measured: core, budget: BUDGET.core_start_ms, unit: 'ms' });
  if (relay !== null && relay > BUDGET.relay_start_ms) over.push({ item: 'relay.start', measured: relay, budget: BUDGET.relay_start_ms, unit: 'ms' });
  return over;
}

export async function runReady(deps: ReadyDeps): Promise<number> {
  const screen = new Screen(deps.tty, deps.clock);
  for (;;) {
    screen.status("Key box, step 4 of 4: waiting for its certificate (if this lasts over 10 minutes: HTTPS must be on in Tailscale's DNS page)");
    if (await deps.tlsOk()) break;
    await deps.wait(POLL_MS);
  }
  const core = startMs(deps, 'keybox.service', deps.coreSocket);
  const relay = startMs(deps, 'keyrelay.service', deps.relaySocket);
  const mem = memAvailableKib(deps.meminfoFile);
  updateFacts(deps.factsFile, (facts) => {
    facts['ready'] = { core_start_ms: core, relay_start_ms: relay, mem_available_kb: mem };
    const bench: Json = isObject(facts['bench']) ? facts['bench'] : {};
    const update = isObject(bench['update']) ? bench['update'] : {};
    const kept = Array.isArray(bench['over']) ? bench['over'].filter((o: unknown) => !(isObject(o) && typeof o['item'] === 'string' && OWN_ITEMS.test(o['item']))) : [];
    bench['over'] = [...kept, ...overItems(update, mem, core, relay)];
    facts['bench'] = bench;
  });
  screen.status('Key box ready.');
  screen.end();
  return 0;
}

/** One TLS check against 127.0.0.1 with the name `host`: the chain and the name are verified; any failure is `false`. */
export function tlsCheck(host: string, port: number, ca?: string): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = connect({ host: '127.0.0.1', port, servername: host, ...(ca === undefined ? {} : { ca }) });
    socket.setTimeout(5_000, () => {
      socket.destroy();
      resolve(false);
    });
    socket.once('secureConnect', () => {
      resolve(socket.authorized);
      socket.end();
    });
    socket.once('error', () => resolve(false));
  });
}

// ------------------------------------------------------------------------------------------------ the entry

const absolute = (value: string | undefined, fallback: string): string => {
  const path = value ?? fallback;
  if (!isAbsolute(path)) throw new RangeError('kb-join paths are absolute');
  return path;
};

function readDomain(env: NodeJS.ProcessEnv): string {
  const domain = env['KB_DOMAIN'];
  if (domain === undefined) throw new RangeError('KB_DOMAIN is not set');
  if (!DOMAIN_NAME.test(domain)) throw new RangeError('KB_DOMAIN is not a domain name');
  return domain;
}

/** KB_TIME_FLOOR is the Unix time (seconds) of the release's commit; unset, no floor beyond systemd's own epoch. */
function readFloorMs(env: NodeJS.ProcessEnv): number {
  const floor = env['KB_TIME_FLOOR'];
  if (floor === undefined) return 0;
  if (!/^\d{1,12}$/.test(floor)) throw new RangeError('KB_TIME_FLOOR is not a Unix time in seconds');
  return Number(floor) * 1000;
}

const wait = (ms: number): Promise<void> => new Promise<void>((resolve) => void systemScheduler.after(ms, resolve));

async function main(mode: string | undefined, env: NodeJS.ProcessEnv): Promise<number> {
  const tty = absolute(env['KB_TTY'], '/dev/tty1');
  try {
    if (mode !== 'join' && mode !== 'ready') throw new RangeError('kb-join needs a mode: join, ready or --self-check');
    const domain = readDomain(env);
    const stateDir = absolute(env['KB_STATE_DIR'], '/var/lib/keybox');
    const factsFile = join(stateDir, 'bootstrap-facts.json');
    if (mode === 'ready') {
      const port = HTTPS_PORT;
      return await runReady({
        env, clock: systemClock, wait, tty, factsFile, domain,
        tlsOk: () => tlsCheck(domain, port),
        meminfoFile: '/proc/meminfo',
        uptimeMs: () => uptime() * 1000,
        socketBornMs: (path) => (existsSync(path) ? statSync(path).birthtimeMs : Number.NaN),
        coreSocket: absolute(env['KB_CORE_SOCKET'], '/run/keybox/http.sock'),
        relaySocket: absolute(env['KB_RELAY_SOCKET'], '/run/keyrelay/http.sock'),
      });
    }
    return await runJoin({
      env, clock: systemClock, wait, tty, factsFile, domain,
      trustFile: absolute(env['KB_TRUST_FILE'], '/etc/keybox/trust.json'),
      installDir: absolute(env['KB_INSTALL_RESULTS'], '/var/lib/keybox-install'),
      timeFloorMs: readFloorMs(env),
    });
  } catch (e) {
    appendFileSync(tty, `${LINE_START}kb-join stopped: ${e instanceof Error ? e.message : 'unknown error'}\n`);
    return 2;
  }
}

if (import.meta.main) process.exitCode = process.argv[2] === SELF_CHECK ? 0 : await main(process.argv[2], process.env);
