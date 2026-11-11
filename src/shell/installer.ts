// KBOX-6: what kb-install (root) does with the requests core leaves in staging. Every run reads and unlinks every
// `*.request` entry of any type, answers each in the root-owned results directory, and:
//   install: refuses unless `current` is the base the approval names and H is not that base; verifies the owner's approval
//     itself against the root copy of the approvers; reads the staged tree through held descriptors (safe-open.ts) under the
//     re-applied limits and name rules and a 60 s deadline; takes H from the bytes it read; checks every pinned binary;
//     writes exactly those bytes into a root-owned release, switches `current`, restarts and rolls back a failed health check.
//   trust: changes /etc/keybox/trust.json only on a proof by an approver in it (approver_add, approver_remove; each approval
//     works once) or on a setup or recovery code root itself checks. An install approval works once too.
// Nothing here reads core's approver table, and nothing is written outside releases/, current, trust.json and the results
// directory; in staging it only removes. A `<name>.settled` marker core leaves once it has read an answer makes the next
// run remove that `<name>.result`.
import { closeSync, constants, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, realpathSync, renameSync, rmSync, symlinkSync, writeSync, fchmodSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { basename, dirname, join } from 'node:path';
import type { Clock } from '../ports/clock.ts';
import type { TrustApprover } from '../ports/trust.ts';
import { parseRootRequest, REQUEST_LIMIT, REQUEST_NAME } from '../pure/install-request.ts';
import type { InstallRefusal, InstallRequest, RootResult, TrustRefusal } from '../pure/install-request.ts';
import { approverKeys, keptProofHolds } from '../pure/kept-proof.ts';
import type { TrustCopy } from '../pure/kept-proof.ts';
import { RELEASE_HASH, RELEASE_LIMITS, checkSegment, fileSha256, releaseHash } from '../pure/release-hash.ts';
import { parseRuntimeLock } from '../pure/runtime-lock.ts';
import { DOMAIN_NAME, approverAddOf } from '../pure/actions.ts';
import { decodeJsonBody } from '../pure/schemas.ts';
import { createCodeRoot, readBootId } from './console.ts';
import { closeFd, listAt, openAt, openDirectory, readThrough, trashIn } from './safe-open.ts';
import type { Trash } from './safe-open.ts';

export interface InstallPaths {
  /** `/var/lib/keybox/staging`: core's, so nothing in it is trusted. */
  readonly staging: string;
  /** `/opt/keybox/releases`. */
  readonly releases: string;
  /** `/opt/keybox/current`, a link to `releases/<H>`. */
  readonly current: string;
  /** `/etc/keybox/trust.json`. */
  readonly trustFile: string;
  /** `/etc/keybox/codes` (root 0700). */
  readonly codesDir: string;
  /** `/var/lib/keybox-install` (root 0755): the results, and the spent trust approvals. */
  readonly results: string;
  /** `/proc/sys/kernel/random/boot_id`. */
  readonly bootIdFile: string;
}

/** The three long-running units, as kb-install sees them. Each call is bounded by `until` (clock ms), which kb-install
 * takes from the time its run has left. */
export interface ReleaseUnits {
  restart(until: number): Promise<void>;
  /** True when both processes answer `GET /healthz` with this release within 60 s of the restart and before `until`. */
  healthCheck(release: string, until: number): Promise<boolean>;
  /** True when the kb-install of the release in `releaseDir` loads every module it imports and exits 0 in its no-op
   * `--self-check` mode before `until`: a release whose root installer cannot start must never stay current. */
  selfCheck(releaseDir: string, until: number): Promise<boolean>;
}

/** Test seams between the steps of the safe copy, after it and after the switch. Production passes none. */
export interface InstallHooks {
  readonly afterList?: (rel: string) => void;
  readonly afterOpen?: (rel: string) => void;
  readonly afterRead?: (rel: string) => void;
  readonly afterWrite?: (rel: string) => void;
  readonly afterCopy?: () => void;
  readonly afterSwitch?: () => void;
}

export interface InstallerDeps {
  readonly paths: InstallPaths;
  readonly units: ReleaseUnits;
  readonly clock: Clock;
  readonly wordlist: readonly string[];
  readonly hooks?: InstallHooks;
  /** The domain the box was made for (KB_DOMAIN); setup for any other, or with none configured, is refused `domain`. */
  readonly domain: string | undefined;
  /** A fixed code for the journal when a request fails in a way no refusal code names. */
  readonly journal?: (code: string) => void;
}

export const COPY_DEADLINE_MS = 60_000;
/** kb-install.service has TimeoutStartSec=120s; a run plans to end 10 s before it (Node's start, the result files), so
 * systemd never has to kill it. Every phase below is bounded by the time this leaves. */
export const RUN_BUDGET_MS = 110_000;
/** One `systemctl restart` of the three units, at most. The last this much of a run is the rollback's restart's alone:
 * no earlier phase is given time that reaches into it. */
export const RESTART_WITHIN_MS = 15_000;
/** The new release's kb-install self-check, at most. */
const SELF_CHECK_WITHIN_MS = 10_000;
/** The least time worth a health check. */
const MIN_HEALTH_MS = 10_000;
/** A copy (its reads, hashes and writes) ends early enough to leave a restart, a self-check, a health check and a rollback
 * restart inside the run. */
const AFTER_COPY_MS = 2 * RESTART_WITHIN_MS + SELF_CHECK_WITHIN_MS + MIN_HEALTH_MS;
/** A pinned binary is read into memory to be hashed; Node's and Caddy's builds are well under this. */
const BINARY_LIMIT = 256 * 1024 * 1024;

class Refusal extends Error {
  readonly code: InstallRefusal;
  constructor(code: InstallRefusal) {
    super(code);
    this.code = code;
  }
}

interface CopiedFile {
  readonly path: string;
  readonly executable: boolean;
  readonly bytes: Uint8Array;
  /** Of `bytes`, taken as they are read, inside the copy's deadline. */
  readonly sha256: string;
}
interface Copy {
  readonly dirs: readonly string[];
  readonly files: readonly CopiedFile[];
}

const keyBytes = (b64: string): Uint8Array => Uint8Array.from(Buffer.from(b64, 'base64url'));

const REQUEST_SUFFIX = Buffer.from('.request');
const SETTLED_SUFFIX = Buffer.from('.settled');
const endsWith = (name: Buffer, suffix: Buffer): boolean => name.length > suffix.length && name.subarray(name.length - suffix.length).equals(suffix);

export async function runInstaller(deps: InstallerDeps): Promise<readonly { readonly name: string; readonly result: RootResult }[]> {
  const { paths } = deps;
  const hooks = deps.hooks ?? {};
  const runDeadline = deps.clock.now() + RUN_BUDGET_MS;
  const noCodes = (): never => {
    throw new Error('kb-install checks codes and never makes one');
  };
  const codes = createCodeRoot({ dir: paths.codesDir, sink: noCodes, random: { bytes: noCodes }, clock: deps.clock, wordlist: deps.wordlist });

  // --- results, trust.json and the running release ------------------------------------------------------------------
  const writeResult = (name: string, result: RootResult): void => {
    const file = join(paths.results, `${name}.result`);
    rmSync(file, { force: true });
    const fd = openSync(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o644);
    try {
      writeSync(fd, result);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  };

  const readTrust = (): TrustCopy | undefined => {
    if (!existsSync(paths.trustFile)) return undefined;
    const decoded = decodeJsonBody(readFileSync(paths.trustFile));
    if (!decoded.ok || typeof decoded.value !== 'object' || decoded.value === null) throw new Error('trust.json does not parse');
    const v = decoded.value as { domain?: unknown; approvers?: unknown };
    if (typeof v.domain !== 'string' || !DOMAIN_NAME.test(v.domain) || !Array.isArray(v.approvers)) throw new Error('trust.json does not parse');
    return { domain: v.domain, approvers: v.approvers as TrustApprover[] };
  };

  const writeTrust = (copy: TrustCopy): void => {
    const temp = `${paths.trustFile}.tmp`;
    rmSync(temp, { force: true });
    const fd = openSync(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o644);
    try {
      fchmodSync(fd, 0o644);
      writeSync(fd, JSON.stringify({ domain: copy.domain, approvers: copy.approvers }));
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(temp, paths.trustFile);
  };

  // Every approval id root acted on (install and trust alike): each approval works once.
  const spentFile = join(paths.results, 'trust-spent');
  const spent = (approvalId: string): boolean => existsSync(spentFile) && readFileSync(spentFile, 'utf8').split('\n').includes(approvalId);
  const spend = (approvalId: string): void => {
    const fd = openSync(spentFile, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW, 0o644);
    try {
      writeSync(fd, `${approvalId}\n`);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  };

  /** The release `current` names, or undefined when it names none (it never leaves releases/ through kb-install). */
  const currentRelease = (): string | undefined => {
    if (!existsSync(paths.current)) return undefined;
    const target = realpathSync(paths.current);
    return dirname(target) === realpathSync(paths.releases) && RELEASE_HASH.test(basename(target)) ? basename(target) : undefined;
  };

  /** H0: `current` resolves to `releases/<H0>`, or kb-install refuses to act. */
  const runningRelease = (): string => {
    const h0 = currentRelease();
    if (h0 === undefined) throw new Error('current is not a release');
    return h0;
  };

  const switchCurrent = (h: string): void => {
    const temp = `${paths.current}.tmp`;
    rmSync(temp, { force: true });
    symlinkSync(join(paths.releases, h), temp);
    renameSync(temp, paths.current);
  };

  // --- the safe copy ------------------------------------------------------------------------------------------------
  const copyTree = (stagingFd: number, h: string, deadline: number): Copy => {
    const top = openAt(stagingFd, h);
    if (top.kind !== 'dir') {
      if (top.kind === 'file') closeFd(top.fd);
      throw new Refusal('not_regular');
    }
    const dirs: string[] = [];
    const files: CopiedFile[] = [];
    let total = 0;
    let entries = 0;
    const walk = (dirFd: number, prefix: string): void => {
      for (const name of listAt(dirFd)) {
        const segment = checkSegment(name);
        const rel = segment === undefined ? undefined : prefix === '' ? segment : `${prefix}/${segment}`;
        if (rel === undefined || Buffer.byteLength(rel) > RELEASE_LIMITS.pathBytes) throw new Refusal('not_regular');
        entries += 1;
        if (entries > RELEASE_LIMITS.entries) throw new Refusal('size');
        hooks.afterList?.(rel);
        const opened = openAt(dirFd, name);
        if (opened.kind === 'refused') throw new Refusal('not_regular');
        try {
          hooks.afterOpen?.(rel);
          if (opened.kind === 'dir') {
            dirs.push(rel);
            walk(opened.fd, rel);
          } else {
            const read = readThrough(opened.fd, opened.size, RELEASE_LIMITS.totalBytes - total);
            if (!read.ok) throw new Refusal('size');
            total += read.bytes.length;
            hooks.afterRead?.(rel);
            files.push({ path: rel, executable: opened.executable, bytes: read.bytes, sha256: fileSha256(read.bytes) });
          }
        } finally {
          closeFd(opened.fd);
        }
        if (deps.clock.now() > deadline) throw new Refusal('timeout');
      }
    };
    try {
      walk(top.fd, '');
    } finally {
      closeFd(top.fd);
    }
    return { dirs, files };
  };

  /** Each pinned binary: unchanged ones from the running release, new ones from `<H>.bin`, both read and hashed. */
  const checkBinaries = (stagingFd: number, h: string, h0: string, copy: Copy, deadline: number): readonly CopiedFile[] => {
    const lockFile = copy.files.find((f) => f.path === 'runtime.lock');
    const lock = lockFile === undefined ? undefined : parseRuntimeLock(Buffer.from(lockFile.bytes).toString('utf8'));
    if (lock === undefined || copy.dirs.includes('bin') || copy.files.some((f) => f.path === 'bin')) throw new Refusal('lock');
    const runningLockPath = join(paths.releases, h0, 'runtime.lock');
    const running = existsSync(runningLockPath) ? parseRuntimeLock(readFileSync(runningLockPath, 'utf8')) : undefined;
    const out: CopiedFile[] = [];
    for (const pin of lock) {
      const unchanged = running?.some((b) => b.name === pin.name && b.sha256 === pin.sha256) === true;
      const holder = unchanged ? openDirectory(join(paths.releases, h0)) : stagingFd;
      try {
        const dir = openAt(holder, unchanged ? 'bin' : `${h}.bin`);
        if (dir.kind !== 'dir') {
          if (dir.kind === 'file') closeFd(dir.fd);
          throw new Refusal('lock');
        }
        try {
          const bin = openAt(dir.fd, pin.name);
          if (bin.kind !== 'file') {
            if (bin.kind === 'dir') closeFd(bin.fd);
            throw new Refusal('lock');
          }
          try {
            const read = readThrough(bin.fd, bin.size, BINARY_LIMIT);
            if (!read.ok) throw new Refusal('size');
            const sha256 = fileSha256(read.bytes);
            if (sha256 !== pin.sha256) throw new Refusal('lock');
            out.push({ path: `bin/${pin.name}`, executable: true, bytes: read.bytes, sha256 });
          } finally {
            closeFd(bin.fd);
          }
        } finally {
          closeFd(dir.fd);
        }
      } finally {
        if (holder !== stagingFd) closeFd(holder);
      }
      if (deps.clock.now() > deadline) throw new Refusal('timeout');
    }
    return out;
  };

  /** Writes exactly the bytes read into a root-owned tree: directories 0755, files 0644 or 0755. Each written file is
   * inside the copy's deadline, or the copy is refused `timeout`. */
  const writeRelease = (target: string, copy: Copy, binaries: readonly CopiedFile[], deadline: number): void => {
    mkdirSync(target, { mode: 0o755 });
    for (const dir of ['bin', ...[...copy.dirs].sort()]) mkdirSync(join(target, dir), { mode: 0o755 });
    for (const file of [...copy.files, ...binaries]) {
      const mode = file.executable ? 0o755 : 0o644;
      const fd = openSync(join(target, file.path), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, mode);
      try {
        fchmodSync(fd, mode);
        writeSync(fd, file.bytes);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      hooks.afterWrite?.(file.path);
      if (deps.clock.now() > deadline) throw new Refusal('timeout');
    }
  };

  // --- the switching record: a kill mid-install is rolled back by the next run or boot ------------------------------
  // `switching <H> from <base>` is written (temp file and rename) before the copy, so before the switch, and removed only
  // once the install is over either way. A run that finds it was killed in between: it puts `current` back on the base,
  // restarts the units unless releases/<H> was never made (then nothing ever ran from H), removes H and answers
  // `failed:interrupted`.
  const switchingFile = join(paths.results, 'switching');
  const writeSwitching = (h: string, base: string): void => {
    const temp = `${switchingFile}.tmp`;
    rmSync(temp, { force: true });
    const fd = openSync(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o644);
    try {
      writeSync(fd, `switching ${h} from ${base}\n`);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(temp, switchingFile);
  };
  const clearSwitching = (): void => rmSync(switchingFile, { force: true });

  /** A restart that cannot be made in time is journalled: `current` is already where it must be, nothing else is left to do. */
  const restartBy = (until: number): Promise<void> => deps.units.restart(until).catch(() => deps.journal?.('restart_failed'));

  /** A record root cannot act on (torn, its base gone, or not matching `current`) is set aside unchanged for a later look,
   * `current` is left as it is and a fixed code is journalled: the run goes on to serve requests, never wedged by it. */
  const setAside = (): void => {
    renameSync(switchingFile, join(paths.results, `switching.bad-${deps.clock.now()}`));
    deps.journal?.('switching_bad');
  };

  const recoverInterrupted = async (): Promise<void> => {
    if (!existsSync(switchingFile)) return;
    const record = /^switching ([0-9a-f]{64}) from ([0-9a-f]{64})\n$/.exec(readFileSync(switchingFile, 'utf8'));
    const h = record?.[1];
    const base = record?.[2];
    if (h === undefined || base === undefined || h === base || !existsSync(join(paths.releases, base))) return setAside();
    const running = currentRelease();
    // The record is written before the copy and removed after: current is its base, its H, or (never made) absent.
    if (existsSync(paths.current) && running !== base && running !== h) return setAside();
    const release = join(paths.releases, h);
    const ranFromH = existsSync(release);
    if (running !== base) switchCurrent(base);
    if (ranFromH) await restartBy(Math.min(deps.clock.now() + RESTART_WITHIN_MS, runDeadline));
    rmSync(`${release}.tmp`, { recursive: true, force: true });
    rmSync(release, { recursive: true, force: true });
    writeResult(h, 'failed:interrupted');
    clearSwitching();
  };

  const install = async (stagingFd: number, req: InstallRequest): Promise<RootResult> => {
    const h0 = runningRelease();
    if (req.base !== h0) return 'refused:base';
    if (req.install === h0) return 'refused:already_current';
    const trust = readTrust();
    const action = { kind: 'install_update', install: req.install, commit: req.commit, base: req.base };
    if (trust === undefined || !keptProofHolds(trust, req.approval, action)) return 'refused:bad_proof';
    if (spent(req.approval.approval_id)) return 'refused:spent';
    const h = req.install;
    const temp = join(paths.releases, `${h}.tmp`);
    const release = join(paths.releases, h);
    rmSync(temp, { recursive: true, force: true });
    rmSync(release, { recursive: true, force: true }); // never current: h is not h0
    const deadline = Math.min(deps.clock.now() + COPY_DEADLINE_MS, runDeadline - AFTER_COPY_MS);
    if (deps.clock.now() >= deadline) return 'refused:timeout';
    writeSwitching(h, h0);
    try {
      const copy = copyTree(stagingFd, h, deadline);
      if (releaseHash(copy.files) !== h) throw new Refusal('hash');
      writeRelease(temp, copy, checkBinaries(stagingFd, h, h0, copy, deadline), deadline);
    } catch (error) {
      rmSync(temp, { recursive: true, force: true });
      clearSwitching();
      if (error instanceof Refusal) return `refused:${error.code}`;
      throw error;
    }
    hooks.afterCopy?.();
    renameSync(temp, release);
    // Spent before the switch: an approval that ever reached `current` never installs again, whatever follows.
    spend(req.approval.approval_id);
    switchCurrent(h);
    hooks.afterSwitch?.();
    // Every phase before a rollback ends by `rollbackAt`, so the rollback's restart always has its RESTART_WITHIN_MS.
    const rollbackAt = runDeadline - RESTART_WITHIN_MS;
    const within = (ms: number): number => Math.min(deps.clock.now() + ms, rollbackAt);
    const healthy = await deps.units
      .restart(within(RESTART_WITHIN_MS))
      .then(() => deps.units.selfCheck(release, within(SELF_CHECK_WITHIN_MS)))
      .then((loads) => loads && deps.units.healthCheck(h, rollbackAt))
      .catch(() => false);
    if (!healthy) {
      switchCurrent(h0);
      await restartBy(runDeadline);
      rmSync(release, { recursive: true, force: true });
    }
    clearSwitching();
    return healthy ? 'installed' : 'rolled_back';
  };

  // --- trust changes --------------------------------------------------------------------------------------------------
  const trustChange = (req: Exclude<ReturnType<typeof parseRootRequest>, { ok: false }>['request']): `refused:${TrustRefusal}` | 'applied' => {
    if (req.kind !== 'trust') return 'refused:bad_request';
    // Past its deadline core has answered `timeout`; applying it now would leave core's table and trust.json apart.
    if (req.deadline !== undefined && deps.clock.now() > req.deadline) return 'refused:late';
    const current = readTrust();
    const keysDecode = (list: readonly TrustApprover[]): boolean => list.every((a) => approverKeys(a) !== undefined);
    switch (req.change) {
      case 'setup':
      case 'recovery': {
        const check = codes.check(req.change, req.code, { bootId: readBootId(paths.bootIdFile), trustExists: current !== undefined });
        if (!check.ok) return `refused:${check.code}`;
        if (req.change === 'recovery' && current === undefined) return 'refused:no_trust';
        if (!keysDecode(req.approvers)) return 'refused:bad_request';
        if (req.change === 'setup' && req.domain !== deps.domain) return 'refused:domain';
        // Spent before the write: a write that fails or a kill after it never leaves the code usable again.
        codes.consume(req.change);
        writeTrust({ domain: req.change === 'setup' ? req.domain : (current?.domain ?? ''), approvers: req.approvers });
        return 'applied';
      }
      case 'approver_add':
      case 'approver_remove': {
        if (current === undefined) return 'refused:no_trust';
        if (spent(req.approval.approval_id)) return 'refused:spent';
        if (req.change === 'approver_add' && (!keysDecode([req.approver]) || current.approvers.some((a) => a.id === req.approver.id))) return 'refused:bad_request';
        // The signed approver_add names the keys by hash, rebuilt here from the keys presented: other keys, other digest.
        const action = req.change === 'approver_add' ? approverAddOf(keyBytes(req.approver.cose_b64), keyBytes(req.approver.device_pub_b64)) : { kind: 'approver_remove', approver_id: req.approver_id };
        if (!keptProofHolds(current, req.approval, action)) return 'refused:bad_proof';
        if (req.change === 'approver_remove') {
          if (!current.approvers.some((a) => a.id === req.approver_id)) return 'refused:unknown_approver';
          if (current.approvers.length <= 1) return 'refused:last_approver';
        }
        spend(req.approval.approval_id);
        const approvers = req.change === 'approver_add' ? [...current.approvers, req.approver] : current.approvers.filter((a) => a.id !== req.approver_id);
        writeTrust({ domain: current.domain, approvers });
        return 'applied';
      }
    }
  };

  // --- one request ----------------------------------------------------------------------------------------------------
  /** Reads a request through the safe open (at most 64 KiB) and moves the entry out of staging at once, whatever it is:
   * into the trash, which the run empties last, so not even a planted tree too deep to remove in one run keeps the path
   * unit triggered. */
  const takeRequest = (stagingFd: number, trash: Trash, name: Buffer): { readonly ok: true; readonly bytes: Uint8Array } | { readonly ok: false; readonly code: 'not_regular' | 'size' } => {
    const opened = openAt(stagingFd, name);
    if (opened.kind !== 'file') {
      if (opened.kind === 'dir') closeFd(opened.fd);
      trash.discard(name);
      return { ok: false, code: 'not_regular' };
    }
    try {
      const read = opened.size > REQUEST_LIMIT ? ({ ok: false } as const) : readThrough(opened.fd, opened.size, REQUEST_LIMIT);
      trash.discard(name);
      return read.ok ? read : { ok: false, code: 'size' };
    } finally {
      closeFd(opened.fd);
    }
  };

  const handle = async (stagingFd: number, trash: Trash, name: Buffer): Promise<RootResult> => {
    try {
      const taken = takeRequest(stagingFd, trash, name);
      if (!taken.ok) return `refused:${taken.code}`;
      const parsed = parseRootRequest(taken.bytes);
      if (!parsed.ok) return `refused:${parsed.code}`;
      return parsed.request.kind === 'install' ? await install(stagingFd, parsed.request) : trustChange(parsed.request);
    } catch (error) {
      deps.journal?.(error instanceof Error && 'code' in error && typeof error.code === 'string' ? error.code : 'internal');
      return 'refused:internal';
    }
  };

  await recoverInterrupted();
  const stagingFd = openDirectory(paths.staging);
  const trash = trashIn(stagingFd, randomBytes(16).toString('hex'));
  const answered: { name: string; result: RootResult }[] = [];
  try {
    // First the answers core has read (`<name>.settled`): the result and the marker go, before any new answer is written.
    for (const name of listAt(stagingFd).filter((n) => endsWith(n, SETTLED_SUFFIX))) {
      const base = name.subarray(0, name.length - SETTLED_SUFFIX.length).toString('utf8');
      if (REQUEST_NAME.test(base)) rmSync(join(paths.results, `${base}.result`), { force: true });
      trash.discard(name);
    }
    for (const name of listAt(stagingFd).filter((n) => endsWith(n, REQUEST_SUFFIX))) {
      const base = name.subarray(0, name.length - REQUEST_SUFFIX.length).toString('utf8');
      const result = await handle(stagingFd, trash, name);
      if (REQUEST_NAME.test(base)) {
        writeResult(base, result);
        answered.push({ name: base, result });
      }
    }
    // Last, once every answer is written: a tree that takes long to remove delays no answer.
    trash.empty();
  } finally {
    closeFd(stagingFd);
  }
  return answered;
}
