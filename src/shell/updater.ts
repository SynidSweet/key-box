// KBOX-6, core's half of an update. `POST /api/updates` takes the tar, computes H itself, keeps the tree in its own staging
// directory and opens one `install_update` approval {install: H, commit: C, base: H0}. On approval it checks that `current`
// is still H0 and writes `<H>.request` for kb-install with the proof the phone sent; core itself writes nothing under
// /opt/keybox. `settle` reads root's answer and emits `update.state`.
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import type { EventLog } from '../ports/events.ts';
import type { Action } from '../pure/actions.ts';
import { ApiError } from '../pure/errors.ts';
import { parseRootResult } from '../pure/install-request.ts';
import type { InstallRequest } from '../pure/install-request.ts';
import { RELEASE_HASH, RELEASE_LIMITS, fileSha256, releaseHash } from '../pure/release-hash.ts';
import { parseTar } from '../pure/tar.ts';
import type { Requester } from '../pure/slots.ts';
import type { Approvals, Executor, Proposed } from './approvals.ts';
import type { Route } from './http.ts';
import { markSettled, writeRootRequest } from './trust-installer.ts';

export const TAR_TYPE = 'application/x-tar';
/** The tar body: 20 MiB of file bytes plus a header and padding per entry and the end blocks. */
/** What core stages for an install: the tree `<H>` and the new binaries `<H>.bin`. */
const STAGED = /^([0-9a-f]{64})(?:\.bin)?$/;
const TAR_BODY_LIMIT = RELEASE_LIMITS.totalBytes + (RELEASE_LIMITS.entries + 3) * 1024;

export interface UpdaterDeps {
  /** `/var/lib/keybox/staging` (core's own). */
  readonly stagingDir: string;
  /** `/var/lib/keybox-install` (root's; core only reads). */
  readonly resultsDir: string;
  /** `/opt/keybox/current`. */
  readonly currentLink: string;
  readonly propose: (input: { readonly action: Action; readonly requester: Requester }) => Proposed;
  readonly approvals: () => Pick<Approvals, 'pending' | 'waiting' | 'executed'>;
  readonly events: Pick<EventLog, 'append'>;
}

export interface Updater {
  readonly routes: readonly Route[];
  readonly executor: Executor;
  /** H0: the release `current` points at; throws when `current` is not a release. */
  release(): string;
  /** H0, or undefined when `current` is missing or not a release (a development run). */
  running(): string | undefined;
  /** Reads root's answers to the installs it waits for; emits `update.state` and ends each approval. */
  settle(): void;
}

export function createUpdater(deps: UpdaterDeps): Updater {
  const running = (): string | undefined => {
    if (!existsSync(deps.currentLink)) return undefined;
    const target = realpathSync(deps.currentLink);
    const h0 = basename(target);
    return RELEASE_HASH.test(h0) && basename(dirname(target)) === 'releases' ? h0 : undefined;
  };
  const release = (): string => {
    const h0 = running();
    if (h0 === undefined) throw new Error('current is not a release');
    return h0;
  };

  const stage = (h: string, entries: ReturnType<typeof parseTar> & { ok: true }): void => {
    const dir = join(deps.stagingDir, h);
    rmSync(dir, { recursive: true, force: true });
    mkdirSync(dir, { recursive: true, mode: 0o750 });
    for (const e of entries.entries) {
      const path = join(dir, e.path);
      if (e.kind === 'dir') mkdirSync(path, { recursive: true, mode: 0o750 });
      else {
        mkdirSync(dirname(path), { recursive: true, mode: 0o750 });
        writeFileSync(path, e.bytes, { mode: 0o640 });
        chmodSync(path, e.executable ? 0o750 : 0o640);
      }
    }
  };

  const intakeRoute: Route = {
    method: 'POST',
    path: '/api/updates',
    surface: 'api',
    scope: 'control',
    open: false,
    takesBody: false,
    rawBody: { type: TAR_TYPE, limit: TAR_BODY_LIMIT },
    run: (input) => {
      const commit = input.query.get('commit');
      if (commit === null || !/^[0-9a-f]{40}$/.test(commit) || [...input.query.keys()].length !== 1) throw new ApiError('bad_request');
      const parsed = parseTar(input.raw ?? new Uint8Array());
      if (!parsed.ok) throw new ApiError('bad_request', parsed.code);
      const h = releaseHash(parsed.entries.flatMap((e) => (e.kind === 'file' ? [{ path: e.path, executable: e.executable, sha256: fileSha256(e.bytes) }] : [])));
      const h0 = release();
      if (h === h0) throw new ApiError('conflict', 'already_current');
      stage(h, parsed);
      const proposed = deps.propose({ action: { kind: 'install_update', install: h, commit, base: h0 }, requester: { kind: 'token', label: input.actor } });
      return { status: 201, json: { approval_id: proposed.approval_id, hash: h, base: h0 } };
    },
  };

  const executor: Executor = (approval) => {
    const action = approval.action;
    if (action.kind !== 'install_update' || approval.proof === undefined) return Promise.resolve({ result: 'failed', reason: 'wrong_kind' });
    if (release() !== action.base) return Promise.resolve({ result: 'failed', reason: 'base_moved' });
    const request: InstallRequest = { kind: 'install', install: action.install, commit: action.commit, base: action.base, approval: approval.proof };
    writeRootRequest(deps.stagingDir, action.install, request);
    deps.events.append('update.state', { approval_id: approval.approvalId, state: 'pending' });
    return Promise.resolve({ result: 'waiting' });
  };

  /** Removes every staged tree and `<H>.bin` no install proposal still needs: one is pending (the slot holds one) or
   * approved and waiting for root. Settled, denied, expired and replaced proposals leave nothing behind. */
  const prune = (): void => {
    if (!existsSync(deps.stagingDir)) return;
    const approvals = deps.approvals();
    const needed = new Set([...approvals.pending('install_update'), ...approvals.waiting('install_update')].flatMap((a) => (a.action.kind === 'install_update' ? [a.action.install] : [])));
    for (const name of readdirSync(deps.stagingDir)) {
      const h = STAGED.exec(name)?.[1];
      if (h !== undefined && !needed.has(h)) rmSync(join(deps.stagingDir, name), { recursive: true, force: true });
    }
  };

  const settle = (): void => {
    const approvals = deps.approvals();
    for (const w of approvals.waiting('install_update')) {
      if (w.action.kind !== 'install_update') continue;
      const file = join(deps.resultsDir, `${w.action.install}.result`);
      // A result older than this approval answers an earlier request for the same H (a rolled-back try).
      if (!existsSync(file) || statSync(file).mtimeMs < w.decidedAt) continue;
      const result = parseRootResult(readFileSync(file, 'utf8'));
      if (result === 'installed' || result === 'rolled_back') {
        deps.events.append('update.state', { approval_id: w.approvalId, state: result });
        approvals.executed(w.approvalId, result === 'installed' ? 'done' : 'failed', result === 'installed' ? 'ok' : 'rolled_back');
      } else if (result === 'failed:interrupted') approvals.executed(w.approvalId, 'failed', 'interrupted');
      else approvals.executed(w.approvalId, 'failed', result?.startsWith('refused:') === true ? result.slice('refused:'.length) : 'bad_result');
      markSettled(deps.stagingDir, w.action.install);
    }
    prune();
  };

  return { routes: [intakeRoute], executor, release, running, settle };
}
