// KBOX-33: the share writer. At start and on every `key.changed` of an admin or master key it reads the store, builds the share
// file (src/pure/share-build.ts), signs it with a key of its own (a master value in the key store), writes it durably (temp
// file, fsync, rename, fsync of the directory), and only then announces the version (one `share.version` event). A version is never
// reused and never lower: it is above the database's last, and a file already on disk counts only when this box signed it (a file
// signed by this box holds a version the database may not know yet, which the writer announces first). A file the box cannot
// refresh is served as stale (503), not as an old file that lacks a new generation: the file is fresh again only when no refresh is
// still queued, and a refresh that failed is tried again on the injected scheduler, with no limit on tries.
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import type { Audit } from '../ports/audit.ts';
import type { Clock, Scheduler } from '../ports/clock.ts';
import type { EventLog, EventSignal } from '../ports/events.ts';
import type { MetaStore } from '../ports/meta.ts';
import type { Random } from '../ports/random.ts';
import type { ShareSigningKey, ShareSource } from '../ports/share.ts';
import { ApiError, ShareError, osErrorCode } from '../pure/errors.ts';
import type { FileSummary } from '../pure/share-build.ts';
import { buildShare, sealEnvelope, summaryOf } from '../pure/share-build.ts';
import { route } from './http.ts';
import type { Route } from './http.ts';

const SEED_BYTES = 32;
const FILE_NAME = 'share.json';
const TEMP_NAME = '.share.json.tmp';

/** A failed refresh is tried again after this long, then after twice as long, up to the cap. There is no limit on tries. */
const RETRY_FIRST_MS = 10_000;
const RETRY_MAX_MS = 600_000;

const PKCS8_ED25519_SEED =Buffer.from('302e020100300506032b657004220420', 'hex');

export interface ShareSigner {
  /** The raw 32-byte public key, base64. */
  readonly publicKeyB64: string;
  sign(bytes: Uint8Array): Uint8Array;
  verify(bytes: Uint8Array, signature: Uint8Array): boolean;
}

/** An Ed25519 signer over a 32-byte seed. */
export function shareSigner(seed: Uint8Array): ShareSigner {
  const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_SEED, Buffer.from(seed)]), format: 'der', type: 'pkcs8' });
  const publicKey = createPublicKey(privateKey);
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  return {
    publicKeyB64: Buffer.from(spki.subarray(spki.length - 32)).toString('base64'),
    sign: (bytes) => sign(null, Buffer.from(bytes), privateKey),
    verify: (bytes, signature) => verify(null, Buffer.from(bytes), publicKey, Buffer.from(signature)),
  };
}

/** The part of the metadata port the writer uses. */
export type ShareMeta = Pick<MetaStore, 'snapshot' | 'shareState' | 'setSharePublicKey' | 'announceShare'>;

export interface ShareWriterDeps {
  /** Where `share.json` lives. */
  readonly dir: string;
  readonly meta: ShareMeta;
  /** The writer's own Ed25519 seed: made at the first start, reused after. */
  readonly signingKey: ShareSigningKey;
  readonly source: ShareSource;
  readonly events: EventLog;
  readonly hub: EventSignal;
  readonly clock: Clock;
  /** Times the retries of a failed refresh. */
  readonly scheduler: Scheduler;
  readonly random: Random;
  /** A failed refresh in the background is reported here as `share.refresh_failed` with a fixed code. */
  readonly audit: Audit;
}

export interface ShareFile {
  readonly version: number;
  readonly bytes: Uint8Array;
}

export interface ShareWriter {
  /** Makes the signing key if there is none, writes the first file, and starts following `key.changed`. Rejects with a fixed error. */
  start(): Promise<void>;
  /** One refresh, after any already running. `written` when a new version went out. */
  refresh(): Promise<'written' | 'unchanged'>;
  /** Resolves when every refresh asked for so far has finished. */
  idle(): Promise<void>;
  /** The file to serve; refuses (503) when there is none or when it is known to be behind the store. */
  serve(): ShareFile;
  stop(): void;
}

function writeAll(fd: number, bytes: Uint8Array): void {
  let done = 0;
  while (done < bytes.length) done += writeSync(fd, bytes, done);
}

/** A failure to clean up after a failed write must not replace the fixed error, so it reports as a result. */
function tryRemove(path: string): boolean {
  try {
    rmSync(path, { force: true });
    return true;
  } catch {
    return false;
  }
}

/** Temp file, fsync, rename, fsync of the directory: a crash leaves the old file or the new one. */
function writeDurably(dir: string, bytes: Uint8Array): void {
  const temp = join(dir, TEMP_NAME);
  try {
    mkdirSync(dir, { recursive: true });
    rmSync(temp, { force: true });
    const fd = openSync(temp, 'wx', 0o644);
    try {
      writeAll(fd, bytes);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(temp, join(dir, FILE_NAME));
    const dirFd = openSync(dir, 'r');
    try {
      fsyncSync(dirFd);
    } finally {
      closeSync(dirFd);
    }
  } catch {
    tryRemove(temp);
    throw new ShareError('write_failed');
  }
}

/** The file on disk, or null when there is none; a read failure other than "none" is a fixed error. */
function readFileIfAny(dir: string): Buffer | null {
  try {
    return readFileSync(join(dir, FILE_NAME));
  } catch (error) {
    if (osErrorCode(error) === 'ENOENT') return null;
    throw new ShareError('write_failed');
  }
}

export function createShareWriter(deps: ShareWriterDeps): ShareWriter {
  let signer: ShareSigner | undefined;
  let current: ShareFile | undefined;
  let stale = false;
  let tail: Promise<unknown> = Promise.resolve();
  /** Refreshes asked for and not yet finished, the one running included. */
  let outstanding = 0;
  let failedTries = 0;
  let stopped = false;
  let cancelRetry: (() => void) | undefined;
  let stopListening: (() => void) | undefined;

  async function loadSigner(): Promise<ShareSigner> {
    let seed = await deps.signingKey.read();
    if (seed === null) {
      seed = deps.random.bytes(SEED_BYTES);
      deps.signingKey.create(seed);
    }
    if (seed.length !== SEED_BYTES) throw new ShareError('signing_key_unreadable');
    const made = shareSigner(seed);
    seed.fill(0);
    const published = deps.meta.shareState().publicKeyB64;
    if (published !== null && published !== made.publicKeyB64) throw new ShareError('signing_key_mismatch');
    if (published === null) deps.meta.setSharePublicKey(made.publicKeyB64);
    return made;
  }

  async function attempt(): Promise<'written' | 'unchanged'> {
    signer ??= await loadSigner();
    const keys = await deps.source.keys();
    const raw = readFileIfAny(deps.dir);
    const summary = raw === null ? undefined : summaryOf(raw);
    // A file on disk counts only when this box signed it; a file it did not sign sets nothing, not even a floor under the version.
    const known: { readonly raw: Buffer; readonly summary: FileSummary } | undefined = raw !== null && summary !== undefined && signer.verify(summary.body, summary.signature) ? { raw, summary } : undefined;
    let announced = deps.meta.shareState().version;
    if (known !== undefined && known.summary.version > announced) {
      // The file is durable and already served; a crash (or a restored database) kept its version from being announced.
      deps.meta.announceShare(known.summary.version);
      announced = known.summary.version;
    }
    const version = announced + 1;
    const built = buildShare({ version, issuedAt: deps.clock.now(), random: deps.random, keys });
    // A file below the announced version is never reused: a reader may have seen the higher one, and would take this for a rollback.
    if (known !== undefined && known.summary.version === announced && known.summary.contentKey === built.contentKey) {
      current = { version: known.summary.version, bytes: known.raw };
      return 'unchanged';
    }
    const envelope = sealEnvelope(built.bytes, signer.sign(built.bytes));
    writeDurably(deps.dir, envelope);
    deps.meta.announceShare(version);
    current = { version, bytes: envelope };
    return 'written';
  }

  function retryLater(): void {
    if (stopped) return;
    cancelRetry?.();
    const delay = Math.min(RETRY_FIRST_MS * 2 ** failedTries, RETRY_MAX_MS);
    failedTries += 1;
    cancelRetry = deps.scheduler.after(delay, () => {
      cancelRetry = undefined;
      inBackground();
    });
  }

  function worked(): void {
    failedTries = 0;
    cancelRetry?.();
    cancelRetry = undefined;
    // A refresh still queued was asked for by a change this one may not have read: the file stays stale until it has run.
    if (outstanding === 1) stale = false;
  }

  /** Runs after every refresh already asked for; a failure is a fixed error and leaves the file marked stale. */
  function enqueue(): Promise<'written' | 'unchanged'> {
    outstanding += 1;
    const run = async (): Promise<'written' | 'unchanged'> => {
      try {
        const result = await attempt();
        worked();
        return result;
      } catch (error) {
        stale = true;
        retryLater();
        throw error instanceof ShareError ? error : new ShareError('refresh_failed');
      } finally {
        outstanding -= 1;
      }
    };
    const result = tail.then(run);
    tail = result.catch((error: unknown) => (error instanceof ShareError ? error.failure : 'refresh_failed'));
    return result;
  }

  /** A refresh nobody awaits: its failure is written to the audit log, never lost. */
  function inBackground(): void {
    void enqueue().catch((error: unknown) => {
      deps.audit.append({ action: 'share.refresh_failed', subject: 'share', at: deps.clock.now(), detail: { code: error instanceof ShareError ? error.failure : 'refresh_failed' } });
    });
  }

  function follow(): void {
    let cursor = deps.events.head();
    stopListening = deps.hub.subscribe(() => {
      const rows = deps.events.after(cursor);
      const last = rows[rows.length - 1];
      if (last === undefined) return;
      cursor = last.seq;
      const changed = rows.filter((r) => r.kind === 'key.changed');
      if (changed.length === 0) return;
      const classes = new Map(deps.meta.snapshot().keys.map((k) => [k.keyref, k.class]));
      // A key the box no longer lists may have been an admin key: look.
      const watched = changed.some((r) => {
        const keyClass = classes.get(String(r.data['keyref']));
        return keyClass === undefined || keyClass === 'admin' || keyClass === 'master';
      });
      if (!watched) return;
      stale = true;
      inBackground();
    });
  }

  return {
    async start() {
      follow();
      await enqueue();
    },
    refresh: enqueue,
    idle: async () => {
      await tail;
    },
    serve() {
      if (current === undefined) throw new ApiError('unavailable', 'share_missing');
      if (stale) throw new ApiError('unavailable', 'share_stale');
      return current;
    },
    stop() {
      stopped = true;
      cancelRetry?.();
      cancelRetry = undefined;
      stopListening?.();
      stopListening = undefined;
    },
  };
}

/** GET /api/share (scope control): the current envelope byte for byte, with the version in a header. */
export function shareRoute(writer: Pick<ShareWriter, 'serve'>): Route {
  return route({
    method: 'GET',
    path: '/api/share',
    surface: 'api',
    scope: 'control',
    handle: () => {
      const file = writer.serve();
      return { raw: { type: 'application/json; charset=utf-8', bytes: file.bytes }, headers: { 'KB-Share-Version': String(file.version) } };
    },
  });
}
