// A running core with a share writer over a synthetic store: the store is a list the test edits (a fake of the ShareSource port),
// everything else is the real thing (meta.db, vault, event log, the control routes with GET /api/share).
import { join } from 'node:path';
import type { TestContext } from 'node:test';
import type { ShareSource } from '../../src/ports/share.ts';
import { toShareKey } from '../kit/share-golden.ts';
import type { FakeKey } from '../kit/share-store.ts';
import { seededRandom, startCore } from '../kit/index.ts';
import type { RunningCore } from '../kit/index.ts';
import { createShareWriter, shareRoute } from '../../src/shell/share-writer.ts';
import type { ShareMeta, ShareWriter } from '../../src/shell/share-writer.ts';

export interface ShareWorld {
  readonly core: RunningCore;
  readonly writer: ShareWriter;
  /** The store the source reads: edit it, then make a `key.changed` for an admin or master key. */
  readonly store: FakeKey[];
  /** The codes of the `share.refresh_failed` rows the writer wrote to the audit log. */
  failures(): string[];
  /** How many times the writer read the store. */
  reads(): number;
  /** The next read of the store throws (a source that is down). */
  failNextReads(count: number): void;
  readonly shareDir: string;
}

export interface ShareWorldOptions {
  readonly store?: readonly FakeKey[];
  /** Reuse a state directory: a second world on the files of a first. */
  readonly stateDir?: string;
  /** Replaces the meta port the writer sees (a fault injected through the port). */
  readonly meta?: (real: ShareMeta) => ShareMeta;
  readonly seed?: number;
  /** Do not call `writer.start()`. */
  readonly noStart?: boolean;
  /** Replaces the fake store with a source made over the running core (the real metadata and vault). */
  readonly source?: (core: RunningCore) => ShareSource;
  /** The share directory, when it is not under the state directory (a database restored beside an old share directory). */
  readonly shareDir?: string;
}

export async function shareWorld(t: TestContext, options: ShareWorldOptions = {}): Promise<ShareWorld> {
  const holder: { writer?: ShareWriter } = {};
  const core = await startCore(t, {
    ...(options.stateDir === undefined ? {} : { stateDir: options.stateDir }),
    extraRoutes: [
      shareRoute({
        serve: () => {
          if (holder.writer === undefined) throw new Error('the writer is not made yet');
          return holder.writer.serve();
        },
      }),
    ],
  });
  const store = [...(options.store ?? [])];
  let reads = 0;
  let failing = 0;
  const fake: ShareSource = {
    keys: () => {
      reads += 1;
      if (failing > 0) {
        failing -= 1;
        return Promise.reject(new Error('the store is not readable'));
      }
      return Promise.resolve(store.map(toShareKey));
    },
  };
  const shareDir = options.shareDir ?? join(core.stateDir, 'share');
  const writer = createShareWriter({
    dir: shareDir,
    meta: options.meta === undefined ? core.meta : options.meta(core.meta),
    signingKey: core.share.signingKey,
    source: options.source === undefined ? fake : options.source(core),
    events: core.events,
    hub: core.hub,
    clock: core.clock,
    scheduler: core.clock,
    random: seededRandom(options.seed ?? 21),
    audit: core.audit,
  });
  holder.writer = writer;
  t.after(() => writer.stop());
  if (options.noStart !== true) await writer.start();
  const failures = (): string[] => core.audit.read(0).entries.filter((r) => r.action === 'share.refresh_failed').map((r) => String(r.detail['code']));
  return { core, writer, store, failures, reads: () => reads, failNextReads: (count) => void (failing = count), shareDir };
}
