// A destination that keeps what it holds, in order, and can refuse a target or fail a deploy: the rotation tests read it to see what each
// destination holds at any moment. Faults are planted through the port (it refuses), never by patching.
import type { DeployRef, Destination, DestinationKind, DestinationTarget, PushOutcome, Redeployer } from '../../src/ports/destination.ts';
import type { Lent } from '../../src/ports/types.ts';

const place = (t: DestinationTarget, name: string): string => `${t.id}/${name}`;

/** A call that changes what a destination holds or runs: the rotation writes its intent before each one (KBOX-51, KBOX-17). */
export type DestinationCall = 'push' | 'remove' | 'redeploy';
/** Told of each such call as it is entered, before anything changes. */
export type EnterCheck = (call: DestinationCall, target: string) => void;

export class RecordingDestination implements Destination {
  readonly kind: DestinationKind = 'vercel-env';
  readonly #held = new Map<string, { bytes: string; version: number }>();
  readonly #refused = new Map<string, number>();
  readonly #applyThenThrow = new Set<string>();
  readonly #timeOut = new Set<string>();
  readonly #removeRefused = new Set<string>();
  readonly #removeThenThrow = new Set<string>();
  readonly #trace: string[];
  #versions = 0;
  #runtime: boolean;
  #enter: EnterCheck | undefined;

  constructor(trace: string[], runtime = true) {
    this.#trace = trace;
    this.#runtime = runtime;
  }

  /** The destination's own properties change while the box runs (KBOX-16): true is `runtime`, false is `api`. */
  setRuntime(runtime: boolean): void {
    this.#runtime = runtime;
  }

  properties(): { readonly readableBy: 'api' | 'runtime'; readonly needsRedeploy: boolean } {
    return { readableBy: this.#runtime ? 'runtime' : 'api', needsRedeploy: this.#runtime };
  }

  /** The destination answers `refused` (it applied nothing) to every push to this target until `allow`. */
  refuse(target: string): void {
    this.refuseAfter(target, 0);
  }

  /** Lets `pushes` more pushes to this target through, then answers `refused` to every one until `allow`. */
  refuseAfter(target: string, pushes: number): void {
    this.#refused.set(target, pushes);
  }

  /** The next push to this target changes what it holds and then answers an error (a timeout or a 5xx after the commit). */
  applyThenThrow(target: string): void {
    this.#applyThenThrow.add(target);
  }

  /** The next push to this target never answers (a timeout) and applied nothing: the caller cannot tell that from one that applied. */
  timeOut(target: string): void {
    this.#timeOut.add(target);
  }

  /** The destination answers an error for every removal at this target until `allow`. */
  refuseRemove(target: string): void {
    this.#removeRefused.add(target);
  }

  /** The next removal at this target takes the value away and then answers an error (a timeout after the commit). */
  removeThenThrow(target: string): void {
    this.#removeThenThrow.add(target);
  }

  /** Every push and removal is told to `check` as it is entered. */
  onEnter(check: EnterCheck): void {
    this.#enter = check;
  }

  allow(target: string): void {
    this.#refused.delete(target);
    this.#removeRefused.delete(target);
  }

  async push(t: DestinationTarget, name: string, v: Lent, master: Lent): Promise<PushOutcome> {
    void master;
    this.#enter?.('push', t.id);
    const left = this.#refused.get(t.id);
    if (left === 0) return { outcome: 'refused' };
    if (left !== undefined) this.#refused.set(t.id, left - 1);
    if (this.#timeOut.delete(t.id)) throw new Error(`timed out ${t.id}`);
    const bytes = await v.use((b) => Promise.resolve(Buffer.from(b).toString('utf8')));
    const existing = this.#held.get(place(t, name));
    this.#trace.push(`push:${t.id}`);
    if (existing?.bytes === bytes) {
      if (this.#applyThenThrow.delete(t.id)) throw new Error(`timed out ${t.id}`);
      return { outcome: 'applied', version: String(existing.version) };
    }
    this.#versions += 1;
    this.#held.set(place(t, name), { bytes, version: this.#versions });
    if (this.#applyThenThrow.delete(t.id)) throw new Error(`timed out ${t.id}`);
    return { outcome: 'applied', version: String(this.#versions) };
  }

  remove(t: DestinationTarget, name: string, master: Lent): Promise<void> {
    void master;
    this.#enter?.('remove', t.id);
    if (this.#removeRefused.has(t.id)) return Promise.reject(new Error(`refused ${t.id}`));
    this.#trace.push(`remove:${t.id}`);
    this.#held.delete(place(t, name));
    if (this.#removeThenThrow.delete(t.id)) return Promise.reject(new Error(`timed out ${t.id}`));
    return Promise.resolve();
  }

  /** The text of the value held at a target, or undefined. */
  heldAt(target: string, name: string): string | undefined {
    return this.#held.get(`${target}/${name}`)?.bytes;
  }

  /** Every value held at a target, by name: what a deploy started now would run. */
  holdingsAt(target: string): ReadonlyMap<string, string> {
    const prefix = `${target}/`;
    return new Map([...this.#held].filter(([at]) => at.startsWith(prefix)).map(([at, { bytes }]) => [at.slice(prefix.length), bytes]));
  }

  versionAt(target: string, name: string): number | undefined {
    return this.#held.get(`${target}/${name}`)?.version;
  }

  /** How many objects the destination holds: a repeated push must not make a second one. */
  objects(): number {
    return this.#held.size;
  }
}

export class RecordingRedeployer implements Redeployer {
  readonly #failing = new Set<DeployRef>();
  readonly #trace: string[];
  /** Where the deployed code reads its values: a deploy that starts runs what this destination holds at that target then. */
  readonly #source: RecordingDestination | undefined;
  readonly #running = new Map<string, ReadonlyMap<string, string>>();
  readonly #startThenThrow = new Set<string>();
  readonly #refuseNext = new Set<string>();
  readonly #failAt = new Set<string>();
  #failNext = false;
  #next = 1;
  #enter: EnterCheck | undefined;

  constructor(trace: string[], source?: RecordingDestination) {
    this.#trace = trace;
    this.#source = source;
  }

  /** The next deploy started will end as failed. */
  failNext(): void {
    this.#failNext = true;
  }

  /** Every deploy at this target ends as failed (the running one stays) until `allow`. */
  failAt(target: string): void {
    this.#failAt.add(target);
  }

  /** The next redeploy at this target starts the deploy (it runs what the target holds) and then answers an error. */
  startThenThrow(target: string): void {
    this.#startThenThrow.add(target);
  }

  /** The next redeploy at this target answers an error and starts nothing. */
  refuseNext(target: string): void {
    this.#refuseNext.add(target);
  }

  allow(target: string): void {
    this.#failAt.delete(target);
  }

  /** Every redeploy is told to `check` as it is entered. */
  onEnter(check: EnterCheck): void {
    this.#enter = check;
  }

  /** The value the code running at a target reads under this name: what the target held when its last successful deploy started. */
  runningAt(target: string, name: string): string | undefined {
    return this.#running.get(target)?.get(name);
  }

  redeploy(t: DestinationTarget, master: Lent): Promise<DeployRef> {
    void master;
    this.#enter?.('redeploy', t.id);
    if (this.#refuseNext.delete(t.id)) return Promise.reject(new Error(`refused ${t.id}`));
    const ref = `deploy-${this.#next}`;
    this.#next += 1;
    this.#trace.push(`redeploy:${t.id}`);
    const runs = (): void => void this.#running.set(t.id, this.#source?.holdingsAt(t.id) ?? new Map<string, string>());
    if (this.#startThenThrow.delete(t.id)) {
      runs();
      return Promise.reject(new Error(`timed out ${t.id}`));
    }
    if (this.#failNext || this.#failAt.has(t.id)) {
      this.#failing.add(ref);
      this.#failNext = false;
    } else {
      runs();
    }
    return Promise.resolve(ref);
  }

  ready(r: DeployRef): Promise<'ready' | 'failed'> {
    return Promise.resolve(this.#failing.has(r) ? 'failed' : 'ready');
  }
}
