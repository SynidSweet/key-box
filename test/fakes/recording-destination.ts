// A destination that keeps what it holds, in order, and can refuse a target or fail a deploy: the rotation tests read it to see what each
// destination holds at any moment. Faults are planted through the port (it refuses), never by patching.
import type { DeployRef, Destination, DestinationKind, DestinationTarget, PushReceipt, Redeployer } from '../../src/ports/destination.ts';
import type { Lent } from '../../src/ports/types.ts';

const place = (t: DestinationTarget, name: string): string => `${t.id}/${name}`;

export class RecordingDestination implements Destination {
  readonly kind: DestinationKind = 'vercel-env';
  readonly #held = new Map<string, { bytes: string; version: number }>();
  readonly #refused = new Map<string, number>();
  readonly #applyThenThrow = new Set<string>();
  readonly #removeRefused = new Set<string>();
  readonly #trace: string[];
  #versions = 0;
  #runtime: boolean;

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

  /** The destination answers an error for every push to this target until `allow`. */
  refuse(target: string): void {
    this.refuseAfter(target, 0);
  }

  /** Lets `pushes` more pushes to this target through, then answers an error for every one until `allow`. */
  refuseAfter(target: string, pushes: number): void {
    this.#refused.set(target, pushes);
  }

  /** The next push to this target changes what it holds and then answers an error (a timeout or a 5xx after the commit). */
  applyThenThrow(target: string): void {
    this.#applyThenThrow.add(target);
  }

  /** The destination answers an error for every removal at this target until `allow`. */
  refuseRemove(target: string): void {
    this.#removeRefused.add(target);
  }

  allow(target: string): void {
    this.#refused.delete(target);
    this.#removeRefused.delete(target);
  }

  async push(t: DestinationTarget, name: string, v: Lent, master: Lent): Promise<PushReceipt> {
    void master;
    const left = this.#refused.get(t.id);
    if (left === 0) throw new Error(`refused ${t.id}`);
    if (left !== undefined) this.#refused.set(t.id, left - 1);
    const bytes = await v.use((b) => Promise.resolve(Buffer.from(b).toString('utf8')));
    const existing = this.#held.get(place(t, name));
    this.#trace.push(`push:${t.id}`);
    if (existing?.bytes === bytes) {
      if (this.#applyThenThrow.delete(t.id)) throw new Error(`timed out ${t.id}`);
      return { version: String(existing.version) };
    }
    this.#versions += 1;
    this.#held.set(place(t, name), { bytes, version: this.#versions });
    if (this.#applyThenThrow.delete(t.id)) throw new Error(`timed out ${t.id}`);
    return { version: String(this.#versions) };
  }

  remove(t: DestinationTarget, name: string, master: Lent): Promise<void> {
    void master;
    if (this.#removeRefused.has(t.id)) return Promise.reject(new Error(`refused ${t.id}`));
    this.#trace.push(`remove:${t.id}`);
    this.#held.delete(place(t, name));
    return Promise.resolve();
  }

  /** The text of the value held at a target, or undefined. */
  heldAt(target: string, name: string): string | undefined {
    return this.#held.get(`${target}/${name}`)?.bytes;
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
  #failNext = false;
  #next = 1;

  constructor(trace: string[]) {
    this.#trace = trace;
  }

  /** The next deploy started will end as failed. */
  failNext(): void {
    this.#failNext = true;
  }

  redeploy(t: DestinationTarget, master: Lent): Promise<DeployRef> {
    void master;
    const ref = `deploy-${this.#next}`;
    this.#next += 1;
    this.#trace.push(`redeploy:${t.id}`);
    if (this.#failNext) {
      this.#failing.add(ref);
      this.#failNext = false;
    }
    return Promise.resolve(ref);
  }

  ready(r: DeployRef): Promise<'ready' | 'failed'> {
    return Promise.resolve(this.#failing.has(r) ? 'failed' : 'ready');
  }
}
