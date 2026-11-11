import type { DeployRef, Destination, DestinationKind, DestinationTarget, PushOutcome, Redeployer } from '../../src/ports/destination.ts';
import type { Lent } from '../../src/ports/types.ts';

const slot = (t: DestinationTarget, name: string): string => `${t.kind}:${t.id}/${name}`;

export class FakeDestination implements Destination {
  readonly kind: DestinationKind = 'vercel-env';
  readonly #held = new Map<string, { bytes: Buffer; version: number }>();
  #versions = 0;

  properties(): { readonly readableBy: 'api' | 'runtime'; readonly needsRedeploy: boolean } {
    return { readableBy: 'runtime', needsRedeploy: true };
  }

  async push(t: DestinationTarget, name: string, v: Lent, master: Lent): Promise<PushOutcome> {
    void master;
    const bytes = Buffer.from(await v.use((b) => Promise.resolve(Uint8Array.from(b))));
    const existing = this.#held.get(slot(t, name));
    if (existing !== undefined && existing.bytes.equals(bytes)) return { outcome: 'applied', version: String(existing.version) };
    this.#versions += 1;
    this.#held.set(slot(t, name), { bytes, version: this.#versions });
    return { outcome: 'applied', version: String(this.#versions) };
  }

  remove(t: DestinationTarget, name: string, master: Lent): Promise<void> {
    void master;
    this.#held.delete(slot(t, name));
    return Promise.resolve();
  }

  has(t: DestinationTarget, name: string): boolean {
    return this.#held.has(slot(t, name));
  }
}

export class FakeRedeployer implements Redeployer {
  readonly #failing = new Set<DeployRef>();
  #failNext = false;
  #next = 1;

  /** The next deploy started will report 'failed'. */
  failNext(): void {
    this.#failNext = true;
  }

  redeploy(t: DestinationTarget, master: Lent): Promise<DeployRef> {
    void t;
    void master;
    const ref = `deploy-${this.#next}`;
    this.#next += 1;
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
