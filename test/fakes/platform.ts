// One in-memory platform: an issuer, its lister and its verifier over the same set of live keys.
import type { Random } from '../../src/ports/random.ts';
import type { Issuer, IssuerCapabilities, IssuedKey, IssueRequest, KeyListing, KeyLister, PlatformKeyInfo, Verifier } from '../../src/ports/issuer.ts';
import type { KeyClass, KeyLocation, Lent, PlatformKeyId, Scope } from '../../src/ports/types.ts';
import { lent } from '../kit/index.ts';

const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');

export class FakePlatformWorld {
  readonly masterBytes: Uint8Array;
  readonly #keys = new Map<PlatformKeyId, { name: string; bytes: Uint8Array }>();
  readonly #random: Random;
  #reachable = true;
  #next = 1;

  constructor(random: Random) {
    this.#random = random;
    this.masterBytes = Buffer.from(`fk-master-${hex(random.bytes(16))}`);
  }

  master(): Lent {
    return lent(this.masterBytes, 'master:1');
  }

  /** A key the platform never issued. */
  stranger(): Lent {
    return lent(Buffer.from('fk-stranger'), 'stranger:1');
  }

  /**
   * A platform that holds one credential and takes a value the caller chose (overlap:false, a database password): the value it held
   * before stops working at once. The credential is listed as `pk-set`.
   */
  async set(value: Lent, master: Lent): Promise<void> {
    await this.#requireMaster(master);
    if (!this.#reachable) throw new Error('platform unreachable');
    const bytes = await value.use((b) => Promise.resolve(Uint8Array.from(b)));
    this.#keys.set('pk-set', { name: 'credential', bytes });
  }

  setReachable(reachable: boolean): void {
    this.#reachable = reachable;
  }

  readonly issuer: Issuer = {
    platform: 'fake',
    capabilities: (): IssuerCapabilities => ({
      create: 'api',
      revoke: 'api',
      selfRotate: false,
      overlap: true,
      set: 'none',
      revealOnce: true,
      scopeSchema: { fields: ['access'] },
      shape: { prefix: 'fk-', alphabet: 'hex', coreLength: { min: 32, max: 32 }, random: true },
      classify: (scope: Scope): KeyClass => (scope['access'] === 'admin' ? 'admin' : 'ordinary'),
    }),
    issue: async (req: IssueRequest, intentName: string, master: Lent): Promise<IssuedKey> => {
      void req;
      await this.#requireMaster(master);
      if (!this.#reachable) throw new Error('platform unreachable');
      const platformKeyId = `pk-${this.#next}`;
      this.#next += 1;
      const bytes = Buffer.from(`fk-${hex(this.#random.bytes(16))}`);
      this.#keys.set(platformKeyId, { name: intentName, bytes });
      return { value: lent(bytes, platformKeyId), platformKeyId };
    },
    revoke: async (id: PlatformKeyId, master: Lent): Promise<'revoked' | 'absent'> => {
      await this.#requireMaster(master);
      return this.#keys.delete(id) ? 'revoked' : 'absent';
    },
  };

  readonly lister: KeyLister = {
    list: async (master: Lent): Promise<PlatformKeyInfo[]> => {
      await this.#requireMaster(master);
      return [...this.#keys].map(([platformKeyId, { name }]) => ({ platformKeyId, name }));
    },
    /** One place holds every key: any location asked for is answered with all of them, in one complete page. */
    listAt: async (at: KeyLocation, master: Lent): Promise<KeyListing> => {
      await this.#requireMaster(master);
      return { complete: true, at, keys: [...this.#keys].map(([platformKeyId, { name }]) => ({ platformKeyId, name, location: at })) };
    },
  };

  readonly verifier: Verifier = {
    verify: async (key: Lent): Promise<'ok' | 'rejected' | 'unreachable'> => {
      if (!this.#reachable) return 'unreachable';
      const presented = Buffer.from(await key.use((b) => Promise.resolve(Uint8Array.from(b))));
      return [...this.#keys.values()].some((k) => Buffer.from(k.bytes).equals(presented)) ? 'ok' : 'rejected';
    },
  };

  async #requireMaster(master: Lent): Promise<void> {
    const presented = Buffer.from(await master.use((b) => Promise.resolve(Uint8Array.from(b))));
    if (!presented.equals(this.masterBytes)) throw new Error('401: the master key was not accepted');
  }
}
