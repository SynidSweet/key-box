import type { KeyRef, Lent } from '../../src/ports/types.ts';
import type { Vault } from '../../src/ports/vault.ts';
import { lent } from '../kit/index.ts';

type Entry = { readonly bytes: Uint8Array; retired: boolean };

export class FakeVault implements Vault {
  readonly #entries = new Map<string, Entry>();

  put(ref: KeyRef, gen: number, v: Uint8Array): void {
    this.#entries.set(`${ref}:${gen}`, { bytes: Uint8Array.from(v), retired: false });
  }

  lend(ref: KeyRef, gen: number): Lent {
    const id = `${ref}:${gen}`;
    const entry = this.#entries.get(id);
    if (entry === undefined || entry.retired) throw new Error(`no live key ${id}`);
    return lent(entry.bytes, id);
  }

  retire(ref: KeyRef, gen: number): void {
    const entry = this.#entries.get(`${ref}:${gen}`);
    if (entry !== undefined) entry.retired = true;
  }
}
