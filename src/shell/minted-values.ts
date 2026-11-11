// KBOX-14, KBOX-41: core's registry of live minted values. An adapter that mints a short-lived credential and injects it
// (the Google access token) registers it here through the MintedSink port; the lend handler's scanner holds its forms next
// to every stored value until it expires, so an upstream echo of it, in any form the scanner knows, is cut.
import type { Clock } from '../ports/clock.ts';
import type { MintedSink } from '../ports/minted.ts';
import { scanForms } from '../pure/forms.ts';
import type { Form } from '../pure/forms.ts';

export interface MintedValues extends MintedSink {
  /** The forms of every value that has not expired; an expired entry is dropped on the way. */
  forms(): readonly Form[];
}

interface Entry {
  readonly forms: readonly Form[];
  readonly expiresAt: number;
}

export function createMintedValues(clock: Clock): MintedValues {
  const byKey = new Map<string, Entry[]>();

  const prune = (): void => {
    const now = clock.now();
    for (const [keyref, entries] of byKey) {
      const live = entries.filter((e) => e.expiresAt > now);
      if (live.length === 0) byKey.delete(keyref);
      else byKey.set(keyref, live);
    }
  };

  return {
    add(keyref, value, expiresAt) {
      const built = scanForms(Buffer.from(value).toString('utf8'));
      if (!built.ok) throw new RangeError(`a minted value must have forms the scanner can match (${built.code})`);
      prune();
      byKey.set(keyref, [...(byKey.get(keyref) ?? []), { forms: built.forms, expiresAt }]);
    },
    forms() {
      prune();
      return [...byKey.values()].flatMap((entries) => entries.flatMap((e) => e.forms));
    },
  };
}
