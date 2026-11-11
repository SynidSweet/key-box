// KBOX-3, KBOX-14, KBOX-50: core's side of the lend socket. Core re-checks every pass, grant and rule id the relay sends,
// and lends a value only for an admin key: the class check is here, in code, not in configuration, so a master or ordinary
// value never reaches the relay. Responses are scanned here too, against every value the box holds (master values
// included), so those values never leave core. The relay's audit rows are written here, closed.
import { readFileSync } from 'node:fs';
import type { Audit } from '../ports/audit.ts';
import type { Clock } from '../ports/clock.ts';
import type { EventLog } from '../ports/events.ts';
import type { MetaKey, MetaStore, TokenRecord, TokenStore } from '../ports/meta.ts';
import type { PlatformEntry } from '../ports/platform.ts';
import type { RelayProfile } from '../ports/relay-profile.ts';
import type { Vault } from '../ports/vault.ts';
import { VaultError } from '../pure/errors.ts';
import { scanForms } from '../pure/forms.ts';
import type { Form } from '../pure/forms.ts';
import { FRAME_BYTES, FRAME_END, acceptedMessage, refusalMessage, scanStepMessage } from '../pure/lend-protocol.ts';
import type { LendRefusal, LendRequest, RelayAuditRow } from '../pure/lend-protocol.ts';
import { createResponseScanner, parseCredentialShapes } from '../pure/scanner.ts';
import type { CredentialShapes, ResponseScanner } from '../pure/scanner.ts';
import { findTokenHash } from '../pure/tokens.ts';
import type { LendHandler, LendSession } from './lend-socket.ts';

export interface LendCoreDeps {
  readonly meta: MetaStore;
  /** The token store the machine API uses, so a new network seen by the relay notifies the same way. */
  readonly tokens: TokenStore;
  readonly vault: Vault;
  readonly audit: Audit;
  readonly events: EventLog;
  readonly registry: readonly PlatformEntry[];
  readonly shapes: CredentialShapes;
  readonly clock: Clock;
}

type Checked<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly code: LendRefusal };

const NOTICE = { code: 'credential_withheld', text: 'credential withheld' } as const;

/** The credential shapes of KBOX-14, from `src/data/credential-shapes.json`; a file that does not parse stops the caller. */
export function loadCredentialShapes(): CredentialShapes {
  const parsed = parseCredentialShapes(JSON.parse(readFileSync(new URL('../data/credential-shapes.json', import.meta.url), 'utf8')) as unknown);
  if (!parsed.ok) throw new RangeError('src/data/credential-shapes.json does not parse');
  return parsed.value;
}

export function createLendHandler(deps: LendCoreDeps): LendHandler {
  const profileOf = (platform: string): RelayProfile | undefined => deps.registry.find((e) => e.id === platform)?.relay;

  const pass = (tokenHash: string): Checked<TokenRecord> => {
    const record = findTokenHash(deps.tokens.tokens(), tokenHash);
    return record === undefined || record.revoked || record.scope !== 'relay' ? { ok: false, code: 'bad_token' } : { ok: true, value: record };
  };

  /** The key, when it exists and is granted to the pass's machine. */
  const grantedKey = (record: TokenRecord, keyref: string): Checked<MetaKey> => {
    const key = deps.meta.snapshot().keys.find((k) => k.keyref === keyref);
    return key !== undefined && key.grants.some((g) => g.machine === record.label) ? { ok: true, value: key } : { ok: false, code: 'forbidden' };
  };

  /** KBOX-3: only an admin key with a relay profile, and only for a rule of that profile, is ever lent. */
  const lendable = (key: MetaKey, ruleId: string): boolean => {
    if (key.class !== 'admin') return false;
    const profile = profileOf(key.platform);
    return profile !== undefined && profile.allow.some((r) => r.id === ruleId);
  };

  /** The forms of one stored generation; none for a generation the vault no longer has. */
  const formsOfStored = async (keyref: string, gen: number): Promise<readonly Form[]> => {
    let lent;
    try {
      lent = deps.vault.lend(keyref, gen);
    } catch (error) {
      if (error instanceof VaultError && error.failure === 'unknown_key') return [];
      throw error;
    }
    return lent.use((bytes) => {
      const result = scanForms(Buffer.from(bytes).toString('utf8'));
      return Promise.resolve(result.ok ? result.forms : []);
    });
  };
  const formsCache = new Map<string, readonly Form[]>();
  /** The forms of every live value: the current generation of each key and the one before it while it may still work. */
  const heldForms = async (): Promise<readonly Form[]> => {
    const all: Form[] = [];
    for (const key of deps.meta.snapshot().keys) {
      for (const gen of [key.gen_current, key.gen_current - 1].filter((g) => g >= 1)) {
        const id = `${key.keyref}:${gen}`;
        const forms = formsCache.get(id) ?? (await formsOfStored(key.keyref, gen));
        formsCache.set(id, forms);
        all.push(...forms);
      }
    }
    return all;
  };

  const runScan = async (session: LendSession, scanner: ResponseScanner): Promise<void> => {
    for (let frame = await session.next(); frame !== undefined; frame = await session.next()) {
      const step = frame.kind === FRAME_BYTES ? scanner.feed(frame.body) : frame.kind === FRAME_END ? scanner.end() : undefined;
      if (step === undefined) return session.reply(refusalMessage('bad_request'));
      session.reply(scanStepMessage(step));
      if (step.kind === 'hit' || frame.kind === FRAME_END) return;
    }
  };

  const writeAudit = (row: RelayAuditRow): void => {
    const { label, keyref, route, ...detail } = row;
    deps.audit.append({ action: 'relay.request', subject: keyref ?? (route === 'grants' ? '/r/_/grants' : 'unmatched'), actor: label ?? 'box', at: deps.clock.now(), detail: { route, ...detail } });
    // KBOX-14: the owner notice follows a hit (a value or a credential shape), not a refused partial or encoded answer.
    if (row.code === 'withheld' && (row.reason === 'value' || row.reason === 'credential')) deps.events.append('box.notice', NOTICE);
  };

  const handle = async (session: LendSession, request: LendRequest): Promise<void> => {
    if (request.op === 'audit') {
      writeAudit(request.row);
      return session.reply(acceptedMessage());
    }
    const record = pass(request.token_hash);
    if (!record.ok) return session.reply(refusalMessage(record.code));
    switch (request.op) {
      case 'resolve': {
        deps.tokens.recordUse(record.value.label, request.network);
        const key = grantedKey(record.value, request.keyref);
        return session.reply(key.ok ? { ok: 'true', label: record.value.label, platform: key.value.platform } : refusalMessage(key.code));
      }
      case 'grants': {
        deps.tokens.recordUse(record.value.label, request.network);
        const grants = deps.meta
          .snapshot()
          .keys.filter((k) => k.class === 'admin' && profileOf(k.platform) !== undefined && k.grants.some((g) => g.machine === record.value.label))
          .map((k) => ({ keyref: k.keyref, platform: k.platform, name: k.name, projects: k.projects }));
        return session.reply({ ok: 'true', machine: record.value.label, grants });
      }
      case 'lend': {
        const key = grantedKey(record.value, request.keyref);
        if (!key.ok || !lendable(key.value, request.rule_id)) return session.reply(refusalMessage('forbidden'));
        return deps.vault.lend(key.value.keyref, key.value.gen_current).use((bytes) => {
          session.replyBytes(bytes);
          return Promise.resolve();
        });
      }
      case 'scan': {
        const key = grantedKey(record.value, request.keyref);
        if (!key.ok) return session.reply(refusalMessage('forbidden'));
        const scanner = createResponseScanner(await heldForms(), deps.shapes);
        session.reply(acceptedMessage());
        return runScan(session, scanner);
      }
    }
  };

  return { handle: (session) => handle(session, session.request) };
}
