// KBOX-11, KBOX-53: machine tokens. The first `control` enrol is accepted only inside a 10-minute window the owner opens for
// one label by a signed operation; it takes one enrol. A `relay` enrol only makes a proposal. A revoke is a signed
// operation naming the label. The first use of a token from a new network sends one push.
import type { Audit } from '../ports/audit.ts';
import type { Clock } from '../ports/clock.ts';
import type { EventLog } from '../ports/events.ts';
import type { MetaStore, TokenStore } from '../ports/meta.ts';
import type { Push } from '../ports/push.ts';
import { ApiError } from '../pure/errors.ts';
import type { Approvals } from './approvals.ts';

/** The owner's enrol window: 10 minutes for one label, one enrol (KBOX-11). */
export const ENROL_WINDOW_MS = 10 * 60_000;

export interface EnrolRequest {
  readonly tokenSha256: string;
  readonly label: string;
  readonly scope: 'control' | 'relay';
  readonly source: string;
  readonly reason?: { readonly agent: string; readonly text: string };
}

export type EnrolAnswer = { readonly status: 'active' } | { readonly status: 'pending' };

export interface MachineTokens {
  /** Signed operation `enrol_window_open {label}`: replaces any open window. */
  openWindow(label: string, approverId: string): void;
  /** Signed operation `token_revoke {label}`: takes effect on the next request. */
  revoke(label: string, approverId: string): void;
  enrol(request: EnrolRequest): EnrolAnswer;
  /** The token store the server sees: the real one, plus one push on a token's first use from a new network. */
  readonly tokenStore: TokenStore;
}

export interface MachineTokenDeps {
  readonly meta: MetaStore & TokenStore;
  readonly events: EventLog;
  readonly approvals: Approvals;
  readonly push: Push;
  readonly audit: Audit;
  readonly clock: Clock;
}

export function createMachineTokens(deps: MachineTokenDeps): MachineTokens {
  let window: { readonly label: string; readonly until: number } | undefined;

  const activeLabel = (label: string): boolean => deps.meta.tokens().some((t) => t.label === label && !t.revoked);
  const knownLabel = (label: string): boolean => deps.meta.tokens().some((t) => t.label === label);

  return {
    openWindow(label, approverId) {
      window = { label, until: deps.clock.now() + ENROL_WINDOW_MS };
      deps.audit.append({ action: 'enrol.window_opened', subject: label, actor: approverId, at: deps.clock.now() });
    },

    revoke(label, approverId) {
      deps.meta.revokeMachine(label);
      deps.audit.append({ action: 'token.revoked', subject: label, actor: approverId, at: deps.clock.now() });
    },

    enrol(request) {
      if (activeLabel(request.label)) throw new ApiError('conflict', 'label_taken');
      if (request.scope === 'relay') {
        deps.approvals.propose({
          action: { kind: 'enrol', label: request.label, token_sha256: request.tokenSha256, address: request.source },
          requester: { kind: 'enrol', address: request.source },
          ...(request.reason === undefined ? {} : { reason: request.reason }),
        });
        return { status: 'pending' };
      }
      const open = window;
      if (open === undefined || deps.clock.now() > open.until || open.label !== request.label) throw new ApiError('forbidden', 'no_window');
      if (knownLabel(request.label)) throw new ApiError('conflict', 'label_taken');
      window = undefined;
      deps.meta.addMachine({ label: request.label, scope: 'control', tokenSha256: request.tokenSha256, enrolledAt: deps.clock.now() });
      deps.audit.append({ action: 'enrol.accepted', subject: request.label, at: deps.clock.now(), detail: { scope: 'control' } });
      return { status: 'active' };
    },

    tokenStore: {
      tokens: () => deps.meta.tokens(),
      recordUse(label, network) {
        const head = deps.events.head();
        deps.meta.recordUse(label, network);
        if (deps.events.after(head).some((e) => e.kind === 'token.new_network' && e.data['label'] === label)) {
          deps.push.send({ title: `The token ${label} was used from a new network ${network}`, kind: 'new_network' });
        }
      },
    },
  };
}
