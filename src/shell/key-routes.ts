// KBOX-34, KBOX-15, KBOX-16: the routes mission control and `hand-off` call to issue keys, rotate them and hand over retired values.
// All scope `control`. The class of a key is computed here and never lowered by a caller; an admin or master result waits for the phone.
import type { MetaStore } from '../ports/meta.ts';
import type { Random } from '../ports/random.ts';
import type { Action, Destination } from '../pure/actions.ts';
import { parseAction } from '../pure/actions.ts';
import { classOf, keyrefOf, matchesShape } from '../pure/class.ts';
import { namesHost } from '../pure/location.ts';
import { ApiError } from '../pure/errors.ts';
import { LABEL, NAME, parseQuery, text } from '../pure/schemas.ts';
import type { Parsed } from '../pure/schemas.ts';
import type { Approvals } from './approvals.ts';
import { parsedRoute, route } from './http.ts';
import type { Route } from './http.ts';
import { classifierOf, shapeOf } from '../pure/platform-shape.ts';
import { keyConfigFor, newKeyOf, placedKey } from './new-key.ts';
import type { AddKey, RotateKey } from './new-key.ts';
import type { Orchestrator } from './orchestrator.ts';
import type { Paste } from './paste.ts';
import { isRecord, only } from './routes-approve.ts';
import { overlapOf, proposalRefusal, rotatesByPaste, verifierFor } from './rotation-ports.ts';
import type { PlatformSource } from './rotation-ports.ts';
import type { DestinationRow, RotationStore } from './rotation-store.ts';
import type { Vault } from '../ports/vault.ts';
import type { Audit } from '../ports/audit.ts';
import type { Clock } from '../ports/clock.ts';
import type { KeyLocation } from '../ports/types.ts';
import type { EventLog } from '../ports/events.ts';

export interface KeyRouteDeps {
  readonly store: RotationStore;
  readonly meta: MetaStore;
  readonly orchestrator: Orchestrator;
  readonly approvals: Pick<Approvals, 'propose'>;
  readonly paste: Paste;
  readonly source: PlatformSource;
  readonly vault: Vault;
  readonly audit: Audit;
  readonly events: EventLog;
  readonly clock: Clock;
  readonly random: Random;
}

const ENV_KEY_NAME = /^[A-Z][A-Z0-9_]*$/;
/** The retired hand-off's body bound: the same 64 KiB as every JSON body (http.ts). */
const RETIRED_VALUE_LIMIT = 64 * 1024;
const rejected =(code: string): ApiError => new ApiError('rejected', code);

interface KeyRequest {
  readonly action: Extract<Action, { kind: 'add_key' }>;
  readonly destinations: readonly Destination[];
  readonly rotateEveryDays: number | undefined;
}

/** `{platform, name, projects, scope, location?, label?, destinations?, rotate_every_days?}`, closed. Members are checked by the action parser. */
function parseKeyRequest(raw: unknown): Parsed<KeyRequest> {
  if (!isRecord(raw) || !only(raw, ['platform', 'name', 'projects', 'scope'], ['location', 'label', 'destinations', 'rotate_every_days'])) return { ok: false };
  const { platform, name, projects, scope, location, label } = raw;
  if (typeof name !== 'string' || !ENV_KEY_NAME.test(name)) return { ok: false };
  const action = parseAction({ kind: 'add_key', platform, name, projects, scope, ...(location === undefined ? {} : { location }), ...(label === undefined ? {} : { label }) });
  if (!action.ok || action.value.kind !== 'add_key') return { ok: false };
  const listed = raw['destinations'];
  const destinations: Destination[] = [];
  if (listed !== undefined) {
    if (!Array.isArray(listed) || listed.length > 16) return { ok: false };
    for (const d of listed as unknown[]) {
      const one = parseAction({ kind: 'add_destination', keyref: 'k/k/K', destination: d });
      if (!one.ok || one.value.kind !== 'add_destination') return { ok: false };
      destinations.push(one.value.destination);
    }
  }
  const days = raw['rotate_every_days'];
  const every = days === undefined ? { ok: true as const, value: undefined } : parseDays(days);
  if (!every.ok) return { ok: false };
  return { ok: true, value: { action: action.value, destinations, rotateEveryDays: every.value } };
}

const parseDays = (v: unknown): Parsed<number> => (typeof v === 'number' && Number.isSafeInteger(v) && v >= 1 && v <= 3650 ? { ok: true, value: v } : { ok: false });

const parseKeyrefBody = (raw: unknown): Parsed<{ readonly keyref: string }> =>
  isRecord(raw) && only(raw, ['keyref']) && typeof raw['keyref'] === 'string' && NAME.test(raw['keyref']) ? { ok: true, value: { keyref: raw['keyref'] } } : { ok: false };

export function keyRoutes(deps: KeyRouteDeps): Route[] {
  const { store } = deps;

  const rowOf = (d: Destination): DestinationRow => {
    // The workstation is a delivery, not an adapter: its value is fetched by the box's own control route (KBOX-34).
    if (d.kind === 'workstation') return { kind: d.kind, target: 'workstation', readable_by: 'api' };
    const kit = deps.source.destination(d.kind);
    if (kit === undefined) throw rejected('unknown_destination');
    return { kind: d.kind, target: d.target, readable_by: kit.destination.properties().readableBy };
  };

  return [
    parsedRoute({
      method: 'POST',
      path: '/api/keys',
      surface: 'api',
      scope: 'control',
      parse: parseKeyRequest,
      handle: async ({ body, actor }) => {
        const { action } = body;
        const keyref = keyrefOf(action.platform, action.projects, action.name);
        const config = keyConfigFor(deps.source, action.platform);
        // KBOX-57, KBOX-15: the class at the request's location (never below the class without it) and the location the entry accepts for it.
        const { klass, at } = placedKey(config, action);
        // KBOX-57: a key elsewhere is a new key; an existing reference is refused on every branch before anything is asked, opened or written.
        if (store.keyExists(keyref)) throw new ApiError('conflict', 'key_exists');
        if (klass === 'master') return masterResult(deps, action, keyref, at, actor);
        if (config.create === 'paste') {
          if (klass === 'ordinary') throw rejected('no_issuer');
          refuseUnverifiable(deps.source, action, at);
          await provenPlacement(deps.source, action, at, 'paste');
          const opened = deps.paste.open({ action, requester: { kind: 'token', label: actor } });
          return { status: 202, json: { keyref, class: klass, paste_task_id: opened.paste_id } };
        }
        // A key of a one-credential platform is added by paste, never by a run (nothing to set back): refused before an approval is asked for.
        if (!overlapOf(deps.source.platform(action.platform))) throw rejected('overlap_needs_paste');
        if (klass !== 'ordinary' && (body.destinations.length > 0 || body.rotateEveryDays !== undefined)) throw rejected('use_approvals_for_options');
        await provenPlacement(deps.source, action, at, 'run');
        if (klass !== 'ordinary') {
          const proposed = deps.approvals.propose({ action, requester: { kind: 'token', label: actor } });
          return { status: 202, json: { keyref, class: klass, approval_id: proposed.approval_id } };
        }
        const rows = body.destinations.map(rowOf);
        const created = await deps.orchestrator.create(newKeyOf(action, deps.source, rows, body.rotateEveryDays));
        if (action.label !== undefined) deps.meta.putGrant(keyref, action.label);
        return { status: 201, json: { keyref, class: klass, status: created.status } };
      },
    }),

    parsedRoute({
      method: 'POST',
      path: '/api/rotations',
      surface: 'api',
      scope: 'control',
      parse: parseKeyrefBody,
      handle: ({ body, actor }) => {
        const head = store.key(body.keyref);
        if (head === undefined) throw new ApiError('not_found');
        if (store.activeRunOf(body.keyref) !== undefined) throw new ApiError('conflict', 'run_exists');
        // KBOX-57: a stored location the entry now refuses is answered with its code, before any run, approval or paste task.
        const info = store.keyInfo(body.keyref);
        // Where a run makes the key (an approval, not a paste) the platform's master is asked first: none is `no_master`, two `master_ambiguous`; where a
        // paste would, a verifier that applies to the key (KBOX-58, `no_verifier`), before the status changes.
        const placed = proposalRefusal(deps.source, head, info);
        if (placed !== 'ok') throw rejected(placed);
        if (head.class === 'ordinary') return { status: 201, json: { run_id: deps.orchestrator.start({ keyref: body.keyref, origin: 'agent' }).runId } };
        const action: RotateKey = { kind: 'rotate_key', keyref: body.keyref };
        // KBOX-34: a paste-source platform's key, and a master whose issuer is not selfRotate, are rotated by a paste.
        if (rotatesByPaste(deps.source, head)) {
          store.setStatus(body.keyref, 'awaiting_paste');
          return { status: 202, json: { paste_task_id: deps.paste.open({ action, requester: { kind: 'token', label: actor } }).paste_id } };
        }
        const proposed = deps.approvals.propose({ action, requester: { kind: 'token', label: actor } });
        store.setStatus(body.keyref, 'awaiting_approval');
        return { status: 202, json: { approval_id: proposed.approval_id } };
      },
    }),

    {
      method: 'POST',
      path: '/api/retired',
      surface: 'api',
      scope: 'control',
      open: false,
      takesBody: false,
      // A retired key value as raw bytes (KBOX-34), bounded like any JSON body.
      rawBody: { type: 'application/octet-stream', limit: RETIRED_VALUE_LIMIT },
      run: ({ query, raw }) => {
        const q = parseQuery({ platform: text(LABEL), project: text(NAME), name: text(ENV_KEY_NAME) }, query);
        if (!q.ok || raw === undefined) throw new ApiError('bad_request');
        return retire(deps, q.value, raw);
      },
    },
  ];
}

/**
 * KBOX-55 fills this: the platforms whose master the box makes itself (Google's signing key). A master result there is `rejected`
 * (`box_made_master`), checked before anything else about a master, because that master is never pasted. None is registered yet.
 */
const BOX_MADE_MASTER_PLATFORMS: ReadonlySet<string> = new Set();

/**
 * KBOX-34: the answer to a master-class result of `POST /api/keys`, on an issuer platform and a paste platform alike: no issuer can make
 * another kind's master and none is asked, no approval is opened, the owner pastes it. In this order: a platform whose master the box makes
 * (`box_made_master`, KBOX-55, none yet); a key no verifier of the platform applies to (`no_verifier`, KBOX-58); then the paste task. A location
 * that names a host is proven first, as for any paste; a master that names none needs no master of its own, or the first one could never enter.
 */
async function masterResult(deps: KeyRouteDeps, action: AddKey, keyref: string, at: KeyLocation, actor: string): Promise<{ readonly status: number; readonly json: unknown }> {
  if (BOX_MADE_MASTER_PLATFORMS.has(action.platform)) throw rejected('box_made_master');
  refuseUnverifiable(deps.source, action, at);
  if (namesHost(deps.source.platform(action.platform)?.location, at)) await provenPlacement(deps.source, action, at, 'paste');
  const opened = deps.paste.open({ action, requester: { kind: 'token', label: actor } });
  return { status: 202, json: { keyref, class: 'master', paste_task_id: opened.paste_id } };
}

/**
 * KBOX-34, KBOX-58, at proposal: an `add_key` that would open a paste task (any class) is refused (`rejected`, `no_verifier`) when no verifier
 * of its platform applies to the key's scope and location: a pasted value is checked by the verifier (KBOX-12), and only the verifier can confirm
 * a pasted generation dead (KBOX-51). Throws before anything is opened, so the owner never reaches the passkey step.
 */
function refuseUnverifiable(source: PlatformSource, action: AddKey, at: KeyLocation): void {
  if (verifierFor(source.platform(action.platform), { scopeItems: action.scope.items, at }) === undefined) throw rejected('no_verifier');
}

/**
 * KBOX-57, at proposal: where the key needs its master (made by a run, or on an entry with a `locationProver`), the master chosen by the key's
 * platform, location and scope items; none is `no_master` and two `master_ambiguous`, both `rejected`. A location naming a host is then proven
 * with that master: `unseen` is `rejected` (`location_unknown`), a prover that throws is `unavailable`. Throws before anything is proposed,
 * opened or written.
 */
async function provenPlacement(source: PlatformSource, action: AddKey, at: KeyLocation, made: 'run' | 'paste'): Promise<void> {
  const kit = source.platform(action.platform);
  const prover = kit?.locationProver;
  if (made === 'paste' && prover === undefined) return;
  const master = source.master(action.platform, at, action.scope.items);
  if (!master.ok) throw rejected(master.code);
  if (prover === undefined || !namesHost(kit?.location, at)) return;
  const seen = await prover.prove(at, master.value).catch(() => {
    throw new ApiError('unavailable');
  });
  if (seen === 'unseen') throw rejected('location_unknown');
}

/** Stores a retired value as a retired generation: never lent, never pushed; fingerprinted only when it passes the shape check (KBOX-34). */
function retire(deps: KeyRouteDeps, q: { readonly platform: string; readonly project: string; readonly name: string }, bytes: Uint8Array): { readonly status: number; readonly json: unknown } {
  const kit = deps.source.platform(q.platform);
  const classify = classifierOf(kit);
  const shape = shapeOf(kit);
  if (classify === undefined || shape === undefined) throw rejected('unknown_platform');
  const keyref = keyrefOf(q.platform, [q.project], q.name);
  const { store } = deps;
  if (store.key(keyref) === undefined) {
    deps.meta.putKey({
      keyref,
      platform: q.platform,
      name: q.name,
      projects: [q.project],
      class: classOf(classify({ items: [] }, {}), undefined),
      status: 'works',
      gen_current: 1,
      schedule: { rotate_every_days: 90, grace_hours: 1, next_due_at: null, expires_at: null },
      coverage: null,
      last_use_at: null,
    });
    store.putKeyInfo(keyref, { scopeItems: [], location: {}, rotatedAt: deps.clock.now(), markAdmin: false });
  }
  const gen = store.topGen(keyref) + 1;
  deps.vault.put(keyref, gen, bytes);
  // KBOX-57: a generation of a key records the key's stored location (the one a new record has just been given is empty).
  store.putGen({ keyref, gen, status: 'retired', platformKeyId: null, location: store.keyInfo(keyref)?.location ?? {} });
  deps.vault.retire(keyref, gen);
  const fits = matchesShape(shape, Buffer.from(bytes).toString('utf8'));
  deps.audit.append({ action: 'key.issued', subject: keyref, at: deps.clock.now() });
  deps.events.append('key.changed', { keyref });
  return { status: 201, json: { keyref, gen, coverage: fits ? null : 'none' } };
}

