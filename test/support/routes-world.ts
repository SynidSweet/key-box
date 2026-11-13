// The approval half of core (approveWorld) with the rotation unit wired in beside it: one fake API platform that issues keys, one paste platform
// whose verifier accepts the values a test names, a recording destination, and the rotation routes on the same socket. Run directly, this
// file does nothing.
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import type { TestContext } from 'node:test';
import type { Issuer, IssuerCapabilities, LocationProver, Verifier } from '../../src/ports/issuer.ts';
import type { KeyClass, KeyLocation, KeyShape, Lent, LocationSchema, PlatformKeyId, Scope } from '../../src/ports/types.ts';
import { deliveryRoutes } from '../../src/shell/deliveries.ts';
import { keyRoutes } from '../../src/shell/key-routes.ts';
import type { Route } from '../../src/shell/http.ts';
import { pasteRoutes } from '../../src/shell/paste.ts';
import { openRotation } from '../../src/shell/rotation.ts';
import type { Rotation, RotationDeps } from '../../src/shell/rotation.ts';
import type { PlatformSource, Point } from '../../src/shell/rotation-ports.ts';
import { FakePlatformWorld } from '../fakes/platform.ts';
import { RecordingDestination, RecordingRedeployer } from '../fakes/recording-destination.ts';
import { bytesOf, drive, seededRandom } from '../kit/index.ts';
import { RP, approveWorld, wire } from './approve-world.ts';
import type { WireProof, World } from './approve-world.ts';

/** A route list that is not built yet: each route answers by whatever the list holds when a request comes. Needs only the routes' shape. */
function lateRoutes(shape: readonly Route[], resolve: () => readonly Route[]): Route[] {
  return shape.map((r) => ({
    ...r,
    run: (input) => {
      const real = resolve().find((x) => x.method === r.method && x.path === r.path);
      if (real === undefined) throw new RangeError(`no route ${r.method} ${r.path} wired`);
      return real.run(input);
    },
  }));
}

const classify = (scope: Scope): KeyClass => {
  const items = scope['items'];
  const list = Array.isArray(items) ? items : [];
  return list.includes('master') ? 'master' : list.includes('admin') ? 'admin' : 'ordinary';
};

export const PASTE_PLATFORM = 'pasteco';
const PASTE_SHAPE: KeyShape = { prefix: 'pk-', alphabet: 'hex', coreLength: { min: 32, max: 32 }, random: true };
/** A value the paste platform's strict shape accepts: `pk-` and 32 hex characters. */
export const pasteValue = (hex32: string): string => `pk-${hex32}`;

export interface PasteView {
  readonly verify_hints?: readonly string[];
  readonly verify_hint?: string;
  readonly paste_id: string;
  readonly digest_b64: string;
  readonly nonce_b64: string;
}

export interface RoutesWorld extends World {
  readonly rotation: Rotation;
  readonly platform: FakePlatformWorld;
  readonly destination: RecordingDestination;
  /** The values the paste platform's verifier answers ok for. */
  readonly accepted: Set<string>;
  /** The `at` of every issue call the api platform received, in order. */
  readonly issuedAt: KeyLocation[];
  /** The `at` of every call the paste platform's verifier received, in order. */
  readonly verifiedAt: KeyLocation[];
  /** The `hint` of every call the paste platform's verifier received, in order (undefined: none was given). */
  readonly verifiedHints: (string | undefined)[];
  /** The token that may call the control routes. */
  readonly control: string;
  api(path: string, options?: { readonly method?: string; readonly json?: unknown; readonly bytes?: Uint8Array; readonly contentType?: string }): ReturnType<World['call']>;
  /** A proof over the paste challenge, as the phone would sign it (written again here from KBOX-12, an independent oracle). */
  pasteProof(view: PasteView, forId?: string): WireProof;
}

export interface RoutesWorldOptions {
  /** Where the process may be stopped (`Point`): a checkpoint that throws stands for the process dying there. */
  readonly checkpoint?: (point: Point) => void | Promise<void>;
  /** false: the api platform holds one credential at a time (it can take a chosen value, so its configuration is accepted). */
  readonly overlap?: boolean;
  /** true: the paste platform has no issuer; its entry states the shape and the class (KBOX-40), as Anthropic and Stripe do. */
  readonly pasteOnly?: boolean;
  /** The paste platform entry's `verifyHints` (KBOX-40); none by default. */
  readonly verifyHints?: readonly string[];
  /** Wraps the approvals rotation is given: a fault planted at the port (a sweep or a proposal that throws). */
  readonly approvals?: (real: RotationApprovals) => RotationApprovals;
  /** Wraps the platform source rotation is given: a fault planted at the port. */
  readonly source?: (real: PlatformSource) => PlatformSource;
  /** The location fields the api platform (`fake`) and the paste platform declare (KBOX-57); none by default. */
  readonly location?: LocationSchema;
  /** The api platform's classification at a location, in place of the items-only one (a KBOX-15 floor fixture). */
  readonly classifyAt?: (scope: Scope, at: KeyLocation) => KeyClass;
  /** The prover of a host-naming location (KBOX-57), on both the api and the paste platform; none by default. */
  readonly locationProver?: LocationProver;
}

type RotationApprovals = RotationDeps['approvals'];

export async function routesWorld(t: TestContext, options: RoutesWorldOptions = {}): Promise<RoutesWorld> {
  const random = seededRandom(11);
  const placeholder = {} as never;
  const shape = [...keyRoutes(placeholder), ...deliveryRoutes(placeholder), ...pasteRoutes(placeholder)];
  let routes: readonly Route[] = [];
  const w = await approveWorld(t, { routes: lateRoutes(shape, () => routes) });
  const platform = new FakePlatformWorld(random);
  const destination = new RecordingDestination([]);
  const redeployer = new RecordingRedeployer([]);
  const accepted = new Set<string>();
  const issuedAt: KeyLocation[] = [];
  const verifiedAt: KeyLocation[] = [];
  const verifiedHints: (string | undefined)[] = [];
  const apiClassify = options.classifyAt ?? classify;
  const placed = { ...(options.location === undefined ? {} : { location: options.location }), ...(options.locationProver === undefined ? {} : { locationProver: options.locationProver }), ...(options.verifyHints === undefined ? {} : { verifyHints: options.verifyHints }) };

  const apiIssuer: Issuer = {
    platform: 'fake',
    capabilities: (): IssuerCapabilities => ({ ...platform.issuer.capabilities(), classify: apiClassify, ...(options.overlap === false ? { overlap: false, set: 'api' as const } : {}) }),
    issue: (req, intent, master) => {
      issuedAt.push(req.at);
      return platform.issuer.issue(req, intent, master);
    },
    revoke: (id: PlatformKeyId, master: Lent) => platform.issuer.revoke(id, master),
    ...(options.overlap === false ? { set: (value: Lent, _at: KeyLocation, master: Lent) => platform.set(value, master) } : {}),
  };
  const pasteIssuer: Issuer = {
    platform: PASTE_PLATFORM,
    capabilities: (): IssuerCapabilities => ({
      create: 'paste',
      revoke: 'paste',
      selfRotate: false,
      overlap: true,
      set: 'none',
      revealOnce: false,
      scopeSchema: { fields: ['items'] },
      shape: PASTE_SHAPE,
      classify,
    }),
    issue: () => Promise.reject(new Error('a paste platform cannot issue')),
    revoke: () => Promise.resolve('absent'),
  };
  const pasteVerifier: Verifier = {
    verify: async (key, target) => {
      verifiedAt.push(target.at);
      verifiedHints.push(target.hint);
      return accepted.has(Buffer.from(await bytesOf(key)).toString('utf8')) ? 'ok' : 'rejected';
    },
  };
  const source: PlatformSource = {
    platform: (id) => {
      if (id === 'fake') return { issuer: apiIssuer, lister: platform.lister, verifier: platform.verifier, ...placed };
      if (id === PASTE_PLATFORM && options.pasteOnly === true) return { shape: PASTE_SHAPE, classify, verifier: pasteVerifier, keyPageUrl: 'https://platform.example/keys', ...placed };
      if (id === PASTE_PLATFORM) return { issuer: pasteIssuer, verifier: pasteVerifier, keyPageUrl: 'https://platform.example/keys', ...placed };
      return undefined;
    },
    destination: (kind) => (kind === 'vercel_env' ? { destination, redeployer } : undefined),
    master: () => ({ ok: true, value: platform.master() }),
    masters: () => [{ at: {}, value: platform.master() }],
  };
  const rotation = openRotation({
    parts: w.parts,
    approvals: options.approvals?.(w.core.approvals) ?? w.core.approvals,
    approvalRecords: w.core.approvals,
    approvers: w.core.approvers,
    push: w.push,
    clock: w.clock,
    scheduler: w.clock,
    random,
    audit: w.parts.audit,
    source: options.source?.(source) ?? source,
    ...(options.checkpoint === undefined ? {} : { checkpoint: options.checkpoint }),
  });
  routes = rotation.routes;
  const control = w.token('mission-control', 'control');
  // approveWorld listens on `http.sock` beside its state directory and offers no raw-body call, so this talks to the same socket.
  const raw = drive(join(dirname(w.stateDir), 'http.sock'));

  const api: RoutesWorld['api'] = (path, o = {}) => {
    if (o.bytes !== undefined) {
      return raw.request({
        path,
        method: o.method ?? 'POST',
        headers: { 'x-kb-client-ip': '203.0.113.9', authorization: `Bearer ${control}`, 'content-type': o.contentType ?? 'application/octet-stream' },
        body: o.bytes,
      });
    }
    return w.call(path, { token: control, ...(o.method === undefined ? {} : { method: o.method }), ...(o.json === undefined ? {} : { json: o.json }) });
  };

  const pasteChallenge = (id: string, digest: Uint8Array, nonce: Uint8Array): Uint8Array =>
    Uint8Array.from(createHash('sha256').update('kbox-v1-paste').update(id).update(digest).update(nonce).digest());

  return Object.assign(w, {
    rotation,
    platform,
    destination,
    accepted,
    issuedAt,
    verifiedAt,
    verifiedHints,
    control,
    api,
    pasteProof(view: PasteView, forId?: string): WireProof {
      const nonce = Uint8Array.from(Buffer.from(view.nonce_b64, 'base64url'));
      const digest = Uint8Array.from(Buffer.from(view.digest_b64, 'base64url'));
      return wire(nonce, w.owner.prove(pasteChallenge(forId ?? view.paste_id, digest, nonce), RP));
    },
  });
}

/**
 * A key record holding one retired generation and an empty stored location, put straight into the stores: what a retired generation made by a
 * box rotation looks like, with no route involved (`POST /api/retired` is removed). The key is an `ordinary` one on `platform`.
 */
export function seedRetiredKey(w: RoutesWorld, at: { readonly platform: string; readonly project: string; readonly name: string }, value: string): string {
  const keyref = `${at.platform}/${at.project}/${at.name}`;
  w.parts.meta.putKey({
    keyref,
    platform: at.platform,
    name: at.name,
    projects: [at.project],
    class: 'ordinary',
    status: 'works',
    gen_current: 1,
    schedule: { rotate_every_days: 90, grace_hours: 1, next_due_at: null, expires_at: null },
    coverage: null,
    last_use_at: null,
  });
  w.rotation.store.putKeyInfo(keyref, { scopeItems: [], location: {}, rotatedAt: w.clock.now(), markAdmin: false });
  w.parts.vault.put(keyref, 1, Buffer.from(value));
  w.rotation.store.putGen({ keyref, gen: 1, status: 'retired', platformKeyId: null, location: {} });
  w.parts.vault.retire(keyref, 1);
  return keyref;
}
