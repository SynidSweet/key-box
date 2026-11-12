// The approval half of core (approveWorld) with the rotation unit wired in beside it: one fake API platform that issues keys, one paste platform
// whose verifier accepts the values a test names, a recording destination, and the rotation routes on the same socket. Run directly, this
// file does nothing.
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import type { TestContext } from 'node:test';
import type { Issuer, IssuerCapabilities, Verifier } from '../../src/ports/issuer.ts';
import type { KeyClass, KeyLocation, KeyShape, Lent, PlatformKeyId, Scope } from '../../src/ports/types.ts';
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
  /** Wraps the approvals rotation is given: a fault planted at the port (a sweep or a proposal that throws). */
  readonly approvals?: (real: RotationApprovals) => RotationApprovals;
  /** Wraps the platform source rotation is given: a fault planted at the port. */
  readonly source?: (real: PlatformSource) => PlatformSource;
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

  const apiIssuer: Issuer = {
    platform: 'fake',
    capabilities: (): IssuerCapabilities => ({ ...platform.issuer.capabilities(), classify, ...(options.overlap === false ? { overlap: false, set: 'api' as const } : {}) }),
    issue: (req, intent, master) => platform.issuer.issue(req, intent, master),
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
    verify: async (key) => (accepted.has(Buffer.from(await bytesOf(key)).toString('utf8')) ? 'ok' : 'rejected'),
  };
  const source: PlatformSource = {
    platform: (id) => {
      if (id === 'fake') return { issuer: apiIssuer, lister: platform.lister, verifier: platform.verifier };
      if (id === PASTE_PLATFORM && options.pasteOnly === true) return { shape: PASTE_SHAPE, classify, verifier: pasteVerifier, keyPageUrl: 'https://platform.example/keys' };
      if (id === PASTE_PLATFORM) return { issuer: pasteIssuer, verifier: pasteVerifier, keyPageUrl: 'https://platform.example/keys' };
      return undefined;
    },
    destination: (kind) => (kind === 'vercel_env' ? { destination, redeployer } : undefined),
    master: () => platform.master(),
  };
  const rotation = openRotation({
    parts: w.parts,
    approvals: options.approvals?.(w.core.approvals) ?? w.core.approvals,
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
    control,
    api,
    pasteProof(view: PasteView, forId?: string): WireProof {
      const nonce = Uint8Array.from(Buffer.from(view.nonce_b64, 'base64url'));
      const digest = Uint8Array.from(Buffer.from(view.digest_b64, 'base64url'));
      return wire(nonce, w.owner.prove(pasteChallenge(forId ?? view.paste_id, digest, nonce), RP));
    },
  });
}
