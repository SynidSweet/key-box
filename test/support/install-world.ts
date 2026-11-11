// A kb-install world in a temp directory: a running release H0 behind a `current` link, a staging directory core could
// write, a root copy of the approvers (trust.json) with soft approvers, root's code store, a results directory and fake
// units. Proofs are built here from the spec text (KBOX-9: canonical JSON, the `kbox-v1` challenge), so the installer's
// verifier is checked against an independent oracle. Run directly, this file does nothing.
import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, readlinkSync, readdirSync, symlinkSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { TestContext } from 'node:test';
import { softApprover } from '../kit/approver.ts';
import type { Quirks, SoftApprover } from '../kit/approver.ts';
import { FakeClock, tempDir } from '../kit/index.ts';
import { WORDLIST } from './approve-world.ts';
import { createCodeRoot } from '../../src/shell/console.ts';
import type { CodeRoot } from '../../src/shell/console.ts';
import { releaseHash } from '../../src/pure/release-hash.ts';
import { runInstaller } from '../../src/shell/installer.ts';
import type { InstallHooks, InstallPaths, ReleaseUnits } from '../../src/shell/installer.ts';
import type { ApprovalProof, TrustApprover } from '../../src/ports/trust.ts';

export const DOMAIN = 'box.example';
const RP = { rpId: `keys.${DOMAIN}`, origin: `https://keys.${DOMAIN}` } as const;
export const BOOT = 'b0070000-0000-4000-8000-000000000002';
export const COMMIT = 'ab'.repeat(20);

const sha = (...parts: (string | Uint8Array)[]): Buffer => {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
};
const hex = (b: Uint8Array | string): string => sha(b).toString('hex');
const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');

export type Tree = Readonly<Record<string, string | Uint8Array | { readonly body: string | Uint8Array; readonly exec: true }>>;

const bodyOf = (v: Tree[string]): Uint8Array => {
  const body = typeof v === 'object' && 'body' in v ? v.body : v;
  return typeof body === 'string' ? Buffer.from(body) : body;
};
const execOf = (v: Tree[string]): boolean => typeof v === 'object' && 'exec' in v;

/** H of a tree, from release-hash.ts (pinned against an independent vector in update.test.ts). */
export const hashOf = (tree: Tree): string => releaseHash(Object.entries(tree).map(([path, v]) => ({ path, executable: execOf(v), sha256: hex(bodyOf(v)) })));

/** The pinned binaries of a world: fake bytes whose sha256 the lock names. */
export const NODE_BIN = Buffer.from('#!/bin/sh\necho fake node 24\n');
export const CADDY_BIN = Buffer.from('#!/bin/sh\necho fake caddy 2\n');
export const lockFor = (node: Uint8Array, caddy: Uint8Array): string =>
  `# name version arch sha256 url\nnode 24.11.1 arm64 ${hex(node)} https://nodejs.org/dist/v24.11.1/node-v24.11.1-linux-arm64.tar.gz\ncaddy 2.10.2 arm64 ${hex(caddy)} https://github.com/caddyserver/caddy/releases/download/v2.10.2/caddy_2.10.2_linux_arm64.tar.gz\n`;

export const RELEASE_0: Tree = { 'runtime.lock': lockFor(NODE_BIN, CADDY_BIN), 'src/main-core.ts': 'old core\n', 'README.md': 'v0\n' };

/** A kept approval proof (KBOX-9) for an action, signed by `approver` over the `kbox-v1` challenge built here from the spec. */
export function keptProof(approver: SoftApprover, approverId: string, action: object, o: { readonly approvalId?: string; readonly quirks?: Quirks; readonly deviceOf?: SoftApprover } = {}): ApprovalProof {
  const approvalId = o.approvalId ?? `apr_${b64u(randomBytes(12))}`;
  const nonce = Uint8Array.from(randomBytes(32));
  // RFC 8785 restricted to the flat string members these actions have: sorted keys, no whitespace.
  const canonical = `{${Object.entries(action as Record<string, string>)
    .sort(([a], [b]) => (a < b ? -1 : 1))
    .map(([k, v]) => `${JSON.stringify(k)}:${JSON.stringify(v)}`)
    .join(',')}}`;
  const challenge = Uint8Array.from(sha('kbox-v1', approvalId, sha(canonical), nonce));
  const parts = approver.prove(challenge, RP, o.quirks);
  const device = o.deviceOf === undefined ? parts.deviceSignature : o.deviceOf.deviceSign(challenge);
  return {
    approval_id: approvalId,
    approver_id: approverId,
    nonce_b64: b64u(nonce),
    credential_id_b64: b64u(parts.credentialId),
    authenticator_data_b64: b64u(parts.authenticatorData),
    client_data_json_b64: b64u(parts.clientDataJSON),
    signature_b64: b64u(parts.signature),
    device_signature_b64: b64u(device),
  };
}

export interface FakeUnits extends ReleaseUnits {
  readonly restarts: string[];
  /** Whether the next health checks pass. */
  healthy: boolean;
}

export function fakeUnits(current: () => string): FakeUnits {
  const units = {
    restarts: [] as string[],
    healthy: true,
    restart(): Promise<void> {
      units.restarts.push(current());
      return Promise.resolve();
    },
    healthCheck(release: string): Promise<boolean> {
      return Promise.resolve(units.healthy && current() === release);
    },
  };
  return units;
}

export interface InstallWorld {
  readonly root: string;
  readonly paths: InstallPaths;
  readonly h0: string;
  readonly owner: SoftApprover;
  readonly ownerId: string;
  readonly clock: FakeClock;
  readonly units: FakeUnits;
  readonly codes: CodeRoot;
  readonly console: string[];
  /** Writes a tree to staging/<H>/ and returns H. */
  stage(tree: Tree, name?: string): string;
  /** A kept approval proof for an action, signed by an approver (the owner by default) over the `kbox-v1` challenge. */
  proof(action: object, options?: { readonly approver?: SoftApprover; readonly approverId?: string; readonly approvalId?: string; readonly quirks?: Quirks; readonly deviceOf?: SoftApprover }): ApprovalProof;
  /** Writes staging/<name>.request with the given JSON. */
  request(name: string, body: unknown): void;
  /** The install request core would write for H over the running release. */
  installRequest(h: string, proof?: ApprovalProof | 'none', base?: string): void;
  run(hooks?: InstallHooks): Promise<void>;
  result(name: string): string | undefined;
  current(): string;
  releases(): string[];
  /** trust.json as it stands, or undefined. */
  trust(): { domain: string; approvers: TrustApprover[] } | undefined;
  writeTrust(approvers: readonly { readonly id: string; readonly a: SoftApprover }[]): void;
  trusted(id: string, a: SoftApprover): TrustApprover;
}

export async function installWorld(t: TestContext, options: { readonly trust?: false } = {}): Promise<InstallWorld> {
  const root = await tempDir(t);
  const paths: InstallPaths = {
    staging: join(root, 'var/lib/keybox/staging'),
    releases: join(root, 'opt/keybox/releases'),
    current: join(root, 'opt/keybox/current'),
    trustFile: join(root, 'etc/keybox/trust.json'),
    codesDir: join(root, 'etc/keybox/codes'),
    results: join(root, 'var/lib/keybox-install'),
    bootIdFile: join(root, 'boot_id'),
  };
  for (const dir of [paths.staging, paths.releases, join(root, 'etc/keybox'), paths.results]) mkdirSync(dir, { recursive: true });
  writeFileSync(paths.bootIdFile, `${BOOT}\n`);
  const clock = new FakeClock(1_700_000_000_000);
  const consoleLines: string[] = [];
  const codes = createCodeRoot({ dir: paths.codesDir, sink: (l) => void consoleLines.push(l), random: { bytes: (n) => Uint8Array.from(randomBytes(n)) }, clock, wordlist: WORDLIST });

  const writeTree = (dir: string, tree: Tree): void => {
    for (const [path, v] of Object.entries(tree)) {
      const file = join(dir, path);
      mkdirSync(join(file, '..'), { recursive: true });
      writeFileSync(file, bodyOf(v), { mode: execOf(v) ? 0o755 : 0o644 });
    }
  };
  const h0 = hashOf(RELEASE_0);
  const r0 = join(paths.releases, h0);
  writeTree(r0, RELEASE_0);
  writeTree(r0, { 'bin/node': { body: NODE_BIN, exec: true }, 'bin/caddy': { body: CADDY_BIN, exec: true } });
  symlinkSync(r0, paths.current);
  const current = (): string => readlinkSync(paths.current).split('/').at(-1) ?? '';
  const units = fakeUnits(current);

  const owner = softApprover();
  const ownerId = 'ap-owner-00001';
  const trusted = (id: string, a: SoftApprover): TrustApprover => ({ id, cose_b64: b64u(a.coseKey), device_pub_b64: b64u(a.devicePublicKey) });
  const writeTrust: InstallWorld['writeTrust'] = (list) =>
    writeFileSync(paths.trustFile, JSON.stringify({ domain: DOMAIN, approvers: list.map((x) => trusted(x.id, x.a)) }));
  if (options.trust !== false) writeTrust([{ id: ownerId, a: owner }]);

  const world: InstallWorld = {
    root,
    paths,
    h0,
    owner,
    ownerId,
    clock,
    units,
    codes,
    console: consoleLines,
    stage(tree, name) {
      const h = hashOf(tree);
      writeTree(join(paths.staging, name ?? h), tree);
      return h;
    },
    proof: (action, o = {}) => keptProof(o.approver ?? owner, o.approverId ?? ownerId, action, o),
    request(name, body) {
      writeFileSync(join(paths.staging, `${name}.request`), JSON.stringify(body));
    },
    installRequest(h, proof, base = h0) {
      const approval = proof === 'none' ? undefined : (proof ?? world.proof({ kind: 'install_update', install: h, commit: COMMIT, base }));
      world.request(h, { kind: 'install', install: h, commit: COMMIT, base, ...(approval === undefined ? {} : { approval }) });
    },
    run: (hooks) => runInstaller({ paths, units, clock, wordlist: WORDLIST, ...(hooks === undefined ? {} : { hooks }) }).then(() => undefined),
    result(name) {
      const file = join(paths.results, `${name}.result`);
      return existsSync(file) ? readFileSync(file, 'utf8') : undefined;
    },
    current,
    releases: () => readdirSync(paths.releases).sort(),
    trust() {
      return existsSync(paths.trustFile) ? (JSON.parse(readFileSync(paths.trustFile, 'utf8')) as { domain: string; approvers: TrustApprover[] }) : undefined;
    },
    writeTrust,
    trusted,
  };
  return world;
}

/** The signed approver_add for a new approver's keys (spec revision 4): lowercase hex SHA-256 of each public key's bytes. */
export const addActionOf = (a: TrustApprover): { readonly kind: 'approver_add'; readonly cose_sha256: string; readonly device_sha256: string } => ({
  kind: 'approver_add',
  cose_sha256: hex(Buffer.from(a.cose_b64, 'base64url')),
  device_sha256: hex(Buffer.from(a.device_pub_b64, 'base64url')),
});

export { hex as sha256Hex };
