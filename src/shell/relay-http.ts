// KBOX-13, KBOX-14, KBOX-32, KBOX-43: kb-relay's HTTP side, on its own unix socket behind Caddy. Each request is read once
// at the edge (client address, pass, target, method, headers), checked against the key's profile, lent its value by core
// for that one call, sent upstream through the egress gate, and answered through core's scanner: no byte leaves before the
// scanner says it cannot belong to a value or a credential, and a cut stream ends with no tail. Nothing of a request,
// a value or an upstream body is ever logged; the journal gets fixed codes only.
import { chmodSync, rmSync } from 'node:fs';
import { createServer, request as httpRequest } from 'node:http';
import type { IncomingHttpHeaders, IncomingMessage, OutgoingHttpHeaders, ServerResponse } from 'node:http';
import type { Duplex } from 'node:stream';
import type { PlatformEntry } from '../ports/platform.ts';
import type { RelayProfile } from '../ports/relay-profile.ts';
import { parseClientAddress } from '../pure/address.ts';
import type { ClientAddress } from '../pure/address.ts';
import type { LendRefusal, RelayAuditRow } from '../pure/lend-protocol.ts';
import { DEFAULT_REQUEST_HEADERS, DEFAULT_RESPONSE_HEADERS, assertRegistry, compileProfile } from '../pure/profile.ts';
import type { ProfileEngine } from '../pure/profile.ts';
import { FORCED_RESPONSE_HEADERS, METHOD_OVERRIDE_HEADERS, RELAY_ERRORS, relayErrorBody, upstreamRefusedBody } from '../pure/relay-errors.ts';
import type { RelayErrorCode } from '../pure/relay-errors.ts';
import { HTTP_METHODS, LABEL, NAME } from '../pure/schemas.ts';
import { canonicalPath, canonicalQuery, parseRelayTarget } from '../pure/target-parse.ts';
import type { RelayTarget } from '../pure/target-parse.ts';
import { hashToken, parsePass } from '../pure/tokens.ts';
import { EgressRefused } from './egress.ts';
import type { Egress } from './egress.ts';
import { LendUnavailable } from './lend-socket.ts';
import type { LendClient, ScanSession } from './lend-socket.ts';

/** Request bodies up to 32 MiB are relayed; larger ones are 413 (KBOX-13 step 7). */
export const REQUEST_BODY_LIMIT = 32 * 1024 * 1024;
const GRANTS_PATH = '/r/_/grants';
/** Methods whose empty body is still declared as `Content-Length: 0`. */
const BODY_METHODS: ReadonlySet<string> = new Set(['POST', 'PUT', 'PATCH']);

export interface RelayDeps {
  readonly registry: readonly PlatformEntry[];
  readonly lend: LendClient;
  readonly egress: Egress;
  /** The box's domain: the relay URL of a key is `https://api.keys.<domain>/r/<keyref>`. Absent until the bootstrap sets it: then /r/_/grants is unavailable. */
  readonly domain: string | undefined;
  /** A fixed code when the relay itself could not do its job. Never text of a request, a value or an answer. */
  readonly journal: (code: string) => void;
}

export interface RelayServer {
  listen(socketPath: string): Promise<void>;
  stop(): Promise<void>;
}

/** Every host a registered relay profile names: the egress gate's adapter hosts for relay calls. */
export const adapterHostsOf = (registry: readonly PlatformEntry[]): string[] =>
  registry.flatMap((e) => (e.relay === undefined ? [] : e.relay.origin.kind === 'fixed' ? [e.relay.origin.host] : [...e.relay.origin.hosts]));

/** A refusal at any step: the code decides the answer. */
class Refused extends Error {
  readonly code: RelayErrorCode;
  readonly reason: RelayAuditRow['reason'];

  constructor(code: RelayErrorCode, reason?: RelayAuditRow['reason']) {
    super(`relay refused: ${code}`);
    this.name = 'Refused';
    this.code = code;
    this.reason = reason;
  }
}

/** Core could not be asked: the pass is neither confirmed nor refused, and the audit row that would follow cannot be written either. */
class CoreUnreachable extends Refused {
  constructor() {
    super('unavailable');
  }
}

/** A refusal core gave for a pass. `forbidden` means core knows the pass and refused the key or the machine, so the request is audited. */
function refusedFor(code: LendRefusal, trace: Trace): Refused {
  if (code === 'forbidden') trace.confirmed = true;
  return new Refused(code === 'bad_token' ? 'bad_token' : 'forbidden');
}

/** What one request leaves for the audit row; filled in as the request goes. */
interface Trace {
  route: RelayAuditRow['route'];
  method: RelayAuditRow['method'];
  label?: string;
  keyref?: string;
  ruleId?: string;
  source?: string;
  agent?: string;
  project?: string;
  status: number;
  bytes: number;
  code?: string;
  reason?: RelayAuditRow['reason'];
  /** Core confirmed the pass (or knew it and refused the key): only then is the request audited. */
  confirmed: boolean;
}

const one = (headers: IncomingHttpHeaders, name: string): string | undefined => {
  const value = headers[name];
  return Array.isArray(value) ? value.join(', ') : value;
};

const errorHeaders = (length: number): OutgoingHttpHeaders => ({ ...FORCED_RESPONSE_HEADERS, 'content-type': 'application/json; charset=utf-8', 'content-length': length, 'cache-control': 'no-store' });

function sendJson(res: ServerResponse, status: number, body: string): void {
  const payload = Buffer.from(body, 'utf8');
  res.writeHead(status, errorHeaders(payload.length));
  res.end(payload);
}

async function readBody(req: IncomingMessage): Promise<Buffer> {
  const declared = one(req.headers, 'content-length');
  if (declared !== undefined && (!/^\d{1,15}$/.test(declared) || Number(declared) > REQUEST_BODY_LIMIT)) throw new Refused(/^\d{1,15}$/.test(declared) ? 'too_large' : 'bad_request');
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const piece = chunk as Buffer;
    total += piece.length;
    if (total > REQUEST_BODY_LIMIT) throw new Refused('too_large');
    chunks.push(piece);
  }
  return Buffer.concat(chunks);
}

/** The forwarded request headers: the defaults and the profile's list, each checked against its words. */
function forwardedHeaders(profile: RelayProfile, headers: IncomingHttpHeaders): Headers {
  const out = new Headers();
  for (const name of [...DEFAULT_REQUEST_HEADERS, ...profile.requestHeaders]) {
    const value = one(headers, name);
    if (value === undefined) continue;
    const words = Object.hasOwn(profile.headerWords, name) ? profile.headerWords[name] : undefined;
    if (words !== undefined && !words.includes(value)) throw new Refused('forbidden');
    out.set(name, value);
  }
  return out;
}

/** The upstream response headers the caller may see, in upstream order, and their wire text for the scanner. */
function passedHeaders(profile: RelayProfile, upstream: IncomingMessage): { readonly headers: [string, string][]; readonly block: Buffer } {
  const allowed = new Set([...DEFAULT_RESPONSE_HEADERS, ...profile.responseHeaders]);
  const status = upstream.statusCode ?? 0;
  if (status >= 300 && status < 400) allowed.add('location');
  const headers: [string, string][] = [];
  const raw = upstream.rawHeaders;
  for (let i = 0; i + 1 < raw.length; i += 2) {
    const name = (raw[i] ?? '').toLowerCase();
    if (allowed.has(name)) headers.push([name, raw[i + 1] ?? '']);
  }
  const block = Buffer.from(`${headers.map(([n, v]) => `${n}: ${v}\r\n`).join('')}\r\n`, 'latin1');
  return { headers, block };
}

const IDENTITY = /^\s*identity\s*$/i;
const CHUNKED = /^\s*chunked\s*$/i;

/** A body the scanner cannot see inside (KBOX-14): any `Content-Encoding` but identity, and any `Transfer-Encoding` but exactly `chunked` (which the HTTP layer decodes). */
function isEncoded(headers: IncomingHttpHeaders): boolean {
  const content = one(headers, 'content-encoding');
  const transfer = one(headers, 'transfer-encoding');
  return (content !== undefined && !IDENTITY.test(content)) || (transfer !== undefined && !CHUNKED.test(transfer));
}

/** Writes one piece of the answer. False when the caller went away, including while the write waited for the caller to read. */
async function writeToCaller(res: ServerResponse, piece: Buffer): Promise<boolean> {
  if (res.destroyed) return false;
  if (res.write(piece)) return true;
  await new Promise<void>((resolve) => {
    const done = (): void => {
      res.off('drain', done);
      res.off('close', done);
      resolve();
    };
    res.once('drain', done);
    res.once('close', done);
  });
  return !res.destroyed;
}

/** How the upstream body ended: read through, a hit, a stream that broke or stopped short of its framing, or a caller who left. */
type Drained = { readonly kind: 'ended' | 'broken' | 'gone' } | { readonly kind: 'hit'; readonly reason: RelayAuditRow['reason'] };

export function createRelayServer(deps: RelayDeps): RelayServer {
  assertRegistry(deps.registry);
  const engines = new Map<string, ProfileEngine>();
  for (const entry of deps.registry) {
    if (entry.relay === undefined) continue;
    const compiled = compileProfile(entry.relay);
    if (compiled.ok) engines.set(entry.id, compiled.engine);
  }
  const stopping = new AbortController();
  const inflight = new Set<Promise<void>>();

  /** Steps 1 and 2: the pass from the profile's headers, checked by core. */
  const passOf = (req: IncomingMessage): { readonly token: string; readonly carriers: readonly string[] } => {
    const parsed = parsePass(one(req.headers, 'authorization'), one(req.headers, 'apikey'));
    if (parsed.kind === 'mismatch') throw new Refused('bad_request');
    if (parsed.kind !== 'pass') throw new Refused('bad_token');
    return parsed;
  };

  async function grants(req: IncomingMessage, res: ServerResponse, trace: Trace, source: ClientAddress): Promise<void> {
    trace.route = 'grants';
    const domain = deps.domain;
    if (domain === undefined) throw new Refused('unavailable');
    if (req.method !== 'GET') throw new Refused('not_found');
    const pass = passOf(req);
    const answer = await deps.lend.grants({ op: 'grants', token_hash: hashToken(pass.token), network: source.network });
    if (!answer.ok) throw refusedFor(answer.code, trace);
    trace.confirmed = true;
    trace.label = answer.machine;
    const list = answer.grants.map((g) => {
      const relayUrl = `https://api.keys.${domain}/r/${g.keyref}`;
      const profile = engines.get(g.platform)?.profile;
      return { keyref: g.keyref, platform: g.platform, name: g.name, projects: g.projects, env: profile === undefined ? {} : profile.envForClients(relayUrl) };
    });
    trace.status = 200;
    sendJson(res, 200, JSON.stringify({ machine: answer.machine, grants: list }));
  }

  /** Steps 1 to 6: everything that is decided before upstream is called. */
  async function admit(req: IncomingMessage, trace: Trace, source: ClientAddress, target: RelayTarget) {
    trace.route = 'relay';
    trace.keyref = target.keyref;
    const pass = passOf(req);
    const tokenHash = hashToken(pass.token);
    const resolved = await deps.lend.resolve({ op: 'resolve', token_hash: tokenHash, keyref: target.keyref, network: source.network });
    if (!resolved.ok) throw refusedFor(resolved.code, trace);
    trace.confirmed = true;
    trace.label = resolved.label;
    const engine = engines.get(resolved.platform);
    if (engine === undefined) throw new Refused('forbidden');
    if (!pass.carriers.every((h) => (engine.profile.callerTokenHeaders as readonly string[]).includes(h))) throw new Refused('bad_token');
    if (METHOD_OVERRIDE_HEADERS.some((h) => req.headers[h] !== undefined)) throw new Refused('method_override');
    const decision = engine.decide(req.method ?? '', target);
    if (!decision.ok) throw new Refused('forbidden');
    trace.ruleId = decision.rule.id;
    const headers = forwardedHeaders(engine.profile, req.headers);
    const body = await readBody(req);
    return { engine, decision, headers, body, tokenHash };
  }

  async function relay(req: IncomingMessage, res: ServerResponse, trace: Trace, source: ClientAddress, target: RelayTarget, abort: AbortSignal): Promise<void> {
    const { engine, decision, headers, body, tokenHash } = await admit(req, trace, source, target);
    const lent = await deps.lend.lend({ op: 'lend', token_hash: tokenHash, keyref: target.keyref, rule_id: decision.rule.id });
    if (!lent.ok) throw new Refused(lent.code === 'bad_token' ? 'bad_token' : 'forbidden');
    headers.set('accept-encoding', 'identity');
    if (body.length > 0 || BODY_METHODS.has(req.method ?? '')) headers.set('content-length', String(body.length));
    headers.set('host', decision.request.host);
    await engine.profile.inject(headers, lent.value);
    const opened = await deps.lend.scan({ op: 'scan', token_hash: tokenHash, keyref: target.keyref });
    if (!opened.ok) throw new Refused('forbidden');
    const scan = opened.session;
    try {
      const query = canonicalQuery(decision.request.query);
      const path = `${canonicalPath(decision.request.segments)}${query === '' ? '' : `?${query}`}`;
      const upstream = await callUpstream(decision.request.host, req.method ?? 'GET', path, headers, body, abort);
      await answer(res, engine.profile, upstream, scan, trace);
    } finally {
      scan.close();
    }
  }

  async function callUpstream(host: string, method: string, path: string, headers: Headers, body: Buffer, abort: AbortSignal): Promise<IncomingMessage> {
    let socket: Duplex;
    try {
      socket = await deps.egress.open('relay', new URL(`https://${host}/`), abort);
    } catch (error) {
      if (error instanceof EgressRefused) throw new Refused(error.code === 'connect_timeout' ? 'upstream_timeout' : 'upstream_unreachable');
      throw error;
    }
    return new Promise((resolve, reject) => {
      const outgoing: OutgoingHttpHeaders = Object.fromEntries(headers.entries());
      const call = httpRequest({ method, path, headers: outgoing, setHost: false, createConnection: () => socket, signal: abort }, resolve);
      call.on('error', () => reject(new Refused('upstream_unreachable')));
      call.end(body);
    });
  }

  /** Step 8: the response through the scanner. Headers and body are one stream; the head is sent once its bytes are released. */
  async function answer(res: ServerResponse, profile: RelayProfile, upstream: IncomingMessage, scan: ScanSession, trace: Trace): Promise<void> {
    const status = upstream.statusCode ?? 502;
    if (status === 206 || upstream.headers['content-range'] !== undefined) {
      upstream.destroy();
      throw new Refused('withheld', 'partial');
    }
    if (isEncoded(upstream.headers)) {
      upstream.destroy();
      throw new Refused('withheld', 'encoded');
    }
    if (status === 401 || status === 403) {
      upstream.destroy();
      trace.status = status;
      trace.reason = 'upstream_refused';
      sendJson(res, status, upstreamRefusedBody());
      return;
    }
    const { headers, block } = passedHeaders(profile, upstream);
    const held: Buffer[] = [];
    let fed = 0;
    let written = 0;
    let headSent = false;
    held.push(block);
    /** Sends what the scanner has released; false when the caller went away. */
    const release = async (upTo: number): Promise<boolean> => {
      if (!headSent && upTo >= block.length) {
        res.writeHead(status, [...headers, ...Object.entries(FORCED_RESPONSE_HEADERS)]);
        headSent = true;
        trace.status = status;
        written = block.length;
        held.splice(0, 1);
      }
      if (!headSent) return true;
      while (written < upTo) {
        const first = held[0];
        if (first === undefined) break;
        const take = Math.min(first.length, upTo - written);
        const piece = first.subarray(0, take);
        held[0] = first.subarray(take);
        if (held[0].length === 0) held.shift();
        written += take;
        trace.bytes += take;
        if (!(await writeToCaller(res, piece))) return false;
      }
      return true;
    };
    const cut = (code: RelayErrorCode, reason?: RelayAuditRow['reason']): void => {
      held.length = 0;
      upstream.destroy();
      trace.code = code;
      if (reason !== undefined) trace.reason = reason;
      if (headSent) res.destroy();
      else throw new Refused(code, reason);
    };

    const head = await scan.feed(block);
    fed = block.length;
    /** The body read to its end; it stops at the first hit, without waiting for upstream's next chunk. */
    const drain = async (): Promise<Drained> => {
      let step = head;
      if (step.kind === 'hit') return { kind: 'hit', reason: step.reason };
      try {
        for await (const chunk of upstream) {
          const piece = chunk as Buffer;
          held.push(piece);
          fed += piece.length;
          step = await scan.feed(piece);
          if (step.kind === 'hit') return { kind: 'hit', reason: step.reason };
          if (!(await release(step.releasable))) return { kind: 'gone' };
        }
      } catch (error) {
        if (!(error instanceof Error)) throw error;
        return { kind: 'broken' };
      }
      return { kind: upstream.complete ? 'ended' : 'broken' };
    };
    const drained = await drain();
    if (drained.kind === 'hit') return cut('withheld', drained.reason);
    if (drained.kind !== 'ended') return cut('upstream_unreachable');
    const last = await scan.end();
    if (last.kind === 'hit') return cut('withheld', last.reason);
    if (!(await release(fed))) return cut('upstream_unreachable');
    res.end();
  }

  async function serve(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const trace: Trace = { route: 'unmatched', method: HTTP_METHODS.find((m) => m === req.method) ?? 'OTHER', status: 500, bytes: 0, confirmed: false };
    const gone = new AbortController();
    res.on('close', () => {
      if (!res.writableFinished) gone.abort();
    });
    const abort = AbortSignal.any([gone.signal, stopping.signal]);
    const refused = await attempt(() => route(req, res, trace, abort));
    if (refused !== undefined) {
      trace.code = refused.code;
      if (refused.reason !== undefined) trace.reason = refused.reason;
      trace.status = RELAY_ERRORS[refused.code].status;
      if (!res.headersSent) sendJson(res, trace.status, relayErrorBody(refused.code));
      else res.destroy();
    }
    if (refused !== undefined && !trace.confirmed && !(refused instanceof CoreUnreachable)) {
      // KBOX-50: a caller core did not vouch for leaves no row, which the internet could otherwise grow; the journal gets the fixed code.
      deps.journal(`pre_auth_${refused.code}`);
      return;
    }
    const audited = await auditOnce(auditRow(trace));
    if (audited !== 'audited') deps.journal(audited);
  }

  /** A failed step as its refusal; anything not a refusal is journalled by a fixed code and answered as internal. */
  async function attempt(job: () => Promise<void>): Promise<Refused | undefined> {
    try {
      await job();
    } catch (error) {
      return refusalOf(error);
    }
    return undefined;
  }

  function refusalOf(error: unknown): Refused {
    if (error instanceof Refused) return error;
    if (error instanceof LendUnavailable) {
      deps.journal('lend_unavailable');
      return new CoreUnreachable();
    }
    deps.journal('relay_failed');
    return new Refused('internal');
  }

  async function auditOnce(row: RelayAuditRow): Promise<'audited' | 'audit_unavailable'> {
    try {
      await deps.lend.audit(row);
    } catch (error) {
      if (error instanceof LendUnavailable) return 'audit_unavailable';
      throw error;
    }
    return 'audited';
  }

  async function route(req: IncomingMessage, res: ServerResponse, trace: Trace, abort: AbortSignal): Promise<void> {
    if (req.headers.origin !== undefined || req.headers.cookie !== undefined) throw new Refused('browser_call');
    const source = parseClientAddress(one(req.headers, 'x-kb-client-ip'));
    if (source === undefined) throw new Refused('bad_request');
    trace.source = source.address;
    const agent = one(req.headers, 'x-agent');
    const project = one(req.headers, 'x-project');
    if (agent !== undefined && LABEL.test(agent)) trace.agent = agent;
    if (project !== undefined && NAME.test(project)) trace.project = project;
    const url = req.url ?? '';
    if (url === GRANTS_PATH) return grants(req, res, trace, source);
    const target = parseRelayTarget(url);
    if (target.ok) return relay(req, res, trace, source, target.value, abort);
    if (target.code !== 'not_found') passOf(req);
    throw new Refused(target.code);
  }

  const server = createServer({ requireHostHeader: false }, (req, res) => {
    const job = serve(req, res);
    inflight.add(job);
    void job.finally(() => inflight.delete(job));
  });

  return {
    async listen(socketPath) {
      rmSync(socketPath, { force: true });
      await new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        server.listen(socketPath, () => {
          server.off('error', reject);
          resolve();
        });
      });
      chmodSync(socketPath, 0o660);
    },
    async stop() {
      stopping.abort();
      await Promise.allSettled([...inflight]);
      server.closeAllConnections();
      if (!server.listening) return;
      await new Promise<void>((resolve, reject) => server.close((error) => (error === undefined ? resolve() : reject(error))));
    },
  };
}

function auditRow(trace: Trace): RelayAuditRow {
  return {
    route: trace.route,
    method: trace.method,
    status: trace.status,
    bytes: trace.bytes,
    ...(trace.label === undefined ? {} : { label: trace.label }),
    ...(trace.keyref === undefined ? {} : { keyref: trace.keyref }),
    ...(trace.ruleId === undefined ? {} : { rule_id: trace.ruleId }),
    ...(trace.source === undefined ? {} : { source: trace.source }),
    ...(trace.agent === undefined ? {} : { agent: trace.agent }),
    ...(trace.project === undefined ? {} : { project: trace.project }),
    ...(trace.code === undefined ? {} : { code: trace.code }),
    ...(trace.reason === undefined ? {} : { reason: trace.reason }),
  };
}
