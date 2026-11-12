// KBOX-47: the one module every outbound request of core and relay goes through. It checks the host against the declared
// lists for the caller, resolves the name once, refuses any private address in the answer and connects to the first address
// it got, so a second lookup can never move the connection. The resolver and connector are ports; production uses DNS and TLS
// offering only HTTP/1.1 (no `h2`, so no multiplexed or trailer-bearing framing). The connect timeout is 10 s; there is none
// after that, so streams are not cut.
import { lookup } from 'node:dns/promises';
import { connect as tlsConnect } from 'node:tls';
import type { Duplex } from 'node:stream';
import type { Scheduler } from '../ports/clock.ts';
import { addressRefused, hostVerdict } from '../pure/egress-policy.ts';
import type { Caller, EgressHost } from '../pure/egress-policy.ts';

export type { Caller } from '../pure/egress-policy.ts';

export const CONNECT_TIMEOUT_MS = 10_000;
/** The only application protocol offered upstream. */
export const UPSTREAM_ALPN: readonly string[] = ['http/1.1'];

export type EgressCode = 'bad_url' | 'undeclared_host' | 'wrong_caller' | 'resolve_failed' | 'private_address' | 'connect_failed' | 'connect_timeout';

/** A refusal or failure of the gate: a fixed code, never the host or the address. */
export class EgressRefused extends Error {
  readonly code: EgressCode;

  constructor(code: EgressCode, options?: ErrorOptions) {
    super(`egress refused: ${code}`, options);
    this.name = 'EgressRefused';
    this.code = code;
  }
}

export interface Resolver {
  /** Every address the name has, in the resolver's order. */
  resolve(host: string): Promise<readonly string[]>;
}

export interface ConnectTarget {
  readonly address: string;
  readonly port: number;
  /** The name the TLS certificate must carry. */
  readonly servername: string;
}

export interface Connector {
  /** A connected stream; rejects when the connection fails or `signal` aborts. */
  connect(target: ConnectTarget, signal: AbortSignal): Promise<Duplex>;
}

export interface Egress {
  open(caller: Caller, url: URL, signal: AbortSignal): Promise<Duplex>;
}

export interface EgressDeps {
  /** The relay profiles' hosts: served to caller `relay` and caller `adapter`. */
  readonly adapterHosts: readonly string[];
  /** The registry entries' own hosts (`PlatformEntry.hosts`): served to caller `adapter` only. */
  readonly registryHosts?: readonly string[];
  readonly listed: readonly EgressHost[];
  readonly resolver: Resolver;
  readonly connector: Connector;
  readonly scheduler: Scheduler;
}

export const systemResolver: Resolver = {
  resolve: async (host) => (await lookup(host, { all: true, verbatim: true })).map((a) => a.address),
};

/** TLS with certificate checks against the host name; `ca` replaces the system roots (tests only). */
export function createTlsConnector(options: { readonly ca?: string } = {}): Connector {
  return {
    connect: (target, signal) =>
      new Promise((resolve, reject) => {
        const socket = tlsConnect({
          host: target.address,
          port: target.port,
          servername: target.servername,
          ALPNProtocols: [...UPSTREAM_ALPN],
          ...(options.ca === undefined ? {} : { ca: options.ca }),
        });
        const fail = (error: Error): void => {
          socket.destroy();
          reject(error);
        };
        const onAbort = (): void => fail(new Error('connect aborted'));
        signal.addEventListener('abort', onAbort, { once: true });
        socket.once('error', fail);
        socket.once('secureConnect', () => {
          signal.removeEventListener('abort', onAbort);
          socket.off('error', fail);
          resolve(socket);
        });
      }),
  };
}

export function createEgress(deps: EgressDeps): Egress {
  const resolveOnce = async (host: string): Promise<string> => {
    let answers: readonly string[];
    try {
      answers = await deps.resolver.resolve(host);
    } catch (cause) {
      throw new EgressRefused('resolve_failed', { cause });
    }
    const first = answers[0];
    if (first === undefined) throw new EgressRefused('resolve_failed');
    if (answers.some(addressRefused)) throw new EgressRefused('private_address');
    return first;
  };

  const connectInTime = (target: ConnectTarget, signal: AbortSignal): Promise<Duplex> => {
    const attempt = new AbortController();
    let timedOut = false;
    const cancel = deps.scheduler.after(CONNECT_TIMEOUT_MS, () => {
      timedOut = true;
      attempt.abort();
    });
    const onAbort = (): void => attempt.abort();
    signal.addEventListener('abort', onAbort, { once: true });
    return deps.connector.connect(target, attempt.signal).then(
      (socket) => {
        cancel();
        signal.removeEventListener('abort', onAbort);
        if (attempt.signal.aborted) {
          socket.destroy();
          throw new EgressRefused(timedOut ? 'connect_timeout' : 'connect_failed');
        }
        return socket;
      },
      (cause: unknown) => {
        cancel();
        signal.removeEventListener('abort', onAbort);
        throw new EgressRefused(timedOut ? 'connect_timeout' : 'connect_failed', { cause });
      },
    );
  };

  return {
    async open(caller, url, signal) {
      if (url.protocol !== 'https:' || url.port !== '' || url.username !== '' || url.password !== '') throw new EgressRefused('bad_url');
      const verdict = hostVerdict(caller, url.hostname, deps.adapterHosts, deps.listed, deps.registryHosts);
      if (verdict !== 'allowed') throw new EgressRefused(verdict);
      const address = await resolveOnce(url.hostname);
      return connectInTime({ address, port: 443, servername: url.hostname }, signal);
    },
  };
}
