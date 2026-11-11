// A started core frame on a unix socket in a temp directory: the same parts main-core wires, a TimedClock, and tokens to call it with.
import { join } from 'node:path';
import type { TestContext } from 'node:test';
import type { TokenScope, TokenStore } from '../../src/ports/meta.ts';
import { hashToken, newToken } from '../../src/pure/tokens.ts';
import { openCore } from '../../src/shell/core.ts';
import type { CoreParts } from '../../src/shell/core.ts';
import { createApiServer } from '../../src/shell/http.ts';
import type { Route } from '../../src/shell/http.ts';
import { drive } from './drive.ts';
import type { DriveReply, Driver } from './drive.ts';
import { TimedClock } from './timed-clock.ts';
import { seededRandom } from './random.ts';
import { tempDir } from './temp.ts';

export interface CoreOptions {
  /** Routes added to the real control routes (the tests' own routes). */
  readonly extraRoutes?: readonly Route[];
  /** A decorator over the token store the server sees, for tests that count lookups. */
  readonly tokenStore?: (real: TokenStore) => TokenStore;
  /** Reuse a state directory (a restart); a fresh one otherwise. */
  readonly stateDir?: string;
  readonly seed?: number;
}

export interface CallOptions {
  readonly method?: string;
  readonly body?: string | Uint8Array;
  readonly headers?: Readonly<Record<string, string>>;
  /** The X-KB-Client-Ip header; the default is a documentation address. Pass null to send none. */
  readonly ip?: string | null;
  /** Send this bearer token. */
  readonly token?: string;
  readonly json?: boolean;
}

export interface RunningCore extends CoreParts {
  readonly stateDir: string;
  readonly socket: string;
  readonly clock: TimedClock;
  readonly journal: readonly string[];
  readonly driver: Driver;
  /** Enrols a machine and returns its token. */
  enrol(label: string, scope: TokenScope): string;
  call(path: string, options?: CallOptions): Promise<DriveReply>;
  stop(): Promise<void>;
}

export async function startCore(t: TestContext, options: CoreOptions = {}): Promise<RunningCore> {
  const stateDir = options.stateDir ?? join(await tempDir(t), 'state');
  const clock = new TimedClock(1_000_000);
  const random = seededRandom(options.seed ?? 7);
  const journal: string[] = [];
  const parts = openCore({ stateDir, clock, scheduler: clock, random });
  const server = createApiServer({
    routes: [...parts.routes, ...(options.extraRoutes ?? [])],
    tokens: options.tokenStore === undefined ? parts.meta : options.tokenStore(parts.meta),
    audit: parts.audit,
    random,
    clock,
    journal: (line) => void journal.push(line),
  });
  const socket = join(await tempDir(t), 'http.sock');
  await server.listen(socket);
  let stopped = false;
  const stop = async (): Promise<void> => {
    if (stopped) return;
    stopped = true;
    await server.stop();
    parts.close();
  };
  t.after(stop);
  const driver = drive(socket);
  return {
    ...parts,
    stateDir,
    socket,
    clock,
    journal,
    driver,
    enrol(label, scope) {
      const token = newToken(random);
      parts.meta.addMachine({ label, scope, tokenSha256: hashToken(token), enrolledAt: clock.now() });
      return token;
    },
    call(path, call = {}) {
      const headers: Record<string, string> = { ...call.headers };
      if (call.token !== undefined) headers['authorization'] = `Bearer ${call.token}`;
      if (call.ip !== null) headers['x-kb-client-ip'] = call.ip ?? '203.0.113.9';
      if (call.json === true) headers['content-type'] = 'application/json';
      return driver.request({ path, method: call.method ?? 'GET', headers, ...(call.body === undefined ? {} : { body: call.body }) });
    },
    stop,
  };
}
