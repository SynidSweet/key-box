// KBOX-6: the three long-running units as kb-install sees them, and the processes it runs on their behalf. A restart is
// `systemctl restart`, killed when it is not over by the bound kb-install gives it; the health check passes when core and
// the relay both answer `GET /healthz` on their unix sockets with the new release within 60 s of the restart and before its
// bound. kb-install runs with PrivateNetwork=yes, so the sockets are the only way to ask. The self-check runs the new
// release's own kb-install in its no-op mode. This is the one module of kb-install that starts a process (arch check).
import { spawnSync } from 'node:child_process';
import { request } from 'node:http';
import { join } from 'node:path';
import type { Clock } from '../ports/clock.ts';
import { RESTART_WITHIN_MS } from './installer.ts';
import type { ReleaseUnits } from './installer.ts';

export const HEALTH_WITHIN_MS = 60_000;
const ASK_EVERY_MS = 1_000;
const ASK_TIMEOUT_MS = 2_000;
/** kb-install's argument for its no-op mode: load every module, touch nothing, exit 0. */
export const SELF_CHECK = '--self-check';

export interface SystemdDeps {
  readonly systemctl: string;
  readonly units: readonly string[];
  /** Core's and the relay's `http.sock`. */
  readonly healthSockets: readonly string[];
  readonly clock: Clock;
  readonly wait: (ms: number) => Promise<void>;
  /** The Node that runs a release's kb-install for its self-check: by default the release's own pinned `bin/node`. */
  readonly nodeOf?: (releaseDir: string) => string;
}

/** The units port, whose bounds default to its own limits (15 s for a restart, 60 s for a health check). */
export interface SystemdUnits extends ReleaseUnits {
  restart(until?: number): Promise<void>;
  healthCheck(release: string, until?: number): Promise<boolean>;
}

/** True when the process on `socket` answers `/healthz` with `{release}` equal to the release given. */
export function answersRelease(socket: string, release: string): Promise<boolean> {
  return new Promise((resolve) => {
    const req = request({ socketPath: socket, path: '/healthz', method: 'GET', headers: { 'x-kb-client-ip': '127.0.0.1' }, timeout: ASK_TIMEOUT_MS }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => void chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve(res.statusCode === 200 && /^\{"release":"[0-9a-f]{64}"\}$/.test(text) && text.includes(`"${release}"`));
      });
      res.on('error', () => resolve(false));
    });
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(false));
    req.end();
  });
}

export function systemdUnits(deps: SystemdDeps): SystemdUnits {
  return {
    restart(until = deps.clock.now() + RESTART_WITHIN_MS) {
      const timeout = Math.max(1, until - deps.clock.now());
      const done = spawnSync(deps.systemctl, ['restart', ...deps.units], { stdio: 'ignore', timeout, killSignal: 'SIGKILL' });
      if (done.error !== undefined) return Promise.reject(done.error);
      return done.status === 0 ? Promise.resolve() : Promise.reject(new Error(`systemctl restart exited ${done.status ?? 'by a signal'}`));
    },
    async healthCheck(release, until = Number.POSITIVE_INFINITY) {
      const deadline = Math.min(deps.clock.now() + HEALTH_WITHIN_MS, until);
      for (;;) {
        const answers = await Promise.all(deps.healthSockets.map((s) => answersRelease(s, release)));
        if (answers.every(Boolean)) return true;
        if (deps.clock.now() >= deadline) return false;
        await deps.wait(Math.min(ASK_EVERY_MS, deadline - deps.clock.now()));
      }
    },
    selfCheck(releaseDir, until) {
      const node = deps.nodeOf?.(releaseDir) ?? join(releaseDir, 'bin', 'node');
      const timeout = Math.max(1, until - deps.clock.now());
      // No environment: the self-check reads no path, so nothing of kb-install's own settings may reach it.
      const done = spawnSync(node, [join(releaseDir, 'src', 'cli', 'kb-install.ts'), SELF_CHECK], { stdio: 'ignore', timeout, killSignal: 'SIGKILL', env: {} });
      return Promise.resolve(done.error === undefined && done.status === 0);
    },
  };
}
