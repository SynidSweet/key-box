// KBOX-6: the three long-running units as kb-install sees them. A restart is `systemctl restart`; the health check passes when
// core and the relay both answer `GET /healthz` on their unix sockets with the new release within 60 s of the restart.
// kb-install runs with PrivateNetwork=yes, so the sockets are the only way to ask.
import { spawnSync } from 'node:child_process';
import { request } from 'node:http';
import type { Clock } from '../ports/clock.ts';
import type { ReleaseUnits } from './installer.ts';

export const HEALTH_WITHIN_MS = 60_000;
const ASK_EVERY_MS = 1_000;
const ASK_TIMEOUT_MS = 2_000;

export interface SystemdDeps {
  readonly systemctl: string;
  readonly units: readonly string[];
  /** Core's and the relay's `http.sock`. */
  readonly healthSockets: readonly string[];
  readonly clock: Clock;
  readonly wait: (ms: number) => Promise<void>;
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

export function systemdUnits(deps: SystemdDeps): ReleaseUnits {
  return {
    restart() {
      const done = spawnSync(deps.systemctl, ['restart', ...deps.units], { stdio: 'ignore' });
      if (done.error !== undefined) return Promise.reject(done.error);
      return done.status === 0 ? Promise.resolve() : Promise.reject(new Error(`systemctl restart exited ${done.status ?? 'by a signal'}`));
    },
    async healthCheck(release) {
      const deadline = deps.clock.now() + HEALTH_WITHIN_MS;
      for (;;) {
        const answers = await Promise.all(deps.healthSockets.map((s) => answersRelease(s, release)));
        if (answers.every(Boolean)) return true;
        if (deps.clock.now() >= deadline) return false;
        await deps.wait(ASK_EVERY_MS);
      }
    },
  };
}
