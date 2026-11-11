// KBOX-6, KBOX-49, KBOX-20: the real TrustPort. Core cannot change /etc/keybox/trust.json: it writes a trust request into
// staging (temp file, then rename to `<name>.request`, which starts kb-install through its path unit) and waits for root's
// answer in the root-owned results directory. Root checks the proof or the code itself; core's table follows only `applied`.
import { closeSync, constants, existsSync, fsyncSync, openSync, readFileSync, renameSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import type { Clock } from '../ports/clock.ts';
import type { Random } from '../ports/random.ts';
import type { TrustPort, TrustRequest, TrustResult } from '../ports/trust.ts';
import { parseRootResult } from '../pure/install-request.ts';

export interface TrustInstallerDeps {
  /** `/var/lib/keybox/staging`. */
  readonly stagingDir: string;
  /** `/var/lib/keybox-install`. */
  readonly resultsDir: string;
  readonly random: Random;
  readonly clock: Clock;
  /** Waits between looks for the result. */
  readonly wait: (ms: number) => Promise<void>;
  /** How long core waits for root; past kb-install's own 120 s unit timeout. */
  readonly timeoutMs?: number;
}

const POLL_MS = 500;
const TIMEOUT_MS = 150_000;

/** Writes `<name>.request` by temp file and rename, so kb-install never reads a half-written request. */
export function writeRootRequest(stagingDir: string, name: string, request: object): void {
  const temp = join(stagingDir, `.${name}.tmp`);
  const fd = openSync(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o640);
  try {
    writeSync(fd, JSON.stringify(request));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(temp, join(stagingDir, `${name}.request`));
}

export function createTrustInstaller(deps: TrustInstallerDeps): TrustPort {
  return {
    async apply(request: TrustRequest): Promise<TrustResult> {
      const name = `trust-${Buffer.from(deps.random.bytes(12)).toString('base64url')}`;
      writeRootRequest(deps.stagingDir, name, request);
      const resultFile = join(deps.resultsDir, `${name}.result`);
      const deadline = deps.clock.now() + (deps.timeoutMs ?? TIMEOUT_MS);
      for (;;) {
        if (existsSync(resultFile)) {
          const result = parseRootResult(readFileSync(resultFile, 'utf8'));
          if (result === 'applied') return { result: 'applied' };
          return { result: 'refused', code: result?.startsWith('refused:') === true ? result.slice('refused:'.length) : 'bad_result' };
        }
        if (deps.clock.now() > deadline) return { result: 'refused', code: 'timeout' };
        await deps.wait(POLL_MS);
      }
    },
  };
}
