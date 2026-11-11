// KBOX-6, KBOX-49, KBOX-20: the real TrustPort. Core cannot change /etc/keybox/trust.json: it writes a trust request into
// staging (temp file, then rename to `<name>.request`, which starts kb-install through its path unit) and waits for root's
// answer in the root-owned results directory. Root checks the proof or the code itself; core's table follows only `applied`.
import { closeSync, constants, existsSync, fsyncSync, openSync, readFileSync, renameSync, rmSync, writeFileSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import type { Clock } from '../ports/clock.ts';
import type { Random } from '../ports/random.ts';
import type { TrustPort, TrustRequest, TrustResult } from '../ports/trust.ts';
import { parseRootResult } from '../pure/install-request.ts';
import type { RootTrustRequest } from '../pure/install-request.ts';

export interface TrustInstallerDeps {
  /** `/var/lib/keybox/staging`. */
  readonly stagingDir: string;
  /** `/var/lib/keybox-install`. */
  readonly resultsDir: string;
  readonly random: Random;
  readonly clock: Clock;
  /** Waits between looks for the result. */
  readonly wait: (ms: number) => Promise<void>;
  /** The request's deadline, from now: root refuses it `late` after that; past kb-install's own 120 s unit timeout. */
  readonly timeoutMs?: number;
}

const POLL_MS = 500;
const TIMEOUT_MS = 150_000;
/** Core looks for an answer this long past the deadline: root checked it before the deadline and writes its result just after. */
const ANSWER_GRACE_MS = 5_000;

/** Writes `<name>.request` by temp file and rename, so kb-install never reads a half-written request. A temp file a
 * crashed write left behind is removed first (staging is core's own). */
export function writeRootRequest(stagingDir: string, name: string, request: object): void {
  const temp = join(stagingDir, `.${name}.tmp`);
  rmSync(temp, { force: true });
  const fd = openSync(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o640);
  try {
    writeSync(fd, JSON.stringify(request));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(temp, join(stagingDir, `${name}.request`));
}

/** Tells root that core has read `<name>.result`: kb-install removes the result and this marker at its next run. */
export function markSettled(stagingDir: string, name: string): void {
  writeFileSync(join(stagingDir, `${name}.settled`), '', { mode: 0o640 });
}

export function createTrustInstaller(deps: TrustInstallerDeps): TrustPort {
  return {
    async apply(request: TrustRequest): Promise<TrustResult> {
      // The bootstrap's tmpfiles line makes the results directory together with kb-install; without it no root answers.
      if (!existsSync(deps.resultsDir)) return { result: 'refused', code: 'no_installer' };
      const name = `trust-${Buffer.from(deps.random.bytes(12)).toString('base64url')}`;
      const deadline = deps.clock.now() + (deps.timeoutMs ?? TIMEOUT_MS);
      const written: RootTrustRequest = { ...request, deadline };
      writeRootRequest(deps.stagingDir, name, written);
      const resultFile = join(deps.resultsDir, `${name}.result`);
      for (;;) {
        if (existsSync(resultFile)) {
          const result = parseRootResult(readFileSync(resultFile, 'utf8'));
          markSettled(deps.stagingDir, name);
          if (result === 'applied') return { result: 'applied' };
          return { result: 'refused', code: result?.startsWith('refused:') === true ? result.slice('refused:'.length) : 'bad_result' };
        }
        if (deps.clock.now() > deadline + ANSWER_GRACE_MS) return { result: 'refused', code: 'timeout' };
        await deps.wait(POLL_MS);
      }
    },
  };
}
