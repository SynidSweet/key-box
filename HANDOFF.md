# HANDOFF — loop state

Fresh-context loop state: this file and the code are the only channels.
REWRITE it (never append) before you finish. Unchanged fails.

## Where things stand

Units `scaffold`, `forms` and `kernel-store` are built, gated and merged on main. No platform, approval, relay, update, rotate or
share code exists yet. The full host `node --test` run, `tsc --noEmit` and gate are green at the last gate run (see "Recent").
The core process (`src/main-core.ts`) is a frame: it opens the state directory, serves the machine API on one unix socket
(`KB_STATE_DIR`, `KB_SOCKET`), and stops on SIGTERM. It has three read routes and no write route.
Next unit: `kernel-approve` (see Remaining). Spec: `docs/spec.md` (the unit's block in "Rules", its row in "Build units").
Run units with the compound-loop driver and `-G loop/gate.sh`.

## Codebase map

- `package.json`, `package-lock.json`, `.nvmrc` (24), `tsconfig.json`, `runtime.lock` (placeholder). Dev dependencies only
  (`typescript` 6.0.3, `@types/node` 24.19.2, exact); no runtime dependencies. `npm ci --ignore-scripts`.
- `src/ports/`: interfaces of design 5.1 (`vault`, `audit`, `meta` incl. TokenStore, `events`, `private`, `clock`, `random`,
  `issuer`, `destination`, `relay-profile`, `approvals`, `notifier`, `types`). Some value shapes are still placeholders (below).
- `src/pure/` (no I/O): `forms.ts` (KBOX-54: `scanForms`, `shareForms`, `coresOf`, `strippedView`, `createMatcher`; fixed failure
  codes, never a part of a value), `schemas.ts` (closed parsers, `AUDIT_SCHEMAS` per audit action, `NAME`), `errors.ts` (closed
  `ERROR_CODES`, `ApiError`, `AdapterError`, `VaultError`, `wrapAdapterCall`, `mapError`), `canonical.ts` (canonical JSON), `tokens.ts`
  (`kbt_` bearer, SHA-256 hash, constant-time find), `address.ts` (client address header), `lent.ts` (`makeLent`: placeholder only).
- `src/shell/` (adapters): `core.ts` `openCore(deps)` is the one place the parts are wired (tests and `main-core.ts` both use it):
  meta.db, audit, events, poller, vault, control routes; it first sweeps orphan vault temp files. `vault-fs.ts` (KBOX-4: one
  0600 file per generation in 0700 dirs, temp + fsync + rename; `sweepOrphanTemps(root)`), `db.ts` (meta.db schema, transactions),
  `meta.ts` (metadata store, events in the same transaction, token hashes, snapshot at a cursor), `audit.ts` (KBOX-50 hash chain),
  `events.ts` (event log, long poll over a Scheduler), `http.ts` (`route()` + `createApiServer`: auth, error mapping, audit row per
  request), `routes-control.ts` (`GET /api/meta`, `/api/audit`, `/api/events`), `private-db.ts` (private.db, separate connection),
  `clock.ts`, `random.ts`.
- `src/main-core.ts`: the process frame. Only it and `private-db.ts` name private.db.
- `deploy/`: `keybox.service`, `keyrelay.service`, `keybox-tmpfiles.conf` (three runtime dirs, socket groups; KBOX-45).
- `test/kit/` (import from `test/kit/index.ts`; `derived-forms.ts` imported directly): `tempDir`/`tempDirSync`, `FakeClock`,
  `TimedClock`, `seededRandom`, `canary()` (whole-value forms), `findDerived()` (prefix, suffix, length beside the name, sha256),
  `fakePlatform`, `drive`, `startCore(t, opts)` (real parts on a temp socket), `startNode`/`spawnNode`, `settle`/`waitUntil`,
  `softAuthenticator`, `lent`/`bytesOf`, `ensureSystemUsers`, unit-text helpers. Kit edits: add files, do not edit existing lines.
- `test/fakes/` and `test/contracts/`: in-memory fakes and one contract suite per port (`xContract(name, make)`); adapters call the
  same suite (`vault-fs.test.ts` runs `vaultContract` over the file vault).
- Tests by rule: `canary.test.ts` (KBOX-2 end to end incl. the running process), `vault-fs.test.ts`, `vault-no-backup.test.ts`
  (KBOX-19: the spec's grep; untouched), `vault-files.test.ts` (KBOX-19: behavioural file-tree test), `vault-sweep.test.ts` (orphan temp sweep), `meta-db`/`meta-store`,
  `audit-chain`, `events`, `api-frame`, `control-read`, `machine-token`, `client-address`, `canonical`, `deploy-units`, `forms`
  (oracle vectors in `test/fixtures/forms/`), `arch.test.ts` + `test/arch/*` (architecture checks on fixture trees and the repo).
- `test/journeys/process-split.test.ts` (KBOX-45): root-only, switches uid; the gate runs it in a Docker container, never on the host.
- `loop/gate.sh` (gate-template v2) and `loop/probes/arch.sh`. The host suite is every `.ts .mts .js .mjs .cjs` file under `test/`
  except the process-split file.

## Remaining

In the spec's order (spec "Build units"):

1. `kernel-approve` (KBOX-7, 8, 9, 11, 20, 22, 49, 53), needs kernel-store; adds `src/pure/{webauthn,cose,challenge}.ts`. The arch kit
   check will then bind `test/kit` (the kit must not reach those files).
2. `update` (KBOX-1, 6, 21, 44, 46, 48), `relay` (KBOX-3, 13, 14, 23, 25, 32, 47), `rotate` (KBOX-12, 15, 16, 17, 34, 51, 52),
   `share` (KBOX-18, 33); parallel. `relay` and `share` use `src/pure/forms.ts`.
3. The six adapter units: `google`, `vercel`, `supabase`, `openai`, `elevenlabs`, `paste`. Each commits `docs/probes/<id>.md` and
   `src/platforms/<id>/unverified.json` before code, or `test/arch.test.ts` fails (KBOX-42).

Open items from the kernel-store review, not fixed: `put()` replaces an existing generation through rename (immutability is not
enforced; a ref `a` gen 1 and a ref `a/1` collide as `write_failed`); `retire()` does not sweep temp files (the sweep runs at start only).
A temp file under a ref longer than the audit NAME limit (128) would make the start-time audit row refuse and stop the start.
Spec-drift audit of `meta`, `core`, `routes-control`, `private-db`, `tokens`, `ports/*` was not done.

Learned that changes them: `Scope`, `Notice.kind`, `RelayProfile` value shapes and `AllowRule.query` in `src/ports` are minimal
placeholders; the first unit that needs one closes it (and may edit the port).

## Decisions

- Node 24 LTS per spec (`.nvmrc`); dev machines run Node 26, which also works. `typescript` 6.0.3 (the arch tests need the JS parser API).
- Silent-catch rule is strict: a catch must throw, return a value other than `undefined`/`null`/`void`, or call `audit.append` /
  `notifier.*` on EVERY path. Applies to `src/` and `test/`. Return a result object to record without throwing.
- `any`, non-null `!`, `@ts-ignore`, `@ts-expect-error`, `@ts-nocheck`, `eslint-disable`, `noqa` counts cover all `.ts`/`.js` outside
  `node_modules` and dot folders; never write those words in a comment.
- Probe `arch` is the gate's architecture step. `SUITE_FAILING_IDS_CMD` is unset: a red suite is always FAIL.
- `GATE_PINNED_PATHS` pins `loop/probes/arch.sh` and `tsconfig.json`; `package-lock.json` is a lockfile pin (`DEPS_ALLOWED=0`).
- Audit rows hold names, ids, codes and statuses only (closed `AUDIT_SCHEMAS`). `vault.temp_swept` has an empty detail: the row's
  `ref` is the key; no value, length or digest.
- A planted-mutant check (scratch copy under `~/.cache`) was used for the canary extension and the no-backup test.

## Gotchas

- Run the gate where `/home/petter/.claude/skills/deterministic-gates` exists and git history is present: under `runq`, a job that
  names that path runs locally. Command: `runq run --why "<why>" -- bash -c "env LOOP_SKILL_DIR=/home/petter/.claude/skills/deterministic-gates LOOP_WORKDIR=<tree> LOOP_BASE_COMMIT=<sha> bash loop/gate.sh"`.
- The gate needs Docker (process-split journey); no docker is a FAIL, never a host fallback.
- A gate with `LOOP_BASE_COMMIT` equal to HEAD needs `TESTS_MUST_GROW=0`.
- Plain `node --test` runs EVERY file under `test/` (no `.test` suffix needed). Helpers there must do nothing when run directly.
  No broken `.ts` fixtures in `test/fixtures/`; build fixture trees in temp dirs. `test/fixtures/forms/generate-oracle.py` is not run.
- The arch test runs `tsc` in a subprocess; a fixture tree needs `materialise(t, tree, { withNodeModules: true })`.
- A contract test that waits for something that may never come needs `{ timeout }`.
- `kit/fake-platform.ts` `401-echo` echoes the whole presented credential on purpose, so leak scans have something to catch.
- Bare `node`/`python3` can be refused on this machine: go through `runq run --why ... --`. runq may run a job on a remote host.
- KBOX-42: the probe report is committed FIRST; no test checks the commit order. The adapter unit's brief must say it.

## Recent

`forms` (KBOX-54), `kernel-store` (KBOX-2, 4, 5, 10, 19, 29, 30, 31, 43, 45, 50) merged at f6280ad. Then four review fixes: canary
derived-form scan, behavioural no-backup test, `.mts/.js/.mjs/.cjs` in the gate's host suite, startup sweep of orphan vault temp files.
