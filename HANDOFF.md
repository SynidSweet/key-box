# HANDOFF — loop state

Fresh-context loop state: this file and the code are the only channels.
REWRITE it (never append) before you finish. Unchanged fails.

## Where things stand

Unit `scaffold` is built and gated: toolchain, layout, ports, test kit, contract suites with fakes, architecture tests,
and `loop/gate.sh`. Everything is green (full `node --test` 195 tests at the last count, `tsc --noEmit` clean, gate PASS).
No feature code exists yet. Next unit: `forms` (and `kernel-store` in parallel with it), per the spec's order.
Spec: `docs/spec.md` (read the unit's block in "Rules" and its row in "Build units"). Run units with the compound-loop
driver and `-G loop/gate.sh`.

## Codebase map

- `package.json`, `package-lock.json`, `.nvmrc` (24), `tsconfig.json`, `runtime.lock` (placeholder format), `.gitignore`.
  Only dev dependencies: `typescript` 6.0.3 and `@types/node` 24.19.2, exact. No `dependencies` key. `npm ci --ignore-scripts`.
- `src/ports/`: the interfaces of design 5.1 (`issuer.ts` has Issuer, KeyLister, Verifier, PasteSource; `destination.ts`;
  `relay-profile.ts`; `vault.ts`; `approvals.ts`; `audit.ts`) plus `clock.ts`, `random.ts`, `notifier.ts`, `types.ts` (closed types, Lent).
- `src/pure/`, `src/shell/`, `src/platforms/`, `src/web/`, `src/cli/`, `deploy/`, `docs/probes/`, `test/fixtures/`, `test/journeys/`:
  empty, each holds a `.gitkeep`.
- `test/kit/` (import from `test/kit/index.ts`): `tempDir(t)`, `FakeClock`, `seededRandom`/`seedFor`/`checkProperty`, `canary()`
  (`findIn`, `assertAbsent`), `fakePlatform(t)` (modes ok, 500, 401-echo, malformed-json, partial-body, redirect, hang, refuse),
  `drive(socketPath)`, `softAuthenticator()`, `lent(bytes, label)`/`bytesOf`, `runNode`. Own tests: `test/kit/kit.test.ts`.
- `test/fakes/`: in-memory fakes for the ports (`vault`, `audit`, `approvals`, `platform` = issuer+lister+verifier over one world,
  `destination` incl. redeployer, `relay-profile`).
- `test/contracts/*.contract.ts`: one suite per port, each an exported function `xContract(name, make)`. `fakes.test.ts` runs every
  suite against its fake. An adapter unit adds its own `*.test.ts` that calls the same suite over `fakePlatform()`.
- `test/arch.test.ts` and `test/arch/*.ts`: the architecture checks. Each check is `checkX(root): Promise<Violation[]>` with a closed
  `ViolationCode`; the test runs it on fixture trees (`test/arch/fixture.ts`: `goodTree`, `withChanges`, `materialise`) and on the repo.
  Checks: toolchain, source imports, erasable syntax, zero counts, pure core, layers, cycles, catches, kit independence, probe reports, typecheck.
- `loop/gate.sh` (from gate-template v2) and `loop/probes/arch.sh` (probe `arch`: positive = arch tests pass on the tree; negative = 14
  planted violations in a scratch copy each turn their intended check red).

## Remaining

In the spec's order (spec "Build units"):

1. `forms` (KBOX-54), `worker-routine`, effort high: `src/pure/forms.ts`, `test/forms.test.ts`, `test/fixtures/forms/*`.
2. `kernel-store` (KBOX-2, 4, 5, 10, 19, 29, 30, 31, 43, 45, 50), in parallel with `forms`.
3. `kernel-approve` (KBOX-7, 8, 9, 11, 20, 22, 49, 53), needs kernel-store; adds `src/pure/{webauthn,cose,challenge}.ts`: the arch kit check will then bind `test/kit`.
4. `update` (KBOX-1, 6, 21, 44, 46, 48), `relay` (KBOX-3, 13, 14, 23, 25, 32, 47), `rotate` (KBOX-12, 15, 16, 17, 34, 51, 52), `share` (KBOX-18, 33); parallel.
5. The six adapter units: `google`, `vercel`, `supabase`, `openai`, `elevenlabs`, `paste`. Each must commit `docs/probes/<id>.md` and
   `src/platforms/<id>/unverified.json` (array of the platform's UNVERIFIED ids) before code, or `test/arch.test.ts` fails (KBOX-42).

Learned that changes them: the `Scope`, `Notice.kind`, `RelayProfile` value shapes and `AllowRule.query` in `src/ports` are minimal
placeholders; the first unit that needs one closes it (and may edit the port).

## Decisions

- Node: the spec says 24 LTS; the dev machines run Node 26, which also works. `.nvmrc` says 24 and `@types/node` is 24.19.2.
- `typescript` 6.0.3, not 7.x: 7 is the native port, and the arch tests need the `typescript` JS parser API.
- Silent-catch rule is strict: a catch must contain a `throw`, a `return` with a value other than `undefined`/`null`/`void`, or an
  `audit.append(...)` / `notifier.*(...)` call, on EVERY path (a conditional throw alone is refused). Applies to `src/` and `test/`, and to
  `.catch(fn)` handlers. To record an error without throwing, return a result object from the catch (see `tryStrip` in `test/arch/sources.ts`).
- The `any`, non-null `!`, `@ts-ignore`, `@ts-expect-error`, `@ts-nocheck`, `eslint-disable` and `noqa` counts cover all `.ts` and `.js` files
  outside `node_modules` and dot folders; comments only for the directives (never write those words in a comment), JSDoc `any` in `.js`.
- Also checked beyond the spec text: each id in a probe report needs a status word on its own line; a platform with no
  `unverified.json` fails; `src/pure` also refuses `Date()` and `globalThis.fetch`-style access. "No file of the release tree under
  node_modules" is checked as: `.gitignore` ignores it, and (when given `trackedFiles`) nothing tracked is under it. The test does not pass the git list yet.
- Probe `arch` is the gate's explicit architecture step; the spec's "no gate probes" refers to live platform probes, not this one.
- `SUITE_FAILING_IDS_CMD` is unset: a red suite is always FAIL, so the gate's "valid escalation" path is unavailable.
- `GATE_PINNED_PATHS` pins `loop/probes/arch.sh` and `tsconfig.json`; `package-lock.json` is a lockfile pin (`DEPS_ALLOWED=0`).
  A unit that must change one of these needs the orchestrator to commit the change first.

## Gotchas

- Gate must run where `/home/petter/.claude/skills/deterministic-gates` exists and where git history is present: under `runq`, a job
  that mentions that path in its command runs locally. A plain job lands on a remote host with a one-commit synthetic git and no skill dir.
  Command used: `runq run --why "<why>" -- env LOOP_SKILL_DIR=/home/petter/.claude/skills/deterministic-gates LOOP_WORKDIR=<tree> LOOP_BASE_COMMIT=<sha> bash loop/gate.sh`.
- Gate with `LOOP_BASE_COMMIT` equal to HEAD needs `TESTS_MUST_GROW=0`. The scaffold itself added files the gate pins and the lockfile, so a
  gate run against the pre-scaffold base needs `DEPS_ALLOWED=1 GATE_PINNED_PATHS=` too.
- Plain `node --test` runs EVERY file under `test/` as a test file (no `.test` suffix needed). Helpers there must do nothing when run
  directly: export only. Do not put broken `.ts` fixtures in `test/fixtures/`; build fixture trees in temp dirs.
- The arch test runs `tsc` in a subprocess (about 1 s on the repo). A fixture tree needs `materialise(t, tree, { withNodeModules: true })`.
- A contract test that waits for something that may never come needs `{ timeout }` (see `approvals.contract.ts`), or a broken adapter hangs the suite.
- `kit/fake-platform.ts` `401-echo` echoes the whole presented credential, on purpose, so leak scans have something to catch.
- runq jobs on remote hosts run in a mirror; files the job writes inside the tree come back, node_modules included.
- KBOX-42 says the probe report is committed FIRST; no test checks the commit order. The adapter unit's brief must say it.

## Recent

Scaffold, 7 commits after base 549f0e3: toolchain; ports + kit; arch tests; contracts + fakes + layout; gate; handoff.
Tests: `test/kit/kit.test.ts` 18, `test/arch.test.ts` 109, `test/contracts/fakes.test.ts` 31 (suites registered by the nine
`*.contract.ts`), 195 in the full run (the rest are no-test helper files counted as passing files).
