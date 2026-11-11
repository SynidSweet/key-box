# HANDOFF — codebase map and loop state

Fresh-context loop state: this file and the code are the only channels.
REWRITE it (never append) before you finish. Unchanged fails.

## Where things stand

Every unit of stages 1 to 4 is built and integrated on `unit/integrate`: `scaffold`, `forms`, `kernel-store`, `kernel-approve`,
`update`, `relay`, `rotate`, `share`. What is left is the six adapter units, three journeys and the items under Remaining.
`src/main-core.ts` now wires everything: `startCore(env, runtime)` (exported; `main()` is `startCore` plus SIGTERM/SIGINT)
serves the machine API, the share file and, when `KB_DOMAIN` is set, the phone app, approvals, the real `TrustPort`, the update
intake and rotation (key routes, paste, deliveries, the hourly tick, the daily reconcile, the `rotate_key` and `add_key`
executors). `src/platforms/registry.ts` is EMPTY until the adapter units add entries, so every action that needs a platform
(`add_key`, `add_destination`, `set_allow_rules`, the two Vercel kinds) is `rejected` at proposal time, no key has a share shape
(`noShapeYet`) and the relay forwards nothing. Spec: `docs/spec.md` (Build units table at the end). Verdicts of each unit's
adversary: `/home/petter/.local/share/lanes/key-box/<unit>.verdict.md`.

## Codebase map

- Root: `package.json` (dev dependencies only: `typescript` 6.0.3, `@types/node` 24.19.2, exact; no runtime dependencies),
  `tsconfig.json`, `runtime.lock` (real Node 24.11.1 and Caddy 2.10.2 arm64 pins), `docs/spec.md`, `docs/setup-checklist.md`,
  `loop/gate.sh` + `loop/probes/arch.sh`.
- `src/ports/` (interfaces of design 5.1): `vault`, `audit`, `meta` (+TokenStore), `events`, `private`, `clock`, `random`,
  `issuer` (Issuer, KeyLister with `listAt`, Verifier), `destination` (Destination, Redeployer, three push outcomes),
  `relay-profile`, `platform` (`PlatformEntry`: id, issuer, lister, relay or denyOnly), `approvals`, `notifier`, `push`, `trust`,
  `share`, `minted`, `types`.
- `src/pure/` (no I/O), by concern:
  - Approvals and proofs: `webauthn`, `cose`, `challenge` (every challenge; shared with kb-install), `actions` (closed `Action`
    union), `slots`, `words`, `codes`, `tokens`, `canonical`, `schemas`, `errors`, `address`, `lent`, `pushcrypto`, `pushsub`.
  - Update: `tar`, `release-hash`, `runtime-lock`, `install-request` (core's request and root's answer, one home), `kept-proof`.
  - Relay: `target-parse`, `rule-match`, `profile` (engine and registry checks), `scanner`, `forms` (the one forms library for
    the scanner and the share writer), `lend-protocol`, `relay-errors`, `egress-policy`.
  - Rotation: `rotation-machine` (steps, intent name, retry delay), `scheduler` (due dates, staggering), `class` (class never
    lowered, KBOX-16).
  - Share: `coverage` (watch tier), `share-build` (format v3, envelope).
- `src/shell/` (adapters and wiring), by concern:
  - Kernel: `core.ts` (`openCore`: meta.db, audit, events, vault, control routes), `db`, `meta`, `audit`, `events`, `vault-fs`,
    `http` (frame), `routes-control`, `private-db`, `clock`, `random`.
  - Approval half: `approve-core` (`openApproveCore`), `approvers`, `approvals`, `tokens`, `routes-approve`, `push`,
    `push-transport`, `console`, `idle-watch`.
  - Update: `updater` (core's intake, `POST /api/updates`), `trust-installer` (real `TrustPort`), `installer` + `safe-open` +
    `systemd` (kb-install's root half; `src/cli/kb-install.ts`), `src/cli/kb-code.ts`.
  - Relay: `relay-http` (kb-relay on its own socket; `src/main-relay.ts`), `lend-core` + `lend-socket` (core's lend side),
    `minted-values`, `egress` + `egress-system` (the one outbound gate; hosts from the registry and `deploy/egress-hosts.json`).
  - Rotation: `rotation.ts` (`openRotation`: the one wiring), `orchestrator` (runs, `stop()` cancels run timers), `reconcile`,
    `revoke-confirm`, `rotation-store`, `rotation-ports` (`PlatformSource`, `PlatformKit`, `Point`), `platform-source`
    (`createPlatformSource`: registry to kits, master key = current generation of the platform's master-class key row),
    `key-routes` (`/api/keys`, `/api/rotations`, `/api/retired`), `deliveries`, `paste` (phone paste flow), `new-key`.
  - Share: `share-source` (admin and master keys; retired generations from the rotation store's `grace` and `retired` rows),
    `share-writer` (`GET /api/share`, `share.version`).
- `src/web/`: the phone app, plain JS under `checkJs` (`app.js`, `setup.*`, `recover.*`, `register.js`, `paste.*`, `sw.js`).
- `src/data/`: `wordlist.txt`, `push-hosts.json`, `credential-shapes.json`.
- `deploy/`: `keybox.service`, `keyrelay.service`, `kb-code.service`, `kb-install.service` + `.path`, `caddy.service`,
  `Caddyfile`, `cloud-init.yaml`, `keybox-tmpfiles.conf`, `runtime.config.json` (`console_device` UNVERIFIED `/dev/ttyAMA0`,
  `link_mbps`), `egress-hosts.json` (non-adapter hosts: the push services, `nodejs.org`, `github.com`).
- Tests: `test/*.test.ts` named for the behaviour (one file per rule family; the spec's rule ids are in the test titles);
  `test/journeys/` (J2 `relayed-call`, J3 in one process `ordinary-rotation`, J5 `recovery`, J6 `share`, `process-split`
  is root-only); `test/contracts/` (one suite per port, run against the fake); `test/arch*` (architecture probe);
  `test/kit/` (shared helpers; add files, do not edit lines; it must not import `src/pure/{webauthn,cose,challenge}`);
  `test/support/*-world.ts` (`approveWorld`, `rotationWorld`, `routesWorld`, `shareWorld`, `relay-world`, `install-world`);
  `test/fakes/` (platform, destination, push, trust, vault, audit, approvals). New this slice: `main-core.test.ts` (core started
  in process on a `TimedClock`), `platform-source.test.ts`, `share-rotation.test.ts` (real share source over a real rotation).

## Remaining

1. The six adapter units, parallel: `google` (KBOX-24, 41), `vercel` (26, 36), `supabase` (37), `openai` (38), `elevenlabs` (39),
   `paste` (40: Anthropic, Stripe). Each COMMITS A PROBE REPORT FIRST (`docs/probes/<id>.md`) of every UNVERIFIED endpoint named in
   its rule, then code. To wire an adapter: add its `PlatformEntry` line to `src/platforms/registry.ts`; `PlatformEntry` has no
   `verifier`, `keyPageUrl` or destination kits yet, so the first adapter to need them extends the port and the two lines in
   `platform-source.ts` that read it; replace `noShapeYet` in `main-core.ts` with the registry's `issuer.capabilities().shape`;
   drop the kind from `NEEDS_ADAPTER` / replace `vetWithoutAdapters` with the adapter's proposal check.
2. Journeys J1 (setup, then approve a rotation of an admin key), J3 as two real processes (J3 runs in one process today) and J4
   (an update bundle approved and installed, then a bad bundle rolled back). J1 and J3 need the registry; J4 needs the real
   kb-install on a box. J2, J5 and J6 exist.
3. Release downloads into `<H>.bin`: an update that changes a pin is refused (`lock`), unchanged pins work. GitHub release assets
   redirect to a second host that must join `deploy/egress-hosts.json` (caller `update`) when downloads are built.
4. Make the trust request's `deadline` required at root (`src/pure/install-request.ts` still parses it as optional).
5. The OCI Run Command disable line in `deploy/cloud-init.yaml` (`oci-cloud-agent-plugin disable "Compute Instance Run Command"`)
   is UNVERIFIED: probe it on the instance; the runcmd has no `set -e`, so a failure says nothing.
6. The `set_allow_rules` executor's widening refusal comes with the adapters (it is `rejected` until one registers, and no code
   reads a key's own allow set but the relay profile narrowing); wire it in the unit that builds that executor, with a test
   through the proposal route.
7. m6 (relay.verdict.md): the canonical re-encoding turns Google's literal `documents:runQuery` into `documents%3ArunQuery`
   (`src/pure/target-parse.ts`, per the spec's rule). Whether Google's front end treats it the same is UNVERIFIED: the `google`
   unit probes it.
8. Decided 2026-11-11 (orchestrator): a revoked generation's value file is deleted (`vault.retire`), so it leaves the share file as
   `none`; only a generation in grace is watched as retired. `KBOX-33` and `KBOX-51` step 10 say so.
9. Open items not fixed: old approvers' push subscriptions are not removed on recovery or removal; the control enrol window is
   per label only (decided 2026-11-11: accepted residual, see Decisions); `private.db` from before kernel-approve has no
   migration; the phone app was never run in a real browser; findings of the unit verdicts that no fix commit names are in the
   verdict files.

## Decisions

- Node 24 LTS; `typescript` 6.0.3. Silent-catch rule strict (throw, return a non-empty value, or `audit.append` / `notifier.*`
  on every path), `src/` and `test/`. No `any`, `!`, ts or eslint suppressions anywhere.
- Control enrol window per label only: not built, accepted residual (orchestrator, 2026-11-11). The fix would make the owner copy a
  hash off a machine and buys nothing under S-717 (relay passes are not pinned and every machine is agent-controlled).
- Integrate: rotation is opened only with the approval half (`KB_DOMAIN` set), because it needs `approvals` and `approvers`; a box
  with no domain has no key, rotation or paste route. The approval executors reach rotation late (`viaRotation`), since rotation is
  built from the approval half that takes the executors. `rotation.run()` is awaited after the server listens, with no catch: a
  failed resume stops the start, loudly.
- Integrate: the platform's master key is the first master-class key row of that platform, current generation, lent from the vault;
  none gives a `RangeError` that the orchestrator audits (`drive_failed`). KBOX-36 says the owner pastes it once; no spec text names
  the row, so this is a reading.
- Integrate: `RotationStore.setGenStatus` writes `key.changed`, so a retirement, a grace and a promote each give the share writer a
  new version (KBOX-33 asks for a version per retirement; nothing emitted one). `Orchestrator.stop()` and `startCore().stop()` cancel
  run timers and are idempotent.
- Share: `createMetaShareSource({generations})` is optional so fake-store tests keep the old shape; main-core passes the rotation
  store's `gens`. A pending or failed generation is not listed.
- Probe `arch` is the gate's architecture step. `GATE_PINNED_PATHS` pins `loop/probes/arch.sh` and `tsconfig.json`; lockfile pinned.
- Planted mutants (scratch copies, one `runq` run) stand in for missed red steps; this slice planted three (the orchestrator stop,
  core's rotation stop, the grace filter) and all were caught.

## Gotchas

- Run the gate under `runq` naming the skill path: `runq run --why "<why>" -- bash -c "env LOOP_SKILL_DIR=/home/petter/.claude/skills/deterministic-gates LOOP_WORKDIR=<tree> LOOP_BASE_COMMIT=<sha> bash loop/gate.sh"`. Needs Docker.
- The guard refuses `node`, `python3` and other interpreters outside `runq run`, and blocks the whole command line: edit with the Edit
  tool, run tests as `runq run --why "<why>" -- node --test <file>`. Never `--place`.
- Plain `node --test` runs EVERY file under `test/`; helpers there must do nothing when run directly.
- Other runq jobs may run remotely with a synced tree: a script outside the repo is not there.
- A bearer token on any phone path (even an unknown one like `/r/x`) is 403 from the frame.
- `startCore` takes a `CoreRuntime` (clock, scheduler, random, journal): a test passes a `TimedClock` and checks
  `pendingTimers === 0` after `stop()`. It still reads `/proc` (idle watch) and the real egress gate; set `KB_INSTALL_RESULTS` and
  `KB_CURRENT` to temp paths.
- `vault.lend` of a retired generation throws `unknown_key`; `shareValuesIn` turns that into `''`.

## Recent

`integrate` (this slice, on main after e1fd5e5): rotation wired into core (`startCore`, `platform-source`, executors, routes,
tick and reconcile, stop), `Orchestrator.stop`, retired generations in the share file over the real source, `key.changed` on
every generation status change, and this file. Before it: `rotate` (two adversary fix rounds; verdict "declared not done" named
the wiring and J1/J3), `update` (verdict UNSOUND, fixes merged incl. spec revision 4: approver_add binds the new approver's key
hashes), `relay` and `share` (SOUND WITH FIXES, fixes merged). Detail of those units is in their verdict files and git history.
