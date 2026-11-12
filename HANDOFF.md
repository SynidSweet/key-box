# HANDOFF — codebase map and loop state

Fresh-context loop state: this file and the code are the only channels.
REWRITE it (never append) before you finish. Unchanged fails.

## Where things stand

Every unit of stages 1 to 4 is built and integrated on main: `scaffold`, `forms`, `kernel-store`, `kernel-approve`,
`update`, `relay`, `rotate`, `share`. What is left is the six adapter units, three journeys and the items under Remaining.
`src/main-core.ts` now wires everything: `startCore(env, runtime)` (exported; `main()` is `startCore` plus SIGTERM/SIGINT)
serves the machine API, the share file and, when `KB_DOMAIN` is set, the phone app, approvals, the real `TrustPort`, the update
intake and rotation (key routes, paste, deliveries, the hourly tick, the daily reconcile, the `rotate_key` and `add_key`
executors). `createRegistry(deps)` in `src/platforms/registry.ts` builds an EMPTY list until the adapter units add entries, so `add_key` is `rejected` at proposal time (no platform is registered),
no key has a share shape and the relay forwards nothing. A registry entry now carries everything an adapter registers (unit
`platforms`); `add_destination`, `set_allow_rules` and the two Vercel kinds stay `rejected` until their executors are built. Spec: `docs/spec.md` (Build units table at the end). Verdicts of each unit's
adversary: `/home/petter/.local/share/lanes/key-box/<unit>.verdict.md`.

## Codebase map

- Root: `package.json` (dev dependencies only: `typescript` 6.0.3, `@types/node` 24.19.2, exact; no runtime dependencies),
  `tsconfig.json`, `runtime.lock` (real Node 24.11.1 and Caddy 2.10.2 arm64 pins), `docs/spec.md`, `docs/setup-checklist.md`,
  `loop/gate.sh` + `loop/probes/arch.sh`.
- `src/ports/` (interfaces of design 5.1): `vault`, `audit`, `meta` (+TokenStore), `events`, `private`, `clock`, `random`,
  `issuer` (Issuer, KeyLister with `listAt`, Verifier), `destination` (Destination, Redeployer, three push outcomes),
  `relay-profile`, `platform` (`PlatformEntry`: id, issuer, lister, relay or denyOnly, verifier, keyPageUrl, shape (no issuer only), destinations,
  required `unverified`; `DestinationKit` lives in `destination`), `approvals`, `notifier`, `push`, `trust`,
  `share`, `minted`, `types`.
- `src/pure/` (no I/O), by concern:
  - Approvals and proofs: `webauthn`, `cose`, `challenge` (every challenge; shared with kb-install), `actions` (closed `Action`
    union), `slots`, `words`, `codes`, `tokens`, `canonical`, `schemas`, `errors`, `address`, `lent`, `pushcrypto`, `pushsub`.
  - Update: `tar`, `release-hash`, `runtime-lock`, `install-request` (core's request and root's answer, one home), `kept-proof`.
  - Relay: `target-parse`, `rule-match`, `profile` (engine and registry checks), `registry-entry` (one shape source, destination kinds),
    `platform-shape` (`shapeOf`: the one shape of an entry or kit), `destination-kind` (the one mapping from the metadata kind
    `vercel_env` to the adapter kind `vercel-env`), `proposal-vet` (`vetAction(registry)`: the adapter condition of each kind; `vetWired`: a kind with no wired executor is refused, derived from `ApproveCore.executorKinds`), `scanner`, `forms` (the one forms library for
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
  `Caddyfile`, `cloud-init.yaml` (its Run Command check writes `/var/lib/keybox/bootstrap-facts.json`, served at
  `GET /api/bootstrap-facts` to a control token; its host firewall step opens 443 only), `keybox-tmpfiles.conf`, `runtime.config.json` (`console_device` UNVERIFIED `/dev/ttyAMA0`,
  `link_mbps`), `egress-hosts.json` (non-adapter hosts: the push services, `nodejs.org`, `github.com`).
- Tests: `test/*.test.ts` named for the behaviour (one file per rule family; the spec's rule ids are in the test titles);
  `test/journeys/` (J2 `relayed-call`, J3 in one process `ordinary-rotation`, J5 `recovery`, J6 `share`, `process-split`
  is root-only); `test/contracts/` (one suite per port, run against the fake); `test/arch*` (architecture probe);
  `test/kit/` (shared helpers; add files, do not edit lines; it must not import `src/pure/{webauthn,cose,challenge}`);
  `test/support/*-world.ts` (`approveWorld`, `rotationWorld`, `routesWorld`, `shareWorld`, `relay-world`, `install-world`);
  `test/support/demo-pages.ts` (a real core on `https://keys.localhost`, state seeded through the real routes, one URL printed per
  page state) and `test/browser/phone-run.ts` + `cdp.ts` (NOT collected by the gate: real Chromium from `~/.cache/ms-playwright`
  over CDP, a virtual WebAuthn authenticator, 390 px screenshots of every page state; run with `runq run --place local
  --why-local display`); `test/fakes/` (platform, platform-entry: `fakeEntry`, `pasteOnlyEntry`, `sourceOf`; destination, push, trust, vault, audit, approvals). New in integration: `main-core.test.ts` (core started
  in process on a `TimedClock`), `platform-source.test.ts`, `share-rotation.test.ts` (real share source over a real rotation).

## Remaining

1. The six adapter units, parallel: `google` (KBOX-24, 41), `vercel` (26, 36), `supabase` (37), `openai` (38), `elevenlabs` (39),
   `paste` (40: Anthropic, Stripe). Each COMMITS A PROBE REPORT FIRST (`docs/probes/<id>.md`) of every UNVERIFIED endpoint named in
   its rule, then code. An adapter adds ONLY `src/platforms/<id>/` and one line in `createRegistry` (`src/platforms/registry.ts`), `create<Name>Entry(deps: RegistryDeps): PlatformEntry` with `deps.http` (the adapter HTTP client: the ONLY way to call the platform) and `deps.clock`. The entry also states `hosts` (exact lower-case DNS names its own calls reach, e.g. `api.vercel.com`; the egress gate refuses any other host for caller `adapter`; a relay-profile host needs no entry in `hosts`). Entry fields:
   `issuer`, `lister`, `relay` or `denyOnly`, `verifier`, `keyPageUrl`, `destinations` (`{destination, redeployer?}` per kind; the kind
   is `destination.kind`), `shape` (only with no issuer; else the issuer's own), `unverified` (ids its probe report marks STILL
   UNVERIFIED; `test/unverified-probes.test.ts` checks it against `docs/probes/<id>.md`). `platform-source`, `main-core` (shapes,
   proposal vet, egress, lend) and the paste flow read the entry; nothing shared changes. `startCore` takes `runtime.registry` for tests.
   An entry with no issuer (paste-only) also states `classify(scope)` (its one class source, like `shape`; the registry check refuses both and
   neither: `classify_twice`, `classify_missing`). `classifierOf` (`src/pure/platform-shape.ts`) reads the one source; `keyConfigFor`
   (`new-key`) serves classify, paste, `newKeyOf` and `retire`. A paste-only key is never `ordinary` through `POST /api/keys` (`no_issuer`).
2. Journeys J1 (setup, then approve a rotation of an admin key), J3 as two real processes (J3 runs in one process today) and J4
   (an update bundle approved and installed, then a bad bundle rolled back). J1 and J3 need the registry; J4 needs the real
   kb-install on a box. J2, J5 and J6 exist.
3. Release downloads into `<H>.bin`: an update that changes a pin is refused (`lock`), unchanged pins work. GitHub release assets
   redirect to a second host that must join `deploy/egress-hosts.json` (caller `update`) when downloads are built.
4. Make the trust request's `deadline` required at root (`src/pure/install-request.ts` still parses it as optional).
5. On the real instance, read `GET /api/bootstrap-facts` once: it shows where the Oracle agent keeps its plugins. The Run Command
   check (a sudoers grant to `ocarun`, a running `runcommand` program) and the firewall step were tested on fixture trees only.
5b. Executors for `delete_key`, `demote`, `set_schedule` (rejected at proposal until built).
6. The `set_allow_rules` executor's widening refusal comes with the adapters (it is `rejected` until one registers, and no code
   reads a key's own allow set but the relay profile narrowing); wire it in the unit that builds that executor, with a test
   through the proposal route.
7. m6 (relay.verdict.md): the canonical re-encoding turns Google's literal `documents:runQuery` into `documents%3ArunQuery`
   (`src/pure/target-parse.ts`, per the spec's rule). Whether Google's front end treats it the same is UNVERIFIED: the `google`
   unit probes it.
8. Decided 2026-11-11 (orchestrator): a revoked generation's value file is deleted (`vault.retire`), so it leaves the share file as
   `none`; only a generation in grace is watched as retired. `KBOX-33` and `KBOX-51` step 10 say so.
9. Open items not fixed: the control enrol window is
   per label only (decided 2026-11-11: accepted residual, see Decisions); `private.db` from before kernel-approve has no
   migration; the phone app ran in real Chromium (test/browser/phone-run.ts) but never on a real phone's browser and passkey;
   findings of the unit verdicts that no fix commit names are in the
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

`platforms` (unit/platforms, fix round): `unverified` is required and a shape-less entry is refused. The older fixture entries
(`test/fixtures/profiles.ts` TEST_REGISTRY, `registry.test.ts`, `relay-forward.test.ts`, `profile-engine.test.ts`, `platform-source.test.ts`) now
carry `unverified: []` and, where the entry has no issuer and is expected to pass, `shape: NO_ISSUER_SHAPE` (exported by
`test/fixtures/profiles.ts`); no assertion changed. The orchestrator test in `test/platform-entry.test.ts` is now two cases over the
real `createPlatformSource` path: the entry's verifier accepts the new key and the run reaches grace, or rejects it and the run fails
with generation 1 current; the world's own verifier is asked in neither. Each new unit test was checked with a planted mutant
(platform-source kit fields, `destination`, `vetAction`, the shape-source check, the probe comparison, `startCore`'s registry check).
Before it: `integrate` (on main after e1fd5e5): rotation wired into core (`startCore`, `platform-source`, executors, routes,
tick and reconcile, stop), `Orchestrator.stop`, retired generations in the share file over the real source, `key.changed` on
every generation status change, and this file. Before it: `rotate` (two adversary fix rounds; verdict "declared not done" named
the wiring and J1/J3), `update` (verdict UNSOUND, fixes merged incl. spec revision 4: approver_add binds the new approver's key
hashes), `relay` and `share` (SOUND WITH FIXES, fixes merged). Detail of those units is in their verdict files and git history.

`platforms-2` (unit/platforms-2): the three `platforms` verdict findings: an issuer-less entry states its own `classify` (one class source,
`classify_twice`/`classify_missing`), the proposal check refuses every kind with no wired executor (`vetWired`, `ApproveCore.executorKinds`), the
probe comparison reads table rows by id cell and checks folders against registry entries. The shape-only fixture entries in `test/registry.test.ts`
and `test/profile-engine.test.ts` gained `classify: NO_ISSUER_CLASSIFY` (orchestrator ruling); the probe-report fixture `REPORT` in
`test/unverified-probes.test.ts` became table rows.

## Adapter HTTP (unit `adapter-http`)

Port `src/ports/http.ts`: `AdapterHttp.request({method, url (absolute https, default port), headers?, body?, timeoutMs?}) -> {status, headers (lower-case, repeats joined), body}`.
Every status (3xx too, never followed) is an answer; only a transport failure rejects, as `HttpTransportError` with `code` one of `refused | unreachable | timeout | too_large | malformed`
(an adapter maps all to `unreachable`). Defaults: timeout `HTTP_TIMEOUT_MS` 30 s for the whole call, body cap `HTTP_BODY_CAP_BYTES` 8 MiB. No header, body or host is in any error. Shell: `src/shell/adapter-http.ts`
(`createAdapterHttp({egress, scheduler, bodyCapBytes?})`, caller `adapter`, `node:http` over the gate's socket, no agent: `createConnection` is ignored when an agent is set).
`refusingAdapterHttp` (ports) is kb-relay's client. Gate: `EgressDeps.registryHosts` (from `PlatformEntry.hosts`, `registryHostsOf`) serve caller `adapter` only; `adapterHosts` (relay profiles) serve relay and adapter.
`checkHosts` (`bad_host`) is part of `checkRegistry`. `main-core` builds the gate lazily (`createLazyEgress`) because the client holds the gate and the registry holds the client.
`REGISTRY` is still exported (built with the refusing client) only because `test/registry.test.ts` and `test/unverified-probes.test.ts` import it; switch them to `createRegistry` and delete it.
Test kit: `test/kit/adapter-http.ts` `adapterHttpTo(target)` (exported from the kit index) sends each request to a loopback server (a `fakePlatform()`), records `sent[].originalHost`.
Tests: `test/adapter-http.test.ts`.
Fix round (adapter-http-2):
- The call's timeout is a whole-call deadline: `egress.open` races the signal during the lookup and refuses an already-aborted signal before resolving or connecting.
- Every failure of `request` is an `HttpTransportError`; new code `invalid_request` (node threw for a header name or value or the method; no text kept); a non-refusal gate failure is `unreachable`.
- `loadEgressHosts(file?)` (egress-system.ts) reads and checks `deploy/egress-hosts.json`; `startCore` calls it first (`CoreRuntime.egressHostsFile` for tests), `createLazyEgress(registry, listed)` binds only the registry's hosts late.
- `addressRefused` also refuses 6to4, Teredo, both NAT64 prefixes (whole, no embedded-v4 check) and 192.88.99/24. The IPv4 documentation ranges stay allowed (they reach no private network; test fixtures use 203.0.113.10 as the public answer).
- `createRelayRegistry(clock, create?)` (platforms/registry.ts) is what main-relay builds its registry with (refusing client); tests pin it, plus the slow-drip body.
