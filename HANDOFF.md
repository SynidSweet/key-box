# HANDOFF — codebase map and loop state

Fresh-context loop state: this file and the code are the only channels.
REWRITE it (never append) before you finish. Unchanged fails.

## Where things stand

Main is `b02e3de`. Stages 1 to 4 and the adapter stage are built and on main. `src/main-core.ts`: `startCore(env, runtime)` (exported;
`main()` is `startCore` plus SIGTERM/SIGINT) serves the machine API, the share file and, when `KB_DOMAIN` is set, the phone app,
approvals, the real `TrustPort`, the update intake and rotation (key routes, paste, deliveries, the hourly tick, the daily reconcile).

The registry (`createRegistry`, `src/platforms/registry.ts`) holds `anthropic`, `elevenlabs`, `google`, `openai`, `stripe`, `supabase`,
`vercel`. Google is the identity half, the box-made signing key (KBOX-55) and the API-key adapter (KBOX-59).

Executors wired in `startCore` (the `executors` map): `install_update`, `rotate_key` and `add_key` (via rotation), `set_schedule` and
`demote` (KBOX-60, `src/shell/key-executors.ts`), `set_allow_rules` (KBOX-61), and the Vercel operations (KBOX-26: `vercel_set_domain` and
`vercel_set_team_setting` are approvals; project creation is a direct route). `delete_key` has no executor yet and is `rejected` at
proposal (`vetWired`): its design waits on owner card C-751 (when a key is deleted, end it at its service, or only forget it).

KBOX-60's crash rule: at start (`openApproveCore`, before anything is served) every `approved` approval with no recorded result is
recorded `failed` / `interrupted` with one `box.notice` (`approval interrupted`) and is never re-run, except `install_update`,
`rotate_key` and `add_key`, which resume themselves (`interruptStranded`, `src/shell/approvals.ts`).

Spec: `docs/spec.md` (Build units table at the end). Verdicts: `/home/petter/.local/share/lanes/key-box/<unit>.verdict.md`.

## Codebase map

- Root: `package.json` (dev dependencies only: `typescript` 6.0.3, `@types/node` 24.19.2, exact; no runtime dependencies),
  `tsconfig.json`, `runtime.lock` (real Node 24.11.1 and Caddy 2.10.2 arm64 pins), `docs/spec.md`, `docs/setup-checklist.md`,
  `docs/probes/<id>.md` (one probe report per adapter), `loop/gate.sh` + `loop/probes/arch.sh`.
- `src/ports/` (interfaces of design 5.1): `vault`, `audit`, `meta` (+TokenStore), `events`, `private`, `clock`, `random`,
  `issuer` (Issuer, KeyLister with `listAt`, Verifier), `destination` (Destination, Redeployer, three push outcomes),
  `relay-profile`, `platform` (`PlatformEntry`: id, issuer, lister, relay or denyOnly, verifier, keyPageUrl, shape (no issuer only),
  destinations, `hosts`, `location`, `boxKey`, Vercel `operations`, required `unverified`; `DestinationKit` lives in `destination`),
  `http` (`AdapterHttp`), `approvals`, `notifier`, `push`, `trust`, `share`, `minted`, `types`.
- `src/pure/` (no I/O), by concern:
  - Approvals and proofs: `webauthn`, `cose`, `challenge` (every challenge; shared with kb-install), `actions` (closed `Action`
    union), `slots`, `words`, `codes`, `tokens`, `canonical`, `schemas`, `errors`, `address`, `lent`, `pushcrypto`, `pushsub`.
  - Update: `tar`, `release-hash`, `runtime-lock`, `install-request` (core's request and root's answer, one home), `kept-proof`.
  - Relay: `target-parse` (`relayAddressOf`), `rule-match`, `profile` (engine and registry checks), `registry-entry` (one shape
    source, destination kinds), `platform-shape` (`shapeOf`, `classifierOf`: the one shape and class source of an entry or kit),
    `destination-kind` (metadata kind `vercel_env` to adapter kind `vercel-env`), `proposal-vet` (`vetAction(registry)`: the adapter
    condition of each kind; `vetWired`: a kind with no wired executor is refused, derived from `ApproveCore.executorKinds`), `scanner`,
    `forms` (one forms library for the scanner and the share writer), `lend-protocol`, `relay-errors`, `egress-policy`,
    `location` (KBOX-57), `project-host`.
  - Rotation: `rotation-machine` (steps, intent name, retry delay), `scheduler` (due dates, staggering), `class` (class never
    lowered, KBOX-16).
  - Share: `coverage` (watch tier), `share-build` (format v3, envelope).
- `src/shell/` (adapters and wiring), by concern:
  - Kernel: `core.ts` (`openCore`: meta.db, audit, events, vault, control routes), `db`, `meta`, `meta-schema`, `migrations`
    (additive only, KBOX-56), `audit`, `events`, `vault-fs`, `http` (frame), `routes-control`, `private-db`, `clock`, `random`.
  - Approval half: `approve-core` (`openApproveCore`), `approvers`, `approvals`, `tokens`, `routes-approve`, `push`,
    `push-transport`, `console`, `idle-watch`.
  - Update: `updater` (core's intake, `POST /api/updates`), `trust-installer` (real `TrustPort`), `installer` + `safe-open` +
    `systemd` (kb-install's root half; `src/cli/kb-install.ts`), `src/cli/kb-code.ts`.
  - Relay: `relay-http` (kb-relay on its own socket; `src/main-relay.ts`), `lend-core` + `lend-socket` (core's lend side),
    `minted-values`, `egress` + `egress-system` (the one outbound gate; hosts from the registry and `deploy/egress-hosts.json`),
    `adapter-http`.
  - Rotation: `rotation.ts` (`openRotation`: the one wiring), `orchestrator` (runs, `stop()` cancels run timers), `reconcile`,
    `revoke-confirm`, `rotation-store`, `rotation-ports` (`PlatformSource`, `PlatformKit`, `Point`), `platform-source`
    (`createPlatformSource`: registry to kits, master key = current generation of the platform's master-class key row),
    `key-routes` (`/api/keys`, `/api/rotations`, `/api/retired`), `deliveries`, `paste` (phone paste flow), `new-key`.
  - Executors and identity: `key-executors` (`set_schedule`, `demote`, `set_allow_rules`, and the one check each makes at proposal and
    at execution), `vercel-routes` (`createVercelOps`; `POST /api/vercel/{projects,domains,settings}`), `box-keys` (`ensureBoxKeys`,
    `refuseBoxKeyAction`), `identity-routes`, `grant-checks`.
  - Share: `share-source` (admin and master keys; retired generations from the rotation store's `grace` and `retired` rows),
    `share-writer` (`GET /api/share`, `share.version`).
- `src/platforms/`: `registry.ts` (`createRegistry(deps)`, one line per adapter; `createRelayRegistry` is kb-relay's, built with the
  refusing client; `REGISTRY` is the same list with the refusing client, still imported by `test/registry.test.ts` and
  `test/unverified-probes.test.ts`: switch them to `createRegistry` and delete it) and one folder per adapter, each with an
  `unverified.json` (ids its probe report marks STILL UNVERIFIED; `test/unverified-probes.test.ts` checks it):
  - `anthropic`, `stripe`: paste-only (no issuer; the entry states its own `shape` and `classify`).
  - `elevenlabs`, `openai`: issuer, lister, verifier, relay profile.
  - `supabase`: project-host relay profile, personal access token beside project keys (KBOX-58), secret destination.
  - `vercel`: env destination, redeployer, `operations.ts` and `team-settings.ts` (KBOX-26).
  - `google`: identity half (`oidc`, `minter`, `grant-check`, box-made `signing-key`, KBOX-55) and the API-key adapter (KBOX-59:
    `issuer`, `lister`, `verifier`, `secret-destination`, `relay`).
  Each entry is built from `RegistryDeps` (`http`, `clock`) and states `hosts` (exact DNS names its own calls reach; the egress gate refuses
  any other host for caller `adapter`; a relay-profile host needs no entry). `platform-source`, `main-core` (shapes, proposal vet, egress,
  lend) and the paste flow read the entry. `startCore` takes `runtime.registry` for tests. The registry check refuses an issuer-less entry
  with both or neither of `shape` and `classify` (`classify_twice`, `classify_missing`); a paste-only key is never `ordinary` through
  `POST /api/keys` (`no_issuer`).
- Adapter HTTP: port `src/ports/http.ts` `AdapterHttp.request({method, url (absolute https), headers?, body?, timeoutMs?})` returns
  `{status, headers (lower-case), body}`. Every status (3xx too, never followed) is an answer; only a transport failure rejects, as
  `HttpTransportError` (`refused | unreachable | timeout | too_large | malformed | invalid_request`; an adapter maps all to
  `unreachable`). Whole-call timeout `HTTP_TIMEOUT_MS` 30 s, body cap 8 MiB; no header, body or host is in any error. Shell
  `createAdapterHttp` is caller `adapter` over the egress gate. `EgressDeps.registryHosts` (`PlatformEntry.hosts`) serve caller `adapter`
  only; `adapterHosts` (relay profiles) serve relay and adapter; `checkHosts` (`bad_host`) is part of `checkRegistry`. `main-core` builds
  the gate lazily (`createLazyEgress`) because the client holds the gate and the registry holds the client. `addressRefused` also refuses
  6to4, Teredo, both NAT64 prefixes and 192.88.99/24. Test kit: `test/kit/adapter-http.ts` `adapterHttpTo(target)` sends each request to a
  loopback `fakePlatform()`.
- Relay address (KBOX-13, KBOX-32): `/r/<keyref with each "/" written "~">` (`relayAddressOf`, `src/pure/target-parse.ts`); it is accepted
  only when it decodes to a stored keyref shape. `lend-protocol` keyref text follows the same shape.
- Env names `src/` reads: core `KB_STATE_DIR`, `KB_SOCKET`, `KB_LEND_SOCKET`, `KB_DOMAIN`, `KB_INSTALL_RESULTS`, `KB_CURRENT`,
  `KB_OIDC_AUDIENCE` (with `KB_DOMAIN` it makes core create the box-made Google signing key at start, KBOX-55; absent, every mint refuses);
  kb-relay `KB_RELAY_SOCKET`, `KB_LEND_SOCKET`, `KB_DOMAIN`; kb-install `KB_STAGING_DIR`, `KB_RELEASES_DIR`, `KB_CURRENT`, `KB_TRUST_FILE`,
  `KB_CODES_DIR`, `KB_INSTALL_RESULTS`, `KB_BOOT_ID_FILE`, `KB_DOMAIN`, `KB_SYSTEMCTL`, `KB_CORE_SOCKET`, `KB_RELAY_SOCKET`; kb-code
  `KB_RUNTIME_CONFIG`, `KB_CODES_DIR`, `KB_BOOT_ID_FILE`, `KB_TRUST_FILE`.
- `src/web/`: the phone app, plain JS under `checkJs` (`app.js`, `setup.*`, `recover.*`, `register.js`, `paste.*`, `sw.js`).
- `src/data/`: `wordlist.txt`, `push-hosts.json`, `credential-shapes.json`.
- `deploy/`: `keybox.service`, `keyrelay.service`, `kb-code.service`, `kb-install.service` + `.path`, `caddy.service`,
  `Caddyfile`, `cloud-init.yaml` (its Run Command check writes `/var/lib/keybox/bootstrap-facts.json`, served at
  `GET /api/bootstrap-facts` to a control token; its host firewall step opens 443 only), `keybox-tmpfiles.conf`, `runtime.config.json`
  (`console_device` UNVERIFIED `/dev/ttyAMA0`, `link_mbps`), `egress-hosts.json` (non-adapter hosts: the push services, `nodejs.org`,
  `github.com`).
- Tests: `test/*.test.ts` named for the behaviour (one file per rule family; the spec's rule ids are in the test titles);
  `test/journeys/` (J2 `relayed-call`, J3 in one process `ordinary-rotation`, J5 `recovery`, J6 `share`, `process-split` is root-only);
  `test/contracts/` (one suite per port, run against the fake); `test/arch*` (architecture probe); `test/kit/` (shared helpers; add
  files, do not edit lines; it must not import `src/pure/{webauthn,cose,challenge}`); `test/support/*-world.ts` (`approveWorld`,
  `rotationWorld`, `routesWorld`, `shareWorld`, `relay-world`, `install-world`); `test/support/demo-pages.ts` (a real core on
  `https://keys.localhost`, state seeded through the real routes, one URL printed per page state) and `test/browser/phone-run.ts` +
  `cdp.ts` (NOT collected by the gate: real Chromium from `~/.cache/ms-playwright` over CDP, a virtual WebAuthn authenticator, 390 px
  screenshots of every page state; run under `runq` with `--class browser`); `test/fakes/` (platform, platform-entry: `fakeEntry`,
  `pasteOnlyEntry`, `sourceOf`; destination, push, trust, vault, audit, approvals); `test/fixtures/profiles.ts` (`TEST_REGISTRY`,
  `NO_ISSUER_SHAPE`, `NO_ISSUER_CLASSIFY`); `main-core.test.ts` starts a core in process on a `TimedClock`.

## Remaining

1. `delete_key` executor, after owner card C-751. It is a run (stop, revoke and confirm, purge). KBOX-56 allows additive migrations only and
   foreign keys are ON, so "delete the key row, keep generations and runs" needs a design first.
2. Journeys J1 (setup, then approve a rotation of an admin key), J3 as two real processes (J3 runs in one process today) and J4
   (an update bundle approved and installed, then a bad bundle rolled back). J1 and J3 need the registry; J4 needs the real
   kb-install on a box. J2, J5 and J6 exist.
3. Release downloads into `<H>.bin`: an update that changes a pin is refused (`lock`), unchanged pins work. GitHub release assets
   redirect to a second host that must join `deploy/egress-hosts.json` (caller `update`) when downloads are built.
4. Make the trust request's `deadline` required at root (`src/pure/install-request.ts` still parses it as optional).
5. On the real instance, read `GET /api/bootstrap-facts` once: it shows where the Oracle agent keeps its plugins. The Run Command
   check (a sudoers grant to `ocarun`, a running `runcommand` program) and the firewall step were tested on fixture trees only.
6. Probes: ids still listed in an adapter's `unverified.json` are UNVERIFIED (Google API-key rotations wait on
   `google.apikey-verify-call`). A live SDK run through the relay with a `~` address has not been done.
7. m6 (relay.verdict.md) is closed: `docs/probes/google.md` row `google.colon-encoding` is VERIFIED (the front end does not decode `%3A`
   in a verb), and the canonical path keeps `:` literal (`PATH_LITERAL`, `src/pure/target-parse.ts:122`), so `documents:runQuery` passes as is.
8. Open items not fixed: the control enrol window is per label only (accepted residual, see Decisions); `private.db` from before
   kernel-approve has no migration; the phone app ran in real Chromium but never on a real phone's browser and passkey; findings of the
   unit verdicts that no fix commit names are in the verdict files.
9. Tidy: `ports/platform.ts` carries Vercel-only types (`operations?`, `vetSetting?`) on the generic `PlatformEntry`. Google: a disabled
   key is still DELETEd once by the sweep; the Secret Manager destination `remove` throws `remove_unsupported`.

## Decisions

- Node 24 LTS; `typescript` 6.0.3. Silent-catch rule strict (throw, return a non-empty value, or `audit.append` / `notifier.*`
  on every path), `src/` and `test/`. No `any`, `!`, ts or eslint suppressions anywhere.
- Control enrol window per label only: not built, accepted residual (orchestrator, 2026-11-11). The fix would make the owner copy a
  hash off a machine and buys nothing under S-717 (relay passes are not pinned and every machine is agent-controlled).
- Rotation is opened only with the approval half (`KB_DOMAIN` set), because it needs `approvals` and `approvers`; a box with no domain
  has no key, rotation or paste route. The approval executors reach rotation late (`viaRotation`), since rotation is built from the
  approval half that takes the executors. `rotation.run()` is awaited after the server listens, with no catch: a failed resume stops
  the start, loudly.
- The platform's master key is the first master-class key row of that platform, current generation, lent from the vault; none gives a
  `RangeError` that the orchestrator audits (`drive_failed`). KBOX-36 says the owner pastes it once; no spec text names the row, so this
  is a reading.
- `RotationStore.setGenStatus` writes `key.changed`, so a retirement, a grace and a promote each give the share writer a new version.
  `Orchestrator.stop()` and `startCore().stop()` cancel run timers and are idempotent.
- `createMetaShareSource({generations})` is optional so fake-store tests keep the old shape; main-core passes the rotation store's `gens`.
  A pending or failed generation is not listed.
- A revoked generation's value file is deleted (`vault.retire`) and leaves the share file as `none`; only a generation in grace is watched
  as retired (KBOX-33, KBOX-51 step 10).
- The relay address of a key is its keyref with `/` written `~` (KBOX-13, revised 2026-11-13): the earlier `[a-z0-9]{6,24}` matched no
  real keyref.
- A key's own allow set only narrows its profile; any change, even back to the whole profile, needs the phone (KBOX-61).
- Probe `arch` is the gate's architecture step. `GATE_PINNED_PATHS` pins `loop/probes/arch.sh` and `tsconfig.json`; lockfile pinned.
- Planted mutants (scratch copies, one `runq` run) stand in for missed red steps.
- Tests that pin a rule a correct change must break are retired only in their own unit, naming the reason and the behaviour pinned,
  reviewed by the stronger reviewer (owner law S-795). Builders never edit pre-existing tests.

## Gotchas

- Run the gate under `runq` naming the skill path, from inside the clone: `runq run --why "<why>" -- bash -c "env
  LOOP_SKILL_DIR=/home/petter/.claude/skills/deterministic-gates LOOP_WORKDIR=<tree> LOOP_BASE_COMMIT=<sha> bash loop/gate.sh"`. Needs
  Docker. The base is main's head before the merge.
- The guard refuses `node`, `python3` and other interpreters outside `runq run`, and blocks the whole command line: edit with the Edit
  tool, run tests as `runq run --why "<why>" -- node --test <file>`. Never `--place`.
- Plain `node --test` runs EVERY file under `test/`; helpers there must do nothing when run directly.
- Other runq jobs may run remotely with a synced tree: a script outside the repo is not there.
- A bearer token on any phone path (even an unknown one like `/r/x`) is 403 from the frame.
- `startCore` takes a `CoreRuntime` (clock, scheduler, random, journal): a test passes a `TimedClock` and checks
  `pendingTimers === 0` after `stop()`. It reads the real egress gate; set `KB_INSTALL_RESULTS` and `KB_CURRENT` to temp paths. The
  idle watch (KBOX-21) reads only the `/proc` files `runtime.proc` names (`systemRuntime` names the real ones); a test runtime names none,
  so a test core holds no reserve. Before that fix every in-process core with `KB_DOMAIN` held 30% of the HOST's memory (~14 GB).
  `test/setup.test.ts:193` still spawns a real core through `main()` with `KB_DOMAIN`, so that one process still holds the reserve.
- `vault.lend` of a retired generation throws `unknown_key`; `shareValuesIn` turns that into `''`.
- A spec rule that lands before its code gets its own Build units row; every KBOX id sits in exactly one row.

## Recent

- `paste-master` (b02e3de): the paste check hands a `needsMaster` verifier the master KBOX-57 chooses (KBOX-58, as the run and the
  revoke check already did); before it a pasted Google API key could only verify `unreachable`. Test `test/paste-master.test.ts`.
- `idle-runtime` (fa4c66d): `CoreRuntime.proc` names the idle watch's `/proc` files; a test runtime names none (KBOX-21). Test
  `test/core-idle.test.ts`.
- `relay-ref` (b57bcab): the relay address of a real key is the keyref with `/` written `~` (KBOX-13, KBOX-32); two pins of the old
  address shape were retired first in their own commit (82e1a37, S-795). Before it `vercel-ops` (48f287b, KBOX-26), `allow-rules`
  (5e21c8b, KBOX-61) and `executors-meta` (3854150, KBOX-60).
