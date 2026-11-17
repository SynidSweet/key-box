# HANDOFF — codebase map and build state

Read this first, then `docs/spec.md`. It serves whoever builds next (mission control's pipeline; no session that knows the history
is left): this file and the code are the channels. REWRITE it (never append) when you finish; an unchanged file is stale.

## Where things stand

Main is `e1960a1`, tag `v2`. All spec units are built except `google-jwks` (see Remaining). Release v2 is the box on a Raspberry Pi 3 B+
(1 GB, arm64, Ubuntu Server 24.04 raspi image) reached over Tailscale at `keybox.tail09a879.ts.net`: phone pages on `https://<host>:8443`,
machine API and relay on `https://<host>` (443). The owner has not done the first boot yet; nothing has run on the real Pi.

Release v2: tag `v2` is commit `e1960a1c8e17db1fbfb3816c86aa0e572b02b399`, content hash H `0c3e893542ec55a001be0fc6291a3075760cc8b814858e3bf0f6dbcf31fc8469`
(563 files), time floor `1794761629`. The release asset `user-data` is `deploy/cloud-init.yaml` with five value lines filled
(`scripts/render-user-data.ts`); H comes from `scripts/release-hash.sh`; `scripts/vm-acceptance.sh` booted that exact file twice in an offline
VM, 9/9 checks passed. Release v1 (`f68e398`, Oracle era) is superseded. A new release repeats those three steps.

`src/main-core.ts`: `startCore(env, runtime)` (exported; `main()` is `startCore` plus SIGTERM/SIGINT) serves the machine API, the share
file and, when `KB_DOMAIN` is set, the phone app, approvals, the real `TrustPort`, the update intake and rotation (key routes, paste,
deliveries, the hourly tick, the daily reconcile). `KB_DOMAIN` now holds the full Tailscale host; `trust.json` keeps its field `domain`.

The registry (`createRegistry`, `src/platforms/registry.ts`) holds `anthropic`, `elevenlabs`, `google`, `openai`, `stripe`, `supabase`,
`vercel`. Google is the identity half (KBOX-55 box-made signing key) and the API-key adapter (KBOX-59); its JWKS publish and the
Google identity as a whole stay off until `google-jwks`.

Executors wired in `startCore` (the `executors` map): `install_update`; `rotate_key`, `add_key` and `delete_key` (all three via
rotation, `viaRotation`); `set_schedule` and `demote` (KBOX-60, `src/shell/key-executors.ts`); `set_allow_rules` (KBOX-61); the Vercel
operations (KBOX-26: `vercel_set_domain` and `vercel_set_team_setting` are approvals; project creation is a direct route).

Deleting a key (KBOX-62, S-816): the approved `delete_key` opens a deletion (`key-delete.ts`, `delete-run.ts`, ledger `deletion-store.ts`,
meta.db migration 3); it ends the key, waits until the platform refuses every live generation twice, then erases; it never gives up.

KBOX-60's crash rule: at start (`openApproveCore`, before anything is served) every `approved` approval with no recorded result is
recorded `failed` / `interrupted` with one `box.notice` and never re-run, except `install_update`, `rotate_key`, `add_key` and
`delete_key`, which resume themselves (`RESUMES_ITSELF`, `src/shell/approve-core.ts`).

Spec: `docs/spec.md` (Revision 5 is the Pi and Tailscale move, KBOX-63..67; units: the Build units table at the end for the earlier
revisions, and Revision 5's own list in its section). Setup guide for the owner:
`docs/setup-checklist.md`. The lane that built v2 (`api-keys-design`) handed over on 2026-11-17; its design
(`briefs/pi-tailnet.spec.md`, cited by the spec as "design 3.x") and unit verdicts are in `/home/petter/.local/share/lanes/key-box/`,
outside the repo.

## Codebase map

- Root: `package.json` (dev dependencies only: `typescript` 6.0.3, `@types/node` 24.19.2, exact; no runtime dependencies),
  `tsconfig.json`, `runtime.lock` (Node 24.11.1 and Caddy 2.10.2 arm64 pins), `docs/spec.md`, `docs/setup-checklist.md`,
  `docs/probes/<id>.md` (one probe report per adapter), `loop/gate.sh` + `loop/probes/arch.sh`.
- `scripts/` (release tooling, not in the running box): `release-hash.sh` (H of a commit as the bootstrap computes it, cross-checked with
  `src/pure/release-hash.ts`), `release-hash-tree.ts`, `render-user-data.ts` (cloud-init plus five values; `src/pure/release-userdata.ts`),
  `vm-acceptance.sh` (hermetic offline VM boot of a `user-data`, needs `/dev/kvm` and docker, about 20 minutes).
- `src/ports/` (interfaces of design 5.1): `vault`, `audit`, `meta` (+TokenStore), `events`, `private`, `clock`, `random`,
  `issuer` (Issuer, KeyLister with `listAt`, Verifier), `destination` (Destination, Redeployer, `DestinationKit`), `relay-profile`,
  `platform` (`PlatformEntry`: id, issuer, lister, relay or denyOnly, verifier, keyPageUrl, shape, destinations, `hosts`, `location`,
  `boxKey`, Vercel `operations`, required `unverified`), `http` (`AdapterHttp`), `approvals`, `notifier`, `push`, `trust`, `share`,
  `minted`, `types`.
- `src/pure/` (no I/O), by concern:
  - Approvals and proofs: `webauthn`, `cose`, `challenge` (every challenge; shared with kb-install), `actions` (closed `Action` union),
    `slots`, `words`, `codes`, `tokens`, `canonical`, `schemas`, `errors`, `address`, `lent`, `pushcrypto`, `pushsub`.
  - Host and time: `box-origins` (the only place that composes an origin: `pagesOrigin`, `machineOrigin`, `relayUrl`, `oidcIssuer`),
    `host-name` (`sameHostName`, the one node-name comparison), `time-gate` (`TIME_OK_FILE`, `/run/keybox-time/ok`), `bench` (the Pi's
    budgets), `qr` (QR encoder, byte mode, level M, versions 1-10, half-block text for tty1).
  - Update: `tar`, `release-hash`, `release-userdata`, `runtime-lock`, `install-request`, `kept-proof`.
  - Relay: `target-parse` (`relayAddressOf`), `rule-match`, `profile`, `registry-entry`, `platform-shape`, `destination-kind`,
    `proposal-vet` (`vetAction(registry)`; `vetWired` refuses a kind with no wired executor), `scanner`, `forms`, `lend-protocol`,
    `relay-errors`, `egress-policy`, `location` (KBOX-57), `project-host`.
  - Rotation: `rotation-machine`, `scheduler`, `class` (class never lowered, KBOX-16). Share: `coverage`, `share-build` (format v4).
- `src/shell/` (adapters and wiring), by concern:
  - Kernel: `core.ts` (`openCore`: meta.db, audit, events, vault, control routes; writes `box_info.oidc_issuer` when a domain is set),
    `db` (`synchronous=FULL`), `meta`, `meta-schema`, `migrations` (additive only, KBOX-56), `audit`, `events`, `vault-fs`, `http`,
    `routes-control` (incl. `GET /api/bootstrap-facts`), `private-db`, `clock`, `random`, `facts-file` (the one writer of the facts file).
  - Approval half: `approve-core` (`openApproveCore`), `approvers`, `approvals`, `tokens`, `routes-approve`, `push`, `push-transport`,
    `console` (root side of the setup and recovery codes).
  - Update: `updater` (core's intake, `POST /api/updates`), `trust-installer` (real `TrustPort`), `installer` + `safe-open` + `systemd`
    (kb-install's root half; `systemd.ts` has `selfCheck` and `joinCheck`), `update-rehearsal` (kb-bench's rehearsal).
  - Relay: `relay-http` (kb-relay; `src/main-relay.ts`), `lend-core` + `lend-socket`, `minted-values`, `egress` + `egress-system` (the one
    outbound gate; hosts from the registry and `deploy/egress-hosts.json`), `adapter-http`.
  - Rotation: `rotation.ts` (`openRotation`: the one wiring), `orchestrator`, `reconcile`, `revoke-confirm`, `proof-watch` (KBOX-51 step
    10: the one exit from `grace`), `rotation-store`, `rotation-ports`, `platform-source` (registry to kits; master chosen by KBOX-57),
    `key-routes` (`/api/keys`, `/api/rotations`), `deliveries`, `paste`, `new-key`.
  - Deletion: `key-delete` (the check, executor, page facts, start-up settle), `delete-run`, `deletion-store`.
  - Executors and identity: `key-executors`, `vercel-routes` (`POST /api/vercel/{projects,domains,settings}`), `box-keys`,
    `identity-routes`, `grant-checks`. Share: `share-source`, `share-writer` (`GET /api/share`, `share.version`).
- `src/cli/` (root and boot-time programs, all run from `/opt/keybox/current` by source): `kb-install` (KBOX-6; refuses everything until the
  time gate file exists), `kb-code` (modes `setup`, `recovery`, `boot`; codes to tty1 only, address as text and QR), `kb-join` (KBOX-64:
  modes `join`, `ready`, `--self-check`: authenticated time, Tailscale join, name check, writes the time gate and the `join` facts; `ready`
  waits for the certificate on :8443 and records start times and memory), `kb-bench` (first-start unit costs and update rehearsal).
- `src/platforms/`: `registry.ts` (`createRegistry(deps)`, one line per adapter; `createRelayRegistry` is kb-relay's; `REGISTRY` is the same
  list with the refusing client, still imported by `test/registry.test.ts`, `test/unverified-probes.test.ts`, `test/main-core.test.ts` and
  `test/delete-key.test.ts`) and one folder per adapter, each with an `unverified.json` (ids its probe report marks STILL UNVERIFIED):
  - `anthropic`, `stripe`: paste-only (no issuer; the entry states its own `shape` and `classify`).
  - `elevenlabs`, `openai`: issuer, lister, verifier, relay profile. `supabase`: project-host relay profile, personal access token (KBOX-58).
  - `vercel`: env destination, redeployer, `operations.ts` and `team-settings.ts` (KBOX-26).
  - `google`: identity half (`oidc`, `minter`, `grant-check`, `signing-key`) and the API-key adapter (`issuer`, `lister`, `verifier`,
    `secret-destination`, `relay`).
  Each entry states `hosts` (exact DNS names its own calls reach; the egress gate refuses any other host for caller `adapter`).
  The registry check refuses an issuer-less entry with both or neither of `shape` and `classify`; a paste-only key is never `ordinary`.
- Adapter HTTP: `AdapterHttp.request({method, url (absolute https), headers?, body?, timeoutMs?})` returns `{status, headers, body}`.
  Every status (3xx never followed) is an answer; only a transport failure rejects, as `HttpTransportError`. `HTTP_TIMEOUT_MS` 30 s, body
  cap 8 MiB. `createAdapterHttp` is caller `adapter` over the egress gate; `main-core` builds the gate lazily (`createLazyEgress`).
  Test kit: `test/kit/adapter-http.ts` `adapterHttpTo(target)` sends each request to a loopback `fakePlatform()`.
- Relay address (KBOX-13, KBOX-32): `https://<host>/r/<keyref with each "/" written "~">` (`relayAddressOf`, `src/pure/target-parse.ts`).
- Env names `src/` reads: core `KB_STATE_DIR`, `KB_SOCKET`, `KB_LEND_SOCKET`, `KB_DOMAIN`, `KB_INSTALL_RESULTS`, `KB_CURRENT`,
  `KB_OIDC_AUDIENCE`; kb-relay `KB_RELAY_SOCKET`, `KB_LEND_SOCKET`, `KB_DOMAIN`; kb-install `KB_STAGING_DIR`, `KB_RELEASES_DIR`,
  `KB_CURRENT`, `KB_TRUST_FILE`, `KB_CODES_DIR`, `KB_INSTALL_RESULTS`, `KB_BOOT_ID_FILE`, `KB_DOMAIN`, `KB_SYSTEMCTL`, `KB_CORE_SOCKET`,
  `KB_RELAY_SOCKET`, `KB_TIME_OK_FILE` (unset means no gate); kb-code `KB_RUNTIME_CONFIG`, `KB_CODES_DIR`, `KB_BOOT_ID_FILE`,
  `KB_TRUST_FILE`, `KB_DOMAIN`; kb-join `KB_DOMAIN`, `KB_TIME_FLOOR`, `KB_TRUST_FILE`, `KB_TTY`, `KB_STATE_DIR`, `KB_INSTALL_RESULTS`,
  `KB_CORE_SOCKET`, `KB_RELAY_SOCKET`; kb-bench `KB_STATE_DIR`, `KB_CURRENT`, `KB_INSTALL_RESULTS`, `KB_TIME_OK_FILE`.
  `KB_FS_ROOT` is only cloud-init's test prefix.
- `src/web/`: the phone app, plain JS under `checkJs` (`app.js`, `setup.*`, `recover.*`, `register.js`, `paste.*`, `sw.js`).
  `src/data/`: `wordlist.txt`, `push-hosts.json`, `credential-shapes.json`.
- `deploy/`: services `keybox`, `keyrelay`, `caddy`, `kb-code`, `kb-install` (+ `.path`), `kb-join`, `kb-ready`, `kb-firewall`;
  `Caddyfile` (`{$KB_DOMAIN}:8443` pages to core, `{$KB_DOMAIN}:443` `/api/*` to core and `/r/*` to the relay; certificates through
  `get_certificate tailscale`); `keybox-nftables.nft` (own table `inet keybox`); `chrony.conf` (NTS only); `resolved-keybox.conf`;
  `tailscaled.defaults`, `tailscale.sources`, `tailscale-archive-keyring.asc`; `keybox-tmpfiles.conf`; `runtime.config.json`
  (`console_device` `/dev/tty1`); `egress-hosts.json` (non-adapter hosts: the push services, `nodejs.org`, `github.com`);
  `cloud-init.yaml` (the Pi bootstrap: ssh purged, hardening, stage-0 time, apt over `https://ports.ubuntu.com`, release download and H
  check, firewall, chrony and tailscale, `kb-bench`, `kb-ready`, the setup code; each step writes `/var/lib/kb-bootstrap/step`).
- Tests: `test/*.test.ts` named for the behaviour (the spec's rule ids are in the test titles); `test/journeys/` (J2 `relayed-call`, J3 in
  one process `ordinary-rotation`, J5 `recovery`, J6 `share`, `process-split` is root-only); `test/contracts/` (one suite per port, run
  against the fake); `test/arch*` (architecture probe); `test/kit/` (shared helpers; add files, do not edit lines; it must not import
  `src/pure/{webauthn,cose,challenge}`); `test/support/*-world.ts` (`approveWorld`, `rotationWorld`, `routesWorld`, `shareWorld`,
  `relay-world`, `install-world`, `delete-world`, `google-world`, `vercel-world`, `lend-world`) and `demo-pages.ts` (a real core, one URL
  printed per page state); `test/browser/phone-run.ts` + `cdp.ts` (NOT collected by the gate: real Chromium over CDP, a virtual
  WebAuthn authenticator, 390 px screenshots; run under `runq` with `--class browser`); `test/fakes/` (platform, platform-entry:
  `fakeEntry`, `pasteOnlyEntry`, `sourceOf`; per-platform API fakes; destination, push, trust, vault, audit, approvals);
  `test/fixtures/` (`profiles.ts`, `share-v4`, `qr`, `webauthn`, `forms`); deploy text tests: `deploy-units`, `deploy-order`,
  `bootstrap-pi`, `bootstrap-hardening`, `caddy-tailnet`, `release-userdata`, `checklist-pi`.

## Remaining

1. `google-jwks` (KBOX-41, KBOX-47, KBOX-55) with its own S-795 retirement unit `retire-jwks-served`; Google stays off until then. The
   local branch `unit/google-a` is an earlier attempt at the identity half, superseded by `google-a` on main (`5ccedfe`); do not build on it.
2. After the owner's first boot: read `GET /api/bootstrap-facts` once (`bench`, `bench.over`; any `update.*` item over budget is settled
   before any key is pasted), and confirm what only the real Pi shows: the Tailscale certificate through Caddy's `get_certificate
   tailscale`, chrony NTS time from a cold clock and chrony held until then, the radios soft-blocked through `/sys/class/rfkill`,
   config.txt's `[all]` lines, apt over `https://ports.ubuntu.com`, the setup QR on tty1. Then mission control sets `MC_KEYBOX_ORIGIN` and
   each machine is enrolled with the owner's phone approval. No agent ever gets a login, root or console on the box.
3. Checked against the code on `e1960a1`:
   - `delete_key` executor: built (KBOX-62; `src/main-core.ts:232` wires it, `src/shell/rotation.ts:124` is the executor). Not open.
   - Journeys J1 and J4: still open, no file in `test/journeys/` (J1 setup then an admin rotation; J4 an update approved, installed,
     then a bad bundle rolled back). J3 still runs in one process (`test/journeys/ordinary-rotation.test.ts:1`); the two-process J3 is open.
   - Release downloads into `<H>.bin`: still open. Core only reads and cleans `<H>.bin` (`src/shell/updater.ts:24,144`) and the installer
     refuses a changed pin without it (`src/shell/installer.ts:278-301`, `lock`); nothing downloads. GitHub's redirect host must join
     `deploy/egress-hosts.json` (caller `update`) when it is built (the `github.com` row says so).
   - Trust request `deadline`: still optional. Absent parses as no deadline (`src/pure/install-request.ts:81-83`, type at `:19`);
     only a present malformed one is `bad_request` (`:105-106`). Core always writes one (`src/shell/trust-installer.ts:57`).
4. Design notes not built: coalesce repeated `proof.refused` audit rows (one per source and minute with a count; today one row per refusal,
   `src/shell/approvers.ts:187`); carry each platform's own key id per live generation in the snapshot (the store has `platform_key_id`,
   `src/shell/rotation-store.ts:212`; `ControlSnapshot` keys lack it, `src/ports/meta.ts:81`); run kb-install's time budgets on a
   monotonic clock (it uses `systemClock`, `Date.now`, `src/cli/kb-install.ts:52`; `kb-bench` already uses `performance.now`).
5. Probes: ids still listed in an adapter's `unverified.json` stay UNVERIFIED (Google API-key rotations wait on
   `google.apikey-verify-call`). A live SDK run through the relay with a `~` address has not been done.
6. Open, not fixed: the control enrol window is per label only (accepted residual, see Decisions); the phone app ran in real Chromium but
   never on a real phone's browser and passkey; findings of the unit verdicts that no fix commit names are in the verdict files.
7. Tidy: `ports/platform.ts` carries Vercel-only types (`operations?`, `vetSetting?`) on the generic `PlatformEntry`. Google: a disabled
   key is still DELETEd once by the sweep; the Secret Manager destination `remove` throws `remove_unsupported`.
   `README.md` still says "no code yet".

## Decisions

- Node 24 LTS; `typescript` 6.0.3. Silent-catch rule strict (throw, return a non-empty value, or `audit.append` / `notifier.*` on every
  path), `src/` and `test/`. No `any`, `!`, ts or eslint suppressions anywhere.
- One host, two ports (KBOX-63): `KB_DOMAIN` is the Pi's Tailscale name; every origin is composed in `src/pure/box-origins.ts`; the
  passkey RP ID is the bare host and the origin check is exact, port included. `src/shell/core.ts` stores `box_info.oidc_issuer`.
- The name is the boundary, not the tag (KBOX-64): `kb-join` compares `Self.DNSName` with `KB_DOMAIN` (and the pinned host) by
  `sameHostName`; every state waits except a wrong name seen on two reads 30 s apart.
- Nothing that decides by the clock runs before an authenticated time (KBOX-65, KBOX-6): `kb-join` writes the time gate file after chrony
  has two NTS sources and the time is at least `KB_TIME_FLOOR`; `kb-install` refuses every request until the file exists.
- Bootstrap facts are names and numbers, never a gate and never a secret; a missed budget is a fact (`bench.over`), not a stop.
- No login anywhere: no sshd, no user, gettys masked; codes and QR codes go to tty1 only (KBOX-66). The box has no backup: a dead card
  means a new setup (spec Revision 5).
- Control enrol window per label only: not built, accepted residual (orchestrator, 2026-11-11). The fix would make the owner copy a hash
  off a machine and buys nothing under S-717 (relay passes are not pinned and every machine is agent-controlled).
- Rotation is opened only with the approval half (`KB_DOMAIN` set); a box with no domain has no key, rotation or paste route. The approval
  executors reach rotation late (`viaRotation`). `rotation.run()` is awaited after the server listens, with no catch: a failed resume
  stops the start, loudly.
- A rotated generation leaves `grace` only on proven evidence (KBOX-51 step 10, `proof-watch.ts`: dead twice, 60 s apart). A failed
  paste run's new key stays `grace`; only an `overlap:false` set's own value is deleted (KBOX-17). A deleted key is erased only after
  that proof (KBOX-62). A retired generation's value file is deleted (`vault.retire`) and leaves the share file as `none`.
- `RotationStore.setGenStatus` writes `key.changed`, so a retirement, a grace and a promote each give the share writer a new version.
  `Orchestrator.stop()` and `startCore().stop()` cancel run timers and are idempotent.
- The share file is format v4 (KBOX-33): every window in 320 SHA-256 slots; `POST /api/retired` is gone. `test/fixtures/share-v4` is the
  corpus devbox's matcher also reads; a corpus change needs a devbox re-vendor (stated at `dcf9e60`, not re-checked here).
- A key's own allow set only narrows its profile; any change, even back to the whole profile, needs the phone (KBOX-61).
- Probe `arch` is the gate's architecture step. `GATE_PINNED_PATHS` pins `loop/probes/arch.sh` and `tsconfig.json`; lockfile pinned.
- Planted mutants (scratch copies, one `runq` run) stand in for missed red steps.
- Tests that pin a rule a correct change must break are retired only in their own unit and commit, naming the reason and the behaviour
  pinned, reviewed by the stronger reviewer (owner law S-795): see `retire-oracle-hosts` C1/C2 and `radio-off` C3 in `git log`.
  Builders never edit pre-existing tests; the next one is `retire-jwks-served`.

## Gotchas

- Run the gate under `runq` naming the skill path, from inside the clone: `runq run --why "<why>" -- bash -c "env
  LOOP_SKILL_DIR=/home/petter/.claude/skills/deterministic-gates LOOP_WORKDIR=<tree> LOOP_BASE_COMMIT=<sha> bash loop/gate.sh"`. Needs
  Docker (`process-split` runs in a container). The base is main's head before the merge.
- The guard refuses `node`, `python3` and other interpreters outside `runq run`, and blocks the whole command line: edit with the Edit
  tool, run tests as `runq run --why "<why>" -- node --test <file>`. No `--place`, except that `scripts/vm-acceptance.sh`'s header names devbox.
- Plain `node --test` runs EVERY file under `test/`; helpers there must do nothing when run directly.
- Other runq jobs may run remotely with a synced tree: a script outside the repo is not there.
- A bearer token on any phone path (even an unknown one like `/r/x`) is 403 from the frame.
- `startCore` takes a `CoreRuntime` (clock, scheduler, random, journal, optional platforms, registry, egress file): a test passes a
  `TimedClock` and checks `pendingTimers === 0` after `stop()`. It reads the real egress gate; set `KB_INSTALL_RESULTS` and `KB_CURRENT`
  to temp paths. The idle watch and its `/proc` reserve are gone (KBOX-21 retired), so a test core holds no reserve.
- `kb-code` makes no code without a well-formed `KB_DOMAIN` (KBOX-66): tests that run it must set one.
- `kb-install` reads its time gate from `KB_TIME_OK_FILE`; unset means no gate, so every older test runs ungated and a deploy test pins
  the line in `deploy/kb-install.service`.
- `scripts/vm-acceptance.sh` reads the guest's root partition from a file of its own: e2fsck drops `?offset=` after a journal replay (see
  the comment above `snapshot()`). The guest is generic x86-64 Ubuntu, so the raspi boot files are faked by its vendor-data.
- `vault.lend` of a retired generation throws `unknown_key`; `shareValuesIn` turns that into `''`.
- A spec rule that lands before its code gets its own Build units row; every KBOX id sits in exactly one row.
- The repo is public: no address, device name beyond the Tailscale host the spec states, or key-like string goes in a file.

## Recent

- `release-v2` (`c6b643e`..`e1960a1`): the user-data renderer, `scripts/release-hash.sh` and the hermetic VM acceptance harness; tag `v2`
  at `e1960a1`, H and floor above. The stolen-box runbook names the platforms' own pages (read 2026-11-16).
- `radio-off` (`cd2da0c`, `545ecaf`, `f1f648c`): the first boot soft-blocks Wi-Fi and Bluetooth through `/sys/class/rfkill`, config.txt
  lines go under `[all]` (a missing final newline keeps the last line whole); C3 retired the three pins of the old rfkill program call.
- `pi-bootstrap` and friends (`5a6c7c3`..`071df3e`): nftables, NTS-only chrony, plain DNS, Tailscale apt source, unit order, the Pi
  checklist; before them `kb-join`, `console-tty1`, `caddy-tailnet`, `host-model` and `retire-oracle-hosts` moved the box off Oracle.
