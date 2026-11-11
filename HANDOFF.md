# HANDOFF — loop state

Fresh-context loop state: this file and the code are the only channels.
REWRITE it (never append) before you finish. Unchanged fails.

## Where things stand

Units `scaffold`, `forms`, `kernel-store` and `kernel-approve` are built on main (`kernel-approve` from 76537bd; see "Recent").
No platform, relay, update, rotate or share code exists yet. The core process (`src/main-core.ts`) serves the machine API and,
when `KB_DOMAIN` is set, the phone app, Web Push and the approvals. Its `TrustPort` refuses every request (`no_installer`) until
the `update` unit builds the real one (kb-install's trust requests), so on a real box setup, recovery and approver changes
cannot complete yet. Kinds that need a platform adapter's check (`add_key`, `add_destination`, `set_allow_rules`, the two
Vercel kinds) are `rejected` at proposal time until an adapter registers. Next: `update`, `relay`, `rotate`, `share` (Remaining).
Spec: `docs/spec.md`. Run units with the compound-loop driver and `-G loop/gate.sh`.

## Codebase map

- `package.json`, `package-lock.json`, `.nvmrc` (24), `tsconfig.json`, `runtime.lock` (placeholder). Dev dependencies only
  (`typescript` 6.0.3, `@types/node` 24.19.2, exact); no runtime dependencies. `npm ci --ignore-scripts`.
- `src/ports/`: interfaces of design 5.1 (`vault`, `audit`, `meta` incl. TokenStore, `events`, `private` (PushStore,
  ApproverStore), `clock`, `random`, `issuer`, `destination`, `relay-profile`, `approvals`, `notifier`, `types`, `push`
  (Push, PushSubscriptions incl. `applicationServerKey`, PushTransport), `trust` (TrustPort: setup, recovery, approver_add,
  approver_remove requests; applied or refused)).
- `src/pure/` (no I/O):
  - `webauthn.ts` (assertion check by hand: clientData type/challenge/origin/crossOrigin/topOrigin, 37-byte authData, AT/ED
    refused, rpIdHash, UP, UV, counter, ES256 over DER; `derToRaw`, `verifyEs256Raw`), `cose.ts` (strict CBOR subset, EC2 P-256
    ES256 only, on-curve check), `challenge.ts` (the one home of every challenge: approval, denial (`kbox-v1-deny`), view, op, paste, registration;
    `verifyProof` = passkey AND device key of the same approver; stateless HMAC nonces bound to purpose, approval id and
    revision). Core and kb-install share these three; `test/kit` must not import them (arch check).
  - `actions.ts` (closed `Action` union of 16 kinds, `parseAction`, `PROPOSAL_ROUTE_KINDS`, `DOMAIN_NAME`), `slots.ts` (`slotOf`,
    `decideSlot`: open / replace / takeover / taken), `words.ts` (KBOX-8 fixed sentences, titles, `renderPage`), `codes.ts`
    (12 BIP-39 words = 132 bits, hash only), `pushcrypto.ts` (RFC 8291 aes128gcm, RFC 8292 VAPID), `pushsub.ts` (endpoint check
    against `src/data/push-hosts.json`), plus the kernel-store files (`forms`, `schemas`, `errors`, `canonical`, `tokens`, `address`).
- `src/shell/`:
  - `approve-core.ts` `openApproveCore(deps)`: wires approvers, approvals, machine tokens and the phone routes over `CoreParts`;
    executes grant, revoke_grant, add/remove_destination, enrol, approver_remove itself; other kinds come in `executors`.
  - `approvers.ts` (the proof check, nonces, view sessions `__Host-kb_view` 15 min, setup/recover/add/remove through the
    TrustPort; core's table changes only after `applied`; an approver_add's registration code carries a `settle` callback
    that ends its approval as done or failed: root_refused, proof_refused, code_expired, superseded, cancelled by a recovery or
    by removing the approver who approved it; `GET /app/queue` answers `{phrase, approvals}`, the viewer's own phrase),
    `approvals.ts` (proposals, 14-day expiry swept lazily, decide,
    kept proofs for install_update/approver_add/approver_remove), `tokens.ts` (enrol window 10 min, one enrol; signed revoke;
    new-network push), `routes-approve.ts` (`/api/proposals`, `/api/enrol`, `/api/enrol/:sha`, every phone route and asset),
    `push.ts` + `push-transport.ts` (Web Push sender, 10 s timeout, 404/410 removes), `console.ts` (root's code store:
    `/etc/keybox/codes` 0700, files 0600; recovery 30 min per boot_id; console sink).
  - `http.ts` frame: path params (`:name`), open routes, raw replies and headers, the phone cookie; a bearer token on a phone
    route is refused 403. Plus the kernel-store files (`core.ts`, `db.ts`, `meta.ts`, `audit.ts`, `events.ts`, `vault-fs.ts`,
    `routes-control.ts`, `private-db.ts`, `clock.ts`, `random.ts`).
- `src/web/`: the phone app, plain JS under `checkJs` (no DOM lib: `browser()` in `webauthn-client.js` is the one typed cast).
  `index.html`/`app.js` (view, queue, approve/deny, signed ops, add phone), `setup.*`, `recover.*`, `register.js`, `sw.js`,
  `manifest.webmanifest`, `app.css`. Errors go to `notifier` (the page's status line), which the silent-catch rule accepts.
- `src/cli/kb-code.ts` (root oneshot: setup | recovery codes to the console device only), `src/main-core.ts`.
- `deploy/`: `keybox.service`, `keyrelay.service`, `kb-code.service` (tty group, one DeviceAllow), `keybox-tmpfiles.conf`,
  `runtime.config.json` (`console_device`, UNVERIFIED `/dev/ttyAMA0`).
- `test/kit/` (add files, do not edit existing lines): kernel-store helpers plus `approver.ts` (`softApprover()`: passkey and
  device key, faults planted under a valid signature) and `cbor.ts`. `test/support/approve-world.ts`: `approveWorld(t, opts)`
  (real core + approve core on a socket, FakeTrust over the real code store, FakePush, journal capture, extra routes, shared
  code dir for journeys). `test/fakes/{push,trust}.ts`. Fixtures: `test/fixtures/webauthn/` (`SOURCE.md` names the vectors).
- Tests by rule: `approval-binding` (KBOX-9), `slots` (KBOX-7), `words` (KBOX-8), `machine-tokens` (KBOX-11), `recovery` (KBOX-20),
  `web-push` (KBOX-22 incl. the URL walk), `setup` (KBOX-49, the pages, the running core), `proposal-routes` (KBOX-53, KBOX-19
  route half), `journeys/recovery.test.ts` (J5); plus the kernel-store files. `test/journeys/process-split.test.ts` is root-only
  (Docker in the gate). `loop/gate.sh`, `loop/probes/arch.sh`.

## Remaining

1. `update` (KBOX-1, 6, 21, 44, 46, 48): builds the real `TrustPort` (`src/shell/trust-installer.ts`) and wires it in
   `main-core.ts` in place of `noInstaller`; kb-install verifies kept proofs with `src/pure/{webauthn,cose,challenge}.ts`;
   sets `KB_DOMAIN` in the unit/cloud-init; registers the `install_update` executor; owns `POST /api/updates`. It also touches
   `deploy/runtime.config.json`, which kernel-approve created with `console_device` only (keep that member).
2. `relay` (KBOX-3, 13, 14, 23, 25, 32, 47), `rotate` (KBOX-12, 15, 16, 17, 34, 51, 52; paste `/p/<id>` and `pasteChallenge` are
   ready), `share` (KBOX-18, 33); parallel. Adapters register the proposal check that `main-core`'s `vetWithoutAdapters` stands in for.
3. The six adapter units (`google`, `vercel`, `supabase`, `openai`, `elevenlabs`, `paste`); each commits its probe report first.

Open items, not fixed:
- Old approvers' push subscriptions are not removed on recovery or removal: subscriptions carry no approver link.
- The control enrol window is per label only (spec KBOX-11): the first `POST /api/enrol` with the label inside the 10 minutes
  takes it, so an agent that polls can win the race against the real machine. The fix (the signed `enrol_window_open` operation
  also names `token_sha256`, which the owner pastes from the machine) changes the operation shape the spec and these tests pin:
  machine-tokens (window tests, `op` helper), proposal-routes (the three enrol cases), setup (client op challenge) and the phone
  page. **Decided (orchestrator, 2026-11-11): not built; accepted residual.** The fix would make the owner copy a hash off a
  machine, which the owner never does, and it buys nothing under S-717: relay passes are not pinned, any of the owner's
  machines may hold one, and every machine is agent-controlled, so a pass won by the race is one an agent could get by asking.
  Revisit only if passes are ever pinned or per-machine grants become a real boundary.
- Unchanged and judged harmless (kernel-approve verdict): the `ENROL_LABEL` check on `enrol_window_open`, the future-nonce
  guard, the duplicate COSE label check, the DER zero r/s check, `records().length <= 1` in `remove`. `private.db` from before
  kernel-approve would fail `listApprovers` (no migration; no box is deployed). The audit grows with each refused proof by
  design (owner: no numeric caps); spent nonces are pruned after 10 minutes. `deploy/keybox.service` sets no `KB_DOMAIN` until `update`.
- Recovery and approver_add need a real TrustPort before J5 can run against two processes; J5 runs core in-process now.
- The phone app was never run in a real browser (no WebAuthn here); only its challenge builders and COSE extraction are tested.
- kernel-store review items: `put()` replaces a generation via rename; `retire()` does not sweep temps; a temp under a ref over 128
  characters stops the start; spec-drift audit of the kernel-store files not done.

## Decisions

- Node 24 LTS per spec; `typescript` 6.0.3. Silent-catch rule strict (throw, return a non-empty value, or `audit.append` /
  `notifier.*` on every path), `src/` and `test/`. No `any`, `!`, ts/eslint suppressions anywhere.
- kernel-approve readings: shape failures on `/api/proposals` are `bad_request`, vet and last-approver failures `rejected`;
  `reason` is `{agent, text}`; the registration challenge is `SHA-256("kbox-v1-register" || nonce)` and a new approver proves both
  keys; assertions with AT or ED flags are refused; a counter that does not grow is refused unless both are 0 (synced passkeys);
  nonces are stateless HMAC, spent on any attempt that passes the HMAC check; replace and takeover send no push; expiry counts
  from the first opening; the approver-add registration step is `POST /recover/register`; `GET /app/push-key` added (the phone
  needs the VAPID key to subscribe; the spec's route list has none); `/app/propose-approver-add` is the one state change a view
  cookie may make (spec lists it with a view session); kb-code makes `/etc/keybox/codes` itself (tmpfiles test pins the dirs).
- Probe `arch` is the gate's architecture step. `GATE_PINNED_PATHS` pins `loop/probes/arch.sh` and `tsconfig.json`; lockfile pinned.
- Planted mutants (scratch copies under `~/.cache`) are the stand-in for missed red steps: kernel-approve planted 17, all caught.

## Gotchas

- Run the gate under `runq` naming the skill path (runs locally): `runq run --why "<why>" -- bash -c "env LOOP_SKILL_DIR=/home/petter/.claude/skills/deterministic-gates LOOP_WORKDIR=<tree> LOOP_BASE_COMMIT=<sha> bash loop/gate.sh"`. Needs Docker.
- Plain `node --test` runs EVERY file under `test/`; helpers there must do nothing when run directly.
- Other runq jobs may run remotely with a synced tree: a script outside the repo is not there (pass it inline, e.g. a data: URL import).
- The guard refuses `perl`/`sed -i` outside the tree and some inline scripts; perl `s|..|..|` with `\|` in the pattern is an
  alternation, not a literal bar (it corrupted a file once): use the Edit tool for multi-line edits.
- A bearer token on any phone path (even an unknown one like `/r/x`) is 403 from the frame.

## Recent

kernel-approve (KBOX-7, 8, 9, 11, 20, 22, 49, 53) on main after 76537bd: verifier, codes and kb-code, TrustPort, Web Push, the frame
extension, approvals and slots, the phone app, recovery, machine tokens, proposal routes, main-core wiring, J5, mutants.
Then the kernel-approve review fixes (verdict SOUND WITH FIXES): five test gaps pinned (nonce key per process, signature counter,
view cookie flags, registration nonce spent, nonce purpose tag), the decision in the challenge (`test/support/approve-world.ts`:
`proofFor(..., decision)`; `decide('deny')` re-signs an unchanged approval proof over the denial challenge, so older deny tests
run as they were), the approver_add code lifecycle, the phrase in the queue, a VAPID pair that fails to decode is a fault,
kb-code tightens an existing code directory. Open: the enrol window (above).
