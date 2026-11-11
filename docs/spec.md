# The key box: a small server that holds admin keys, passes on approved requests and changes keys on a schedule (spec, KBOX)

Status: draft, not built. Source: the decided design `proof/api-keys-design.md` (revision 5, final) and its two verdicts (`api-keys-design.verdict.md`
UNSOUND, `api-keys-design.verdict2.md` SOUND WITH FIXES; the design's fixes answer both), under
`/home/petter/.local/share/lanes/mission-control/`. This file makes the key box buildable and gateable; it does not redesign it. Owner rulings behind it
(`mctl truth --scope mission-control`): S-702 to S-717; S-709 is in devbox scope. S-711 (account logins) is being amended by card C-692 to "an
authenticator app synced only to a Google account never signed in on the owner's machines"; this spec follows the design's section 8, which already says so
(see "Contradictions found in the design").

Scope: the key box repo ONLY (design build units 1 to 8). Not here: devbox units 9 and 10 (`admin-match` share backend; `with-keys`, `keybox-enrol`,
`hand-off`) and mission-control units 11 to 17 (API keys page, client, rights, delivery, migration, guard rows). This file states every contract those
sides rely on: the machine API (`KBOX-29` to `KBOX-31`, `KBOX-34`, `KBOX-53`), the relay endpoint and pass (`KBOX-32`), the share file (`KBOX-33`), the
event and long-poll shapes (`KBOX-31`). They will be specced against this file.

Rule ids are `KBOX-n`. `KBOX-1` to `KBOX-26` keep the design's numbers. `KBOX-27` and up are written for this spec and each cites the design section it
makes buildable. Every rule states behaviour and the test that proves it. "Design §x" names a section of the design.

## In plain words

The key box is a small computer of its own, rented free from Oracle, that holds the keys which could do real damage: the admin keys and the keys that make
other keys. Nobody logs into it, and the agents have no way in. Your phone is the only thing that can tell it to do something that matters, with your
face or fingerprint, in an app you put on your home screen.

An agent that needs an admin key does not get the key. Its program sends the request to the key box instead of to the platform (OpenAI, Supabase,
Google). The box checks that the computer asking holds a pass you approved and that the key was granted to it, passes on only the kinds of request named
in advance, adds the key itself, and sends the answer back. If the answer carries anything shaped like a key, the box holds it back. A request that
would make a new key, a new login or a new password is never passed on.

The box also changes keys on a schedule. It makes a new key, puts it where the old one was, restarts the apps that need it, checks that all works, and
only a day later switches the old key off. If anything fails, the old key stays and you get one message. Ordinary keys change without asking you. Admin
keys wait for your phone, one at a time. Where a platform cannot make keys on request (Anthropic, Stripe), you copy the key on your phone and paste it in
the app.

The box can also update itself, but only to the exact version your phone approved. The approval page says that agents wrote and checked that version and
that nobody you trust has read it. That is true and the box cannot make it better; it only makes sure that what runs is what you approved.

The box writes a file of one-way fingerprints of the admin keys, which your computer uses to notice a stray copy of one. It never shows a key, a length or
the start or end of a key anywhere, except in two named cases (an ordinary key it made for your computer, and the public opening letters of a key's
format in the fingerprint file).

What it does not do: it cannot stop an update you approve from taking every key; it cannot stop an app that agents wrote from reading the keys that
app is given; it cannot tell which agent on a machine holding a pass is calling. A pass that leaks works from anywhere until you switch it off in one tap,
and the box's log records every use. If you lose your phone, you get back in only through the authenticator app synced to your Google account (design §8).

## Contradictions found in the design (read before building)

1. Design §0, §1.5 step 1, `KBOX-20` (first paragraph), §7 and R7 still say the authenticator app has cloud sync and backup off and that a lost phone
   cannot be recovered. Revision 5 (§8, `KBOX-20` third bullet, §11 Q3) says the app syncs to a Google account never signed in on the owner's machines, so a
   lost phone IS recoverable. **This spec follows §8/§11** (the later, owner-answered text). The setup checklist and the recovery text (`KBOX-48`) carry the
   new wording. S-711 as filed still says "does not sync" until card C-692 lands.
2. Design §1.3 says the lend socket checks `SO_PEERCRED`. Node's standard library has no peer-credential API, and zero npm dependencies is a settled rule.
   This spec makes the operating system check it instead: socket mode and directory ownership (`KBOX-3`, `KBOX-45`).
3. Design §10 unit 6 (share file) tests against devbox's `admin-match` finding every planted copy, but the v3 backend in `admin-match` is unit 9, built
   after unit 6. `KBOX-33` closes this with a reference matcher written in the box's test kit and a golden corpus that devbox unit 9 runs too.
4. Design §10 unit 2's test "enrol without an open window and without a control token refused" can be read two ways. This spec reads it as: a
   `scope: control` enrol needs the open window; a `scope: relay` enrol needs no token and only creates a proposal (`KBOX-53`).
5. Design header says "revision 4" while sections 8 and 11 carry revision 5 text. No behaviour depends on it.

## Toolchain and layout (decided here; rules `KBOX-27`, `KBOX-28`, `KBOX-35`)

| Choice | Decision |
|---|---|
| Runtime | Node.js 24 LTS, arm64 on the A1 box. The exact patch is pinned by sha256 in `runtime.lock`; `.nvmrc` carries the major for development. No other runtime. |
| How TypeScript runs | Node's own type stripping: `node src/main-core.ts`. No build step, so the approved bytes are the running bytes (design §1.3). Erasable syntax only: no `enum`, `namespace`, parameter properties or decorators; imports name the `.ts` file. Browser code is plain `.js` with JSDoc types, checked by the same compiler (`checkJs`). |
| Type checking | `typescript` is the repo's ONE dev dependency (`devDependencies`, exact version), used only by `npm run typecheck` (`tsc --noEmit`) and by `test/arch.test.ts`. It is never imported by `src/` and is not in the release bundle (`node_modules` is untracked). |
| Strictness | `tsconfig.json`: `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `noImplicitOverride`, `noPropertyAccessFromIndexSignature`, `noFallthroughCasesInSwitch`, `verbatimModuleSyntax`, `erasableSyntaxOnly`, `allowImportingTsExtensions`, `noEmit`, `checkJs`, tests included. No `any`, no non-null `!`, no `@ts-ignore`, no `eslint-disable`: counts start at zero and may not rise. |
| Test runner | `node:test` with `node:assert/strict`. No test packages. `npm test` runs `node --test`. |
| Runtime dependencies | None. `package.json` has no `dependencies` key. Imports in `src/` are `node:` builtins or relative files. |
| Layout | `src/ports/` (the interfaces of design §5.1 and the closed types); `src/pure/` (pure core: no process, network, file, clock or randomness); `src/shell/` (adapters: the only code that touches the outside); `src/platforms/<id>/`; `src/web/` (the phone app, plain `.js`); `src/main-core.ts`, `src/main-relay.ts`, `src/cli/*.ts`; `deploy/` (unit files, Caddyfile, cloud-init text); `test/`, `test/kit/`, `test/contracts/`, `test/fixtures/`, `test/journeys/`; `docs/spec.md`, `docs/probes/`. |

## Rules

Within each unit the rules are given in order. Test names cite the rule id (`test-doctrine` R8); each test file is named after the behaviour it covers.

### Unit `scaffold`: the repo, the toolchain and the shared test kit

**`KBOX-27` One toolchain, no runtime packages.** The choices in the toolchain table hold. Source: design §1.3 (zero npm runtime dependencies, run from source by
type stripping). Test (`test/arch.test.ts`): `package.json` has no `dependencies` (and `devDependencies` is exactly `typescript`); every import specifier in
`src/` is a `node:` builtin or a relative path ending `.ts` or `.js`; no file under `src/` uses TypeScript-only runtime syntax (enum, namespace, parameter
property: checked by running every `.ts` file through `node:module` `stripTypeScriptTypes` and comparing the line count and a re-parse); `tsc --noEmit` is
clean with the strict options of the table; the counts of `any`, non-null `!`, `@ts-ignore`, `@ts-expect-error`, `eslint-disable` and `noqa` are zero.

**`KBOX-28` Pure core, imperative shell, no cycles, no silent catch.** Source: design §1.3 (trusted core), code-doctrine. `src/pure/**` imports no
`node:fs`, `node:net`, `node:http*`, `node:tls`, `node:dns`, `node:os`, `node:child_process`, `node:sqlite`, `node:worker_threads`, and uses none of `Date.now`,
`new Date()` without an argument, `Math.random`, `setTimeout`, `setInterval`, `fetch`, `process.`, `randomBytes`, `randomUUID`, `randomInt`, `generateKey*`
(hashing, HMAC, HKDF, signature verification and AES-GCM with a given IV are allowed). Randomness, time, files, sockets and the database come in through
the ports of `src/ports/`. `src/ports` and `src/pure` import nothing from `src/shell` or `src/platforms`. There is no import cycle (type-only and dynamic
imports included). Every `catch` rethrows, reports through the `Audit` or `Notifier` port, or returns an error result; an empty catch or a catch that only
logs is refused. Test (`test/arch.test.ts`, using `typescript` as a parser): each of these on a fixture that breaks it fails, and the repo's own tree passes.

**`KBOX-35` The shared test kit and the contract suites.** Source: design §10 ("every unit starts by writing the failing tests"), test-doctrine R3, R7, R9,
section 5. `test/kit/` provides, and tests use instead of hand-built setup: `tempDir()` (removed in an `after` hook), `FakeClock` (time is always passed in),
`seededRandom(seed)` (the seed is printed on failure; property tests take it from `KB_SEED` or draw one and report it), `canary()` (fresh random bytes and
`assertAbsent(surfaces)`, which looks for the bytes raw, base64 std and url, hex, percent, JSON-escaped and `\u`-escaped in each named surface: database file
and WAL, audit log, captured journal, every event, every HTTP response, every Web Push payload), `softAuthenticator()` (a software passkey plus device key
that makes real assertions and device-key signatures), `fakePlatform()` (a real HTTP server on a loopback port that plays one platform's API and can fail in
its real ways: refuse, hang, 500, 401 with an echoed key hint, malformed JSON, partial body, redirect), `drive()` (talks to a started core or relay over its
unix socket). One contract suite per port in `test/contracts/` (`issuer`, `lister`, `verifier`, `destination`, `redeployer`, `relayProfile`, `vault`,
`approvals`, `audit`) is written once and run against the fake and, in each adapter unit, against that adapter over `fakePlatform()`. Other tests never mock
or spy on this repo's own modules or database; faults are injected through a port or through `fakePlatform()`. The canary suite
(`test/canary.test.ts`) is extended by every unit that adds a response, log line or event. Test: the kit's own behaviour is tested only where it is
tricky (`assertAbsent` finds a planted base64 copy and a `\u` copy and returns clean on a decoy; a failing `fakePlatform()` mode really fails).

**`KBOX-42` An adapter starts with a live probe, reported before code.** Source: design §5.4, §12. Each platform folder `src/platforms/<id>/` needs
`docs/probes/<id>.md` committed first. It lists every UNVERIFIED item this spec names for that platform with one line each: the request sent to a
throwaway project (never a real one), the status and the shape of the answer (names only, never a value), and VERIFIED, REFUTED or STILL UNVERIFIED. An
item the probe cannot settle stays marked UNVERIFIED in the code's comments and in the adapter's registry entry. Test (`test/arch.test.ts`): a platform
folder with no probe file fails; a probe file missing one of the platform's UNVERIFIED ids fails (the id list is in `src/platforms/<id>/unverified.json`,
written by the adapter unit from this spec). The probe never runs in the test suite and never reads a value file.

### Unit `forms`: the leak-scan forms library

**`KBOX-54` One forms library for both scanners.** Source: design §1.1 (response scanner, fingerprint writer), `KBOX-14`, §6.5, devbox
`admin-secrets-spec.md` §3 and §4 (normative for the forms; this is a port to TypeScript). `src/pure/forms.ts` is the one place that computes, for a stored
value: its **core** (a JWT: the signature; a value with a known prefix: the rest; a URL with userinfo: the password as written; else the whole value) and its
**forms**: raw; base64 standard and url interiors at byte alignments 0, 1, 2 (the interior is the characters fixed by the core's bytes alone); hex lower and
upper; percent (one form: `encodeURIComponent` style, Python `quote` style and the `safe=''` style, with upper- and lower-case escape digits); JSON-escaped
(also `/` as `\/`) where it differs from raw; `\uXXXX` with every character escaped, lower and upper hex. Two sets are exported: `scanForms` (all of them, for
the relay's response scanner) and `shareForms` (raw plus the six base64 interiors, for the share file). It also exports the stripped view (whitespace and
`\`-newline removed, with a map from a stripped offset back to the raw one) and a streaming matcher that finds a form across chunk boundaries (chunks overlap
by the longest form minus 1). The library never logs, throws with, or returns any part of a value in an error; a failure is a fixed code.
Test (`test/forms.test.ts`): known-answer tables for each form on short synthetic values; properties with a seeded generator (R6): for any core, prefix and
suffix, every form of the core is found inside the same encoding of prefix, core and suffix at some alignment, and a copy split across any chunk boundary is
found exactly once; a wrapped copy (base64 at 64 and 76 columns, CRLF, `\`-newline) is found only in the stripped view and maps back to the right offset; a
decoy (a value differing in one core byte) is never found; the failure paths (empty value, a core shorter than the form's minimum window) return fixed codes.
The independent oracle for the tables is reported by the builder (`worker-routine`): the cheapest honest source is devbox's own `admin-match` form
functions run on synthetic canary values through its test seam; if that is not usable the builder says so and uses hand-computed vectors for values of 1, 2
and 3 bytes plus the substring property.

### Unit `kernel-store`: the vault, the database, the audit log, the machine API frame and the events

**`KBOX-2` A value leaves the box only to an approved destination or a relayed upstream.** Source: design §1.2. No page, machine-API response, log line,
audit entry, event, error, metadata export or Web Push payload carries a value, a length, a prefix, a suffix or an unkeyed digest. Two exceptions: a
box-issued **ordinary** key is delivered to the workstation destination (`KBOX-34`), and the signed share file carries, for anchored entries only, the public
prefix of the key's format (from the adapter's `shape`, never read from the value) and `len`, the length of the digested run (`KBOX-33`). A coverage tier
name is not a length. Test: the canary suite (`KBOX-35`) after add, rotate, relay, a failed rotation and a paste; the canary is absent from every surface
listed in `KBOX-35`, except the declared prefix in the share file and the delivery route. A seeded property test feeds random byte strings through the audit
and event writers and the error mapper and finds none in the output.

**`KBOX-4` Values are lent, never returned.** Source: design §1.2. The vault port is `put(ref, gen, bytes)`, `lend(ref, gen)` and `retire(ref, gen)`; `lend`
returns a `Lent` whose `use(fn)` hands the bytes to `fn` and whose `toString`, `toJSON` and `util.inspect` all return `[key <ref>:<gen>]`. Every adapter call
is wrapped: anything it throws is replaced by a fixed text plus the platform's HTTP status (the same pattern as mission control's KREQ-12), and a create
response that holds a new value is never logged, even when it fails to parse. Vault files live under `/var/lib/keybox/vault/<ref>/<gen>`, one file per
generation, mode 0600 in a 0700 directory owned by `keybox`, written by temp file, `fsync` and `rename` so a crash leaves the old file or the new one. Test:
`String`, template string, `JSON.stringify`, `inspect` and `console.log` of a `Lent` give the placeholder; a thrown error from a fake adapter that quotes the
canary reaches no surface; a crash injected between write and rename leaves a readable vault; a canary in a create response that fails to parse is absent
everywhere.

**`KBOX-5` The metadata database never holds a value, by construction.** Source: design §1.2. Values live only under the vault directory. The metadata
database (`meta.db`: keys, classes, grants, destinations, schedules, rotation state, approvals, coverage, machine token hashes) is exported in full through
the machine API. A second database file (`private.db`) holds Web Push subscriptions, the setup phrase and approver credentials and is **never exported**; no
export code can open it (separate port, separate connection). Test: the canary suite; a test that lists every table of `meta.db` and every column and fails on
a column typed or named as a value store (`value`, `secret`, `token` without `_sha256`); `private.db` rows are absent from `GET /api/meta` and from every
other response. `node:sqlite` in the pinned Node LTS is checked first; if unusable the metadata goes in JSON-lines files with atomic rename behind the same
port, and the report says so.

**`KBOX-10` Machine API token rules.** Source: design §2. Bearer tokens are 32 random bytes, base64url (43 characters), with the prefix `kbt_`. The box
stores only `SHA-256(token)`. Any request carrying an `Origin` or `Cookie` header is refused with 403 `browser_call`, so no browser-driven call reaches the
machine API. Phone routes accept no bearer token; the machine API accepts no passkey assertion. A token is compared by its hash in constant time. Test:
a request with `Origin` is refused on every `/api/*` and `/r/*` route; a bearer token on a phone route is refused; a malformed token (length, alphabet,
prefix) gets 401 with no database lookup (counted through the port); two tokens whose hashes share a long prefix are told apart.

**`KBOX-19` Backups: none of values; metadata goes to mission control.** Source: design §8. There is no backup of vault files and no code path that writes
one (a test greps the shell adapters for any copy of a vault path). The metadata database is exported on change as events plus `GET /api/meta` (`KBOX-30`).
Test: after a change to a key, a destination and a grant, the next event after the change has kind `key.changed` and `GET /api/meta` shows it; the export
contains no `private.db` content.

**`KBOX-29` Wire conventions of every machine-API route.** Source: design §2, §6.3; decided here. HTTPS only (Caddy), JSON bodies UTF-8 with
`Content-Type: application/json`, except the octet-stream routes named in `KBOX-34`. Times are integers in milliseconds since the epoch, named `*_at`.
Every `/api/*` request needs `Authorization: Bearer kbt_…` of a token with the route's scope (`KBOX-11`, `KBOX-30`). Every response carries
`Cache-Control: no-store` and `KB-Api-Version: 1`. Errors have one shape, `{"error":{"code":"<snake_case>","message":"<fixed text>"}}`, and never echo
request text. Codes: `bad_request` 400, `browser_call` 403, `unauthorized` 401, `forbidden` 403, `not_found` 404, `slot_taken` 409, `conflict` 409,
`too_large` 413, `unsupported_media` 415, `rejected` 422 (a value that failed its checks; the reason is a names-only code), `unavailable` 503 (a dependency
inside the box is down), `internal` 500 (fixed text; the cause goes to the audit log as a code). JSON request bodies are read up to 64 KiB (a mechanical
safety bound for parsing, not a policy limit; decided here and easily raised); a body over it gets `too_large`. A body is parsed once into a typed value at
the edge (closed object, unknown member refused, string lengths and shapes checked); the interior takes only parsed types. Request ids: `req_` plus 12
random base64url characters, echoed as `KB-Request-Id` and written to the audit log. Test (`test/api-frame.test.ts`): each code is produced by a request that
should get it and its body matches the fixed text; an unknown member, a wrong type, a body of 64 KiB + 1 and a body with a BOM or invalid UTF-8 are refused
with no state change; an error body never contains a canary placed in the request.

**`KBOX-30` Control read routes: metadata and audit.** Source: design §6.2, §6.3; shapes decided here. Scope `control` only.
- `GET /api/meta` returns `{cursor, box, keys, machines, approvals}`. `cursor` is the event sequence number at the moment of the snapshot (a new client starts
  its long-poll there). `box` is `{release, share_version, share_public_key_ed25519_b64, oidc_issuer}`. A key is `{keyref, platform, name, projects,
  class, status, gen_current, destinations:[{kind, target, readable_by}], schedule:{rotate_every_days, grace_hours, next_due_at, expires_at}, grants:[{machine}],
  allow_rules:[ruleId], coverage, last_use_at}` where `class` is `ordinary|admin|master`, `status` is `works|rotating|awaiting_approval|awaiting_paste|failed`
  and `coverage` is `windowed|anchored|none|null` (null until measured). A machine is `{label, scope, enrolled_at, revoked, last_network}`. An approval is
  `{approval_id, kind, title, slot, opened_at, expires_at}` where `title` is the box's one-line title (`KBOX-8`). Nothing in `private.db` and no token
  hash appears.
- `GET /api/audit?since=<seq>&limit=<n>` returns `{entries, cursor, more}`: each entry is the audit row of `KBOX-50` with `seq`, `at`, `prev_hash`, `hash`.
  `limit` is optional; without it all rows after `since` come back.
Test (`test/control-read.test.ts`): the exact member set of each response is pinned by a closed-schema parse in the test (a new member fails it); a revoked
or relay-scope token is refused; a snapshot taken during a write is consistent with its `cursor` (replaying events after `cursor` on the snapshot gives the
final state); the canary is absent.

**`KBOX-31` Events and the long poll.** Source: design §1.1 (Notifier), §2, §6.3; shapes decided here. Events are append-only rows `{seq, at, kind, data}` in
`meta.db`, `seq` a strictly increasing integer from 1. `GET /api/events?since=<seq>` (scope `control`) answers at once with the events after `since` if there are
any; otherwise it holds the request for 25 seconds and then answers `{events:[], cursor:<since>}`; a response with events is `{events:[…], cursor:<last seq>}`.
A missing `since` means the current head (no replay). `since` greater than the head is `bad_request`. Events are never deleted in v1 (they hold names only).
The closed list of kinds and their `data` (names, ids and codes only, never a value):

| kind | data |
|---|---|
| `approval.opened` | `approval_id, approval_kind, title, slot, revision` |
| `approval.decided` | `approval_id, decision: approved\|denied\|expired` |
| `approval.executed` | `approval_id, result: done\|failed, reason_code` |
| `key.changed` | `keyref` |
| `rotation.state` | `run_id, keyref, state, step` |
| `rotation.failed` | `run_id, keyref, step, reason_code, old_key_works: true` |
| `rotation.old_key_still_on` | `run_id, keyref, gen` |
| `delivery.ready` | `delivery_id, keyref, project, name, gen` |
| `share.version` | `version` |
| `machine.changed` | `label, change: enrolled\|revoked` |
| `token.new_network` | `label, network` |
| `update.state` | `approval_id, state: pending\|installed\|rolled_back` |
| `box.notice` | `code, text` (fixed texts: credential withheld, idle near, orphan key found, delivery unacknowledged) |

Test (`test/events.test.ts`, `FakeClock`): the long poll returns on the first event, returns an empty batch at 25 s of fake time, and two concurrent pollers
both see every event; `since` semantics (equal to head, older, greater than head, missing); kinds outside the table cannot be written (type and runtime
check); a poll interrupted by server stop answers `unavailable`, not an empty batch (so "unreachable" is never read as "nothing happened"); the canary is absent.

**`KBOX-43` The client address comes from one header.** Source: design §1.3 (client address). Both processes read the client address only from
`X-KB-Client-Ip`, only from a connection on their unix socket, and ignore `X-Forwarded-For`, `X-Real-IP` and `Forwarded`. A missing or malformed header
is `bad_request` on the machine API and 400 on the relay. The network used by "new network" checks is the /24 of an IPv4 address and the /48 of an
IPv6 address. Test: the audit row's source address equals the header whatever the other three say; the three spoofed headers change nothing; the first use
of a token from a new network writes one `token.new_network` event and a second use from the same network writes none (the Web Push is in
`kernel-approve`); /24 and /48 boundaries.

**`KBOX-45` Process layout, sockets and unit hardening.** Source: design §1.3. Three system users (`caddy`, `keybox`, `keyrelay`) and three units. Core
listens on `/run/keybox/http.sock`, relay on `/run/keyrelay/http.sock`, both owned by their user, mode 0660 with group `caddy`, in directories mode 0750; the
lend socket `/run/keybox/lend.sock` is mode 0660 owner `keybox` group `keyrelay` in a 0750 directory. (The operating system, not a peer-credential call, is
the access check: Node has none.) Each unit has `LimitCORE=0`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `PrivateTmp=yes`; kb-relay has no read access
to the vault directory (`InaccessiblePaths=/var/lib/keybox`) and `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`. The OS is Ubuntu LTS minimal with
unattended security upgrades (cloud-init, `KBOX-48`). Test (`test/deploy-units.test.ts`, text check of `deploy/*.service` and a started-process check in
`test/journeys/process-split.test.ts`): each directive is present; started as separate processes in a temp dir with the real socket modes, the relay
process cannot open a vault file, a connection from a different group is refused by the mode (the test runs only where it can switch uid and reports a skip
as "unverified", never as green); the lend socket exists only after core starts.

**`KBOX-50` The audit log is append-only and hash-chained, and never holds a value.** Source: design §1.1. Rows `{seq, at, actor, action, ref, detail,
prev_hash, hash}` with `hash = SHA-256(prev_hash ‖ canonical JSON of the row without hash)` (canonical JSON as in `KBOX-9`). The first row's `prev_hash` is 32
zero bytes. `actor` is a token label, an approver id or `box`. `detail` is a closed object per action (names, ids, codes, statuses, byte counts). The port
has `append` and read only; there is no update or delete path. A relay row (`KBOX-13`) carries time, token label, source address, claimed agent and project,
keyref, method, rule id, status, bytes. Test: appending 1,000 rows then flipping one byte of a stored row makes `verifyChain()` name the first bad `seq`;
a deleted row is detected; `detail` objects with an unknown member are refused at the writer; the canary is absent; two concurrent appends get distinct
sequence numbers and a valid chain.

### Unit `kernel-approve`: approvers, approvals, slots, phone pages, recovery and push

**`KBOX-49` First approver: the setup code and the phone's registration.** Source: design §1.5 steps 4 and 5. At first start with no approver, the box
creates a one-time setup code (12 words, 132 random bits from the 2048-word list `src/data/wordlist.txt`, BIP-39 English; decided here), keeps only its hash
(SHA-256 of the lower-case words joined by single spaces) and writes the words only to the console sink (`KBOX-20`'s sink, never stdout or the journal). `/setup` on
`keys.<domain>` takes the code, then runs one page flow: create a passkey (WebAuthn `attestation: "none"`, ES256 only, user verification required), create the
device key (`KBOX-9`) with the loss warning shown first, subscribe to Web Push (`KBOX-22`), and type a short phrase. Setup then closes for good: with one approver
registered `/setup` answers 404. Later approvers come only by approval (`approver_add`, `KBOX-53`) or by recovery (`KBOX-20`). The only CBOR the box parses is
one COSE public-key map at registration: a decoder for exactly EC2 P-256 ES256 (small-integer keys; integer and byte-string values) that refuses anything
else. Test (`test/setup.test.ts`): wrong code refused and the code stays valid; a second setup refused after the first completes; the code never appears in
captured stdout or the journal; a COSE map with an unknown key type, an extra member, a floating-point value or trailing bytes is refused; setup without a
device-key registration refuses to complete; the phrase is stored in `private.db` only.

**`KBOX-7` What needs the phone: one approval per action, bound to one exact action.** Source: design §3. The actions that need an approval: adding or
importing an admin or master key, deleting one, every rotation of one (scheduled or manual); granting or revoking a machine's use of an admin key; adding or
removing a destination of an admin key, and changing its relay allow rules or schedule; lowering a key's class (`demote`); enrolling a machine token; a Vercel
domain or team-setting change (`KBOX-26`); adding or removing an approver; installing an update. Changes to ordinary keys need no approval. There is no bulk
approval route and no route that takes more than one action. **Slots (against approval fatigue):** every proposal sits in one slot named by kind and
subject: rotate, delete, demote, grant, destination, allow-rule and schedule changes have the key as subject; enrol has the source address; Vercel domain and
team-setting changes have one slot per project and operation; approver-add and update have no subject and one slot each. One proposal is pending per slot. A
second proposal in an occupied slot from another requester token is refused with `slot_taken` (409) naming the pending approval; from the same requester token
it **replaces** the pending content (same approval id, `revision` + 1, new digest, fresh nonce, the earlier assertion no longer applies) and sends no new push;
a proposal originated by the box (a scheduled rotation, a platform expiry) takes over an occupied slot; pending proposals expire after 14 days; a denial
frees the slot. A proposal that would allow a `mustDeny` operation (`KBOX-25`) is refused at proposal time with `rejected` and never reaches the phone. The
scheduler's one-per-day staggering is in `KBOX-52`. Test (`test/slots.test.ts`, `FakeClock`): every row above as a case; update, approver-add, enrol (per source
address) and demote (per key) each have one slot; a second token gets 409 and the same token replaces with no second push; a box rotation takes over a squatted
slot and the squatter's pending assertion no longer applies; expiry at 14 days minus 1 ms and plus 1 ms; denial frees; no route accepts a list of actions; a
canary in a requester reason is absent from push payloads.

**`KBOX-8` The box writes the words.** Source: design §3. The action is stored as typed data when proposed. The page text is rendered by the box, in fixed
sentences per action kind (`src/pure/words.ts`), from that data, never from text sent by mission control. A requester's reason appears separately as "Reason
given by <machine>/<agent> (not checked)", plain text, no links. Every page names the requesting machine token. A page for a key without watch coverage
says so in plain words. Test: a table test renders every action kind from fixtures and compares against the fixed sentences; a reason carrying markup, a link
and a canary renders as inert text and the other sentences are unchanged; the page for each kind names the token label; the title of each kind (used by push
and `meta`) is pinned.

**`KBOX-9` The signature is bound to the exact action and to the approver device.** Source: design §3. `actionDigest = SHA-256` of the canonical action JSON,
which is RFC 8785 (JCS) restricted to integers: sorted keys, UTF-8, no floats, no `null` (an absent member is omitted), no whitespace. Each page render gets
a fresh 32-byte nonce, used once. The challenge is `SHA-256("kbox-v1" ‖ approvalId ‖ actionDigest ‖ nonce)` (approvalId as UTF-8; the digest and nonce are
fixed length, so the concatenation is unambiguous). The box accepts an approval only when all hold: the passkey signature verifies against a registered
approver; `clientDataJSON.type` is `webauthn.get`; the origin is exactly `https://keys.<domain>`; `rpIdHash` is SHA-256 of `keys.<domain>`; flags UP and UV
are set; the challenge matches; the nonce is unused; the stored action is still pending with the same digest; and an ECDSA P-256 signature over the same
challenge verifies against **the device key of the same approver** (WebCrypto non-extractable key, signature as raw 64-byte r‖s over the 32 challenge bytes
with SHA-256, verified with `dsaEncoding: 'ieee-p1363'`). An approver is a (passkey, device key) pair registered together. A passkey alone never approves or
opens a view. An approval executes by its stored id, never from a client body. Deny needs an assertion too. A **view session** needs the passkey assertion
and the device-key signature over a view challenge `SHA-256("kbox-v1-view" ‖ nonce)`, and gives a read-only cookie (`__Host-` prefix, HttpOnly, Secure,
SameSite=Strict, no `Domain`) that can change nothing. Losing the device key (reinstalling the app, clearing its data) forces recovery; the setup page says so
before it creates the key. Hand-written crypto here (WebAuthn assertion verification, authenticator-data parsing, DER-to-raw ECDSA conversion, challenge
construction) uses `node:crypto` primitives only and has known-answer tests. Test (`test/approval-binding.test.ts`): an assertion for action A replayed for B is
refused; UV clear refused; wrong origin and wrong rpIdHash refused; `type` other than `webauthn.get` refused; nonce reuse refused; passkey without device
signature refused; passkey of approver X with the device key of approver Y refused; a changed action digest after render refused; a view session without the
device signature refused; the assertion verifier passes a published WebAuthn test vector (the builder names its source and reports if none usable); a
JCS vector set (sorted keys, unicode, escapes, integer boundaries, a float refused).

**`KBOX-11` Machine tokens and their scopes.** Source: design §2 (owner decisions C-686). A token is generated on the machine that uses it: the machine's
enrol step writes 32 random bytes to its local store and sends only `SHA-256(token)`, a label and the scope. Passes are not tied to an address: no address is
registered, pinned or checked; the box writes the client address of every use to the audit log. The first enrolment (mission control's `control` token) is
accepted only inside a 10-minute window the owner opens in the app (a phone action that needs the view session). Every later enrolment is a proposal and needs
an approval whose text reads "enrol <label> for relay (request seen from <address>; the label and the address are not checked)". Scopes: `control` (mission
control: read metadata, status, audit and events; propose; issue and manage **ordinary** keys, Vercel project tokens included; request the three Vercel
operations; fetch deliveries) and `relay:<label>` (only `/r/*`, only keys granted to that machine). The first use of any token from a new network sends one Web
Push naming the token and network. Any token is revoked from the phone in one tap with no further approval (revoking only removes access). Test
(`test/machine-tokens.test.ts`): a relay token on `/api/*` refused; a control token on `/r/*` refused; enrol with no window and `scope: control` refused;
window expiry at 10 minutes of fake time and single use; a relay enrol from any address makes a proposal whose text carries the label and the address seen
(spoofed `X-Forwarded-For` ignored); no address-registry or pin member exists in any schema; an approved relay token works from two addresses; first use from a
new network sends exactly one push and a second from the same network none; revocation takes effect on the next request.

**`KBOX-20` Recovery of the approver.** Source: design §8 (revision 5; Q3 as amended by C-692). The only way in is the Oracle login (`KBOX-48` carries the
account rules). At every boot the box writes a fresh **recovery code** (12 words as in `KBOX-49`) to the console sink only (the serial console device, written
directly, never to stdout or the journal) and keeps only its hash; the code is valid for 30 minutes after boot and once. `/recover` takes the code, registers
a new approver (passkey, device key, phrase) and **revokes every other approver**, sending each a Web Push first. Why the code alone suffices: whoever holds
the Oracle account can already read the disk. Two cases are stated in the box's own words on `/recover` and on setup: the app was reinstalled or its data
cleared (recover with the authenticator app on the same phone); the phone is lost (recover with the authenticator app restored from the owner's Google account on a
new phone; paper backup codes were skipped for now). Web address lost or Oracle account lost: no recovery in the box; setup is redone from the bootstrap
(design §8). Test (`test/recovery.test.ts`, `FakeClock`): no code exists until `boot()` runs; code refused at 30 minutes plus 1 ms, on second use, and after a
second boot (the old code is void); recovery revokes every other approver and each gets a push first; the code is absent from captured stdout, the journal and
the audit log (only a `recovery.used` action without text); a new approver after recovery can approve and an old one cannot; the real console device is
UNVERIFIED (design §12: whether OCI console history captures the boot-time code) and is probed by the `update` unit on the real instance.

**`KBOX-22` How the owner learns something waits.** Source: design §3. Web Push from the box itself is the primary channel. The VAPID private key and the push
subscriptions live only in `private.db`. A notification carries the box's one-line title and names only; tapping it opens the installed Key box app at the box's
origin; the app icon badge shows the number waiting. The box signs VAPID JWTs (RFC 8292, ES256) and encrypts payloads (RFC 8291, `aes128gcm`, HKDF) with
`node:crypto` only. Mission control may raise one desk card per waiting approval ("Your phone has something to approve in the Key box app" plus the title); **no
route, field or event of the box carries a URL to the box for use in a card** (the only URL in any response is the OIDC and JWKS metadata). If push fails, the
app still shows the queue when opened. Test (`test/web-push.test.ts`): payload encryption reproduces the RFC 8291 appendix example byte for byte; the VAPID JWT
verifies with an independent ES256 check written in the test; a failing push endpoint (fakePlatform: 410, 500, hang) removes the subscription on 410, retries
nothing on 500 and never blocks the approval queue; a payload never contains more than title, kind and count; no response schema has a member holding the box's
URL.

**`KBOX-53` Proposal and enrol routes, and the closed action kinds.** Source: design §3, §6.3; shapes decided here.
- `POST /api/proposals` (scope `control`): body `{action, reason?}`. Response 201 `{approval_id, status:"pending", slot, revision, replaced}`; 409 `slot_taken`
  with `{pending_approval_id}` in the error's `detail`; 422 `rejected` for a `mustDeny` match or a malformed action. The `action` is one of the closed kinds, each
  with typed members: `add_key {platform, name, projects, scope, mark_admin?, label?}`, `delete_key {keyref}`, `rotate_key {keyref}`, `grant {keyref, machine}`,
  `revoke_grant {keyref, machine}`, `add_destination {keyref, destination}`, `remove_destination {keyref, destination}`, `set_allow_rules {keyref, rules}`,
  `set_schedule {keyref, rotate_every_days, grace_hours}`, `demote {keyref}`, `vercel_set_domain {project, op, domain, to_project?}`,
  `vercel_set_team_setting {setting, value}`, `approver_add {}`, `approver_remove {approver_id}`, `install_update {install, commit, base}`. (`enrol` is created by
  the enrol route below; `install_update` by `POST /api/updates`; `add_key` for an admin key by `POST /api/keys`, `KBOX-34`.) A kind outside the list is `bad_request`.
- `POST /api/enrol` (no token): body `{token_sha256, label, scope: "control"|"relay", reason?}`. `control` is accepted only while the window is open and
  answers 201 `{status:"active"}` and the box's `share_public_key_ed25519_b64`; `relay` creates or replaces the `enrol` proposal of the source address and
  answers 202 `{status:"pending"}`. `GET /api/enrol/<token_sha256>` (no token) answers `{status: pending|approved|denied|expired}` and nothing else. Labels are
  `[a-z0-9-]{1,32}`; a label already used by an active token is `conflict`.
- `approver_add` is proposed from the app by an existing approver (view session). When approved, the approving app shows a one-time registration code (12
  words, valid 10 minutes, once) that the new device enters at `/recover`'s registration step; this path is decided here (design §3 lists the approval but not the
  registration step).
Test (`test/proposal-routes.test.ts`): each kind accepted with valid members and refused with each member wrong; the response shapes pinned by closed
schema; the three enrol cases; a hash that is not 64 hex characters refused; the enrol status route reveals nothing beyond the status word; approver-add code
refused after 10 minutes and on second use.

### Unit `update`: bundle intake, install over an approved base, the bootstrap, egress layers, idle watch

**`KBOX-1` Nobody logs in.** Source: design §1.2. The box has no `sshd`, no login user besides system accounts, no shell endpoint and no debug route; the OCI
Run Command agent plugin is disabled; the OCI Compute Instance Monitoring plugin stays on. The serial console is reachable only through the OCI account. Agents
get no login, root, console or cloud-account access. Test (`test/bootstrap-text.test.ts`, text check of `deploy/cloud-init.yaml`): `ssh` packages removed and
`sshd` masked, no `authorized_keys` for any user, the default user's keys removed, the Run Command plugin disabled and the monitoring plugin not; the route
table of core and relay (exported by `main-*`) has no route matching shell, exec, debug, eval or console; the exact command that disables the plugin is
UNVERIFIED and is probed on the real instance by the builder (reported, not run in tests).

**`KBOX-6` The box installs only an approved exact hash, over the base it was approved against.** Source: design §1.4. `POST /api/updates` (scope `control`,
`Content-Type: application/x-tar`, query `commit=<40 hex>`) takes a tar of the tracked files at commit C plus `runtime.lock`. Intake limits: 20 MiB, 5,000
entries, 255-byte paths; regular files and directories only; symlinks, hard links, devices, FIFOs, pax or GNU extended headers and any path outside the tree
(absolute, containing `..`) are refused. One pax **global** header (`g`) as the very first entry is accepted and ignored (that is how `git archive` writes
the commit id; decided here). The box computes the **content hash** H itself: SHA-256 of the text made of one line per file, sorted bytewise by path,
`<mode> <sha256 hex> <path>\n`, with mode `0755` if the owner-execute bit is set and `0644` otherwise (decided here). It opens an `install_update` approval
`{install: H, commit: C, base: H0}` where H0 is the running release, and answers 201 `{approval_id, hash, base}`. The phone page says, in the box's fixed words:
"Install key box version H[:12] (commit C[:12]) over version H0[:12]"; the number of files added, changed and removed; changes to `runtime.lock` (Node or Caddy
binary hashes) with the official download URL of each; and the fixed sentence **"Agents wrote this version and only agents checked it. Any change can take every
key, and this page cannot tell whether it is safe."** On approval the box refuses if `current` is no longer H0 (a new proposal is needed); otherwise it
re-hashes the staged tree (mismatch refuses), unpacks to `/opt/keybox/releases/<H>`, downloads and verifies any new pinned binary, switches the `current` link
and restarts the units. The health check passes when both processes answer `GET /healthz` with the new H within 60 seconds of restart (decided here); on
failure it switches back to H0 and emits `update.state rolled_back`. An approval names H and H0 and cannot install any other bundle or apply over any other base.
Test (`test/update.test.ts`, temp dirs, fake systemd port): staged tree changed after approval refused; approval of H1 cannot install H2; base H0 refused when
`current` is H1; symlink, hard link, device, FIFO, `..`, absolute path, pax `x` header and a second `g` header refused; 20 MiB + 1, 5,001 entries and a
256-byte path refused; failed health check rolls back and leaves `current` at H0; a crash between unpack and link switch leaves the old release running; the
update page carries the fixed sentence byte for byte; the hash matches a vector computed independently in the test; a truncated tar is refused with a fixed code.

**`KBOX-21` Not looking idle.** Source: design §8. Oracle may reclaim an Always Free instance when, over 7 days, CPU p95, network and (A1 only) memory are all
under 20% (VERIFIED); whether pay-as-you-go accounts are exempt is UNVERIFIED, so the box assumes they are not. The A1 box is 1 OCPU and 2 GB. kb-core keeps a
touched working reserve so memory use stays above 30% of `MemTotal` (the design says above 25%; the 5 points of margin are decided here); it computes
the same three figures over a rolling 7 days from `/proc` (CPU from `/proc/stat`, memory from `/proc/meminfo`, network from `/proc/net/dev` against the nominal
link speed in `deploy/runtime.config.json`) and sends a Web Push if all three come within 5 points of the 20% line. How Oracle computes its network figure and
whether the figures here match its `MemoryUtilization` metric are UNVERIFIED; the builder measures them on the real instance and reports (design §12). The box
makes no call to Oracle's monitoring API. Test (`test/idle-watch.test.ts`, synthetic `/proc` files, `FakeClock`): the push fires when the three figures are
within 5 points, not when one is 6 points away; the reserve keeps memory at or above 30% of a fake `MemTotal` and is released on shutdown; a failing `/proc`
read is reported once as a notice, not swallowed.

**`KBOX-44` The Caddy client-address header.** Source: design §1.3. `deploy/Caddyfile` terminates TLS with ACME TLS-ALPN-01 on 443 only (port 80 closed), routes
`keys.<domain>` to core and `api.keys.<domain>` `/api/*` to core and `/r/*` to relay over the unix sockets, sets `X-KB-Client-Ip` from its own view of the
connection replacing any client value, and removes `X-Forwarded-For`, `X-Real-IP` and `Forwarded` from the request. The Caddy and Node binaries are pinned by
sha256 in `runtime.lock`. Test (text check): each directive is present; a request-header manipulation test is run against a real Caddy only on the real
instance (UNVERIFIED, reported); the lock file lists a sha256 and an official URL for each binary.

**`KBOX-46` Egress layers 1 and 2, stated honestly.** Source: design §1.5 (egress). Layer 1: the OCI security list (ingress TCP 443 only; egress TCP 443 to
anywhere, and UDP/TCP 53 plus UDP 123 to `169.254.169.254` only), written into the setup checklist. Layer 2: kb-relay's unit has `IPAddressDeny=` covering
link-local, private and loopback ranges with `IPAddressAllow=127.0.0.53/32` for the resolver stub. Layer 3 is `KBOX-47`. The update page and the setup page say
that none of these stops approved malicious code. Test (text check): the checklist lists the exact security-list rows; the relay unit carries the two
directives; both pages carry the sentence "These limits do not stop an approved update that is malicious."

**`KBOX-48` The bootstrap text and the setup checklist.** Source: design §1.5. The bootstrap is a cloud-init document of about 60 lines in the repo's README
at a tagged release, opened on the phone. It names the commit C and content hash H of release 1 and the official URLs and sha256 of the Node and Caddy builds;
downloads the source at C from `codeload.github.com`; checks H; installs; removes sshd and the default user's keys; disables the Run Command plugin; starts
the units; and generates the one-time setup code (`KBOX-49`) writing it to the console sink only. The checklist (`docs/setup-checklist.md`, written by this unit)
says, in order: a new email account and a new Oracle account logged into only from the phone; one factor that does not sync to any machine the agents use: an
**authenticator app synced only to the owner's Google account, which is never signed in on the workstation, devbox or Helsinki**, and whose passwords for
Oracle, deSEC and the email account are not saved anywhere that syncs to those machines (design §8, revision 5); no passkey sign-in and no SMS on these
accounts; pay-as-you-go with a budget alert; home region near the owner; a free `dedyn.io` name in a deSEC account used only from the phone with its own
login, DNSSEC if offered; `keys.<domain>` and `api.keys.<domain>` at a reserved IP; Ubuntu LTS minimal on A1 (1 OCPU, 2 GB), "no SSH key", the reserved IP,
the security list of `KBOX-46`, the bootstrap text as cloud-init user data; reading the setup code in the console history; `/setup`. It states plainly: the
free name can be withdrawn and then setup is redone on a new name; if A1 capacity is unavailable, try again later or another availability domain; the E2.1.Micro
shape is not an option (no memory criterion in Oracle's idle rule). Test (`test/bootstrap-text.test.ts`, text check): the cloud-init names C and H and four
pinned hashes, calls no network host other than the declared ones, and never contains a value; the checklist contains the Google-synced-authenticator sentence
and does not contain "hardware key" as a requirement or "cloud sync off"; the recovery wording matches `KBOX-20`'s two cases; the three UNVERIFIED items of
design §12 (deSEC authenticator app, TLS-ALPN-01 for a `dedyn.io` name, DNSSEC) are marked UNVERIFIED in the checklist.

### Unit `relay`: the relay process, the lend socket, forwarding, scanning and the egress gate

**`KBOX-3` Master keys never reach the relay.** Source: design §1.2. kb-relay cannot read the vault. Core lends it a value over `/run/keybox/lend.sock` (one request
per lend; request `{token_hash, keyref, rule_id}`; answer the value for that one call) only when all hold: the key is admin class (never master, never
ordinary), a grant exists for the calling relay token's machine, the key has a relay profile, and the request matched an allow rule of that profile. Core
re-checks token, grant and rule id. Master values are lent only to issuer, verifier and destination code inside core. This is enforced by a class check in the
lend handler, not by configuration. Indirect use is closed by `KBOX-13` and `KBOX-14`. Test (`test/lend.test.ts`): a master keyref is refused with no value
sent; an ordinary keyref refused; a keyref without a grant refused; a revoked token refused; a rule id not in the profile refused; a lend call from a process
the socket mode refuses (see `KBOX-45`); the lend response is a one-shot (a second read on the same connection gets nothing); core down makes the relay answer
503 `unavailable`; the canary is absent from the relay's logs.

**`KBOX-13` Forwarding rules.** Source: design §4. The relay URL is `https://api.keys.<domain>/r/<keyref>/<path>`; the upstream origin is fixed by the key's
profile (the Google profile takes the host as the first path segment, which must equal byte for byte one of the key's declared hosts: lowercase ASCII, no
port, no `@`, no `%`, no trailing dot). In order:
1. Read the caller's token from the profile's declared headers (`Authorization: Bearer`, `apikey`); if several declared headers are present they must carry
   the same token or the request is 400.
2. The token must be a relay token, not revoked, with a grant on `keyref`; the source address is not checked, it goes in the audit.
3. **Parse once, refuse ambiguity.** From the raw request target, 400 with no upstream call if the path has an encoded `/`, `\` or `.` (`%2F`, `%5C`, `%2E`,
   either case); `%00`, a control byte or a non-ASCII byte; a raw `\`, `;`, `#`; an empty segment (`//`); a `.` or `..` segment; a malformed `%` escape. The
   remaining percent escapes are decoded per segment; rules match the **decoded segments**; the forwarded path is the decoded segments re-encoded canonically
   (RFC 3986 unreserved literal, everything else `%XX` upper case), so the path matched is the path sent.
4. **Method and query.** The method comes from the request line only; `X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override` give 400. The query is split on
   `&`; 400 for a malformed `%` escape, `%00`, a control or non-ASCII byte, a raw `;` or `#`, an empty key or a duplicate key; names and values are decoded once
   and a decoded name or value still holding `%`, `&`, `=` or a control byte is refused. Each allow rule lists the exact query keys it accepts, each with a value
   shape (a fixed word or a bounded integer); the default is none. A decoded key the matched rule does not list is 403, so `?al%74=media`, `?%24method=`,
   `?%61ccess_token=` and `$httpMethod` fail and no rule lists `access_token`, `key` or `apikey`. The forwarded query is the matched keys re-encoded.
5. **Match the profile**: default-deny; the request must match one allow rule `{id, method, host, pathTemplate, query}` and none of the profile's `mustDeny`
   rules. A miss is 403, no upstream call, no lend.
6. Ask core for a lend (`KBOX-3`).
7. Build the upstream request: forward only the profile's request-header allow-list (default `Content-Type`, `Accept`, `Content-Length` recomputed; per profile
   `Prefer`, `Range`, `OpenAI-Beta`, `Idempotency-Key`; Supabase `Accept-Profile` and `Content-Profile` only with the value `public`); drop everything else
   (the caller's `Authorization` included); set `Accept-Encoding: identity`; set the profile's auth headers from the lent value, never in the query or body; `redirect:
   manual` (a 3xx goes back unfollowed); send through the egress gate (`KBOX-47`); stream both ways (SSE works); request bodies up to 32 MiB (413 above).
   The upstream connect timeout is 10 s and there is no total timeout, so streams are not cut (decided here).
8. Pass the response through the scanner (`KBOX-14`).
9. Audit (`KBOX-50`): time, token label, source address, claimed agent and project (`X-Agent`, `X-Project`; logged, not checked, not forwarded), keyref, method, **rule
   id** (the query is dropped), status, bytes. Bodies are never logged. WebSockets are not relayed in v1.
Failure shapes: unknown or revoked token 401 `bad_token`; no grant or no rule 403 `forbidden`; ambiguity 400 `bad_path`, `bad_query`, `method_override`; upstream
unreachable 502 `upstream_unreachable`; connect timeout 504 `upstream_timeout`; core down 503 `unavailable`; each with the fixed text of `KBOX-29`'s frame.
Test (`test/relay-forward.test.ts`, relay over a real loopback `fakePlatform()` through the gate's test connector): the canonicalisation table (`%2F`, `%2e%2e`,
`//`, `;x`, `\`, non-ASCII, bad `%`, `/v1//x`, `/v1/%6Frganization/`) gives 400 with no upstream call; the forwarded path equals the matched path; the three override
headers give 400; `?_method=`, `?al%74=media`, `?%24method=`, `?%61ccess_token=`, `$httpMethod`, a duplicated key give refusal with no upstream call; a non-listed request
header is not forwarded and the caller's `Authorization` never is; `Accept-Profile: vault` gives 403; a 3xx is not followed; two different source addresses both pass;
the audit row has the rule id and no query; a hung upstream gives 504; a refused connection gives 502; the real streaming path is run once end to end with a 5 MiB
body and an SSE stream.

**`KBOX-14` Response handling.** Source: design §4. Every relayed response's headers and body are matched, as a stream with carry, against every value the box holds
(all `scanForms` of `KBOX-54`, master values and the short-lived Google tokens the relay injects included) and against a fixed list of credential shapes held as data in
`src/data/credential-shapes.json`: prefixes `sk-`, `sk_`, `rk_`, `ek_`, `vcp_`, `vci_`, `vca_`, `vcr_`, `vck_`, `sb_secret_`, `sbp_`, `GOCSPX-`, `AIza`, `ya29.`, `1//`,
`github_pat_`, `ghp_`, `whsec_`; PEM private-key headers; JSON members named `private_key`, `client_secret`, `refresh_token`, `access_token`, `bearerToken`,
`signing_secret`, `xi-api-key` or `api_key` with a non-empty string value; JWTs (three base64url segments, the first decoding to JSON with `alg`). On either hit the
stream is cut, the caller gets 502 `withheld` ("response withheld: it carried a key"), and the audit log and an owner notice follow; there are no per-operation
exceptions. Upstream 401 and 403 bodies are replaced by the fixed text "upstream refused the key" with the status. Response headers are an allow-list (`Content-Type`,
`Content-Length`, `Retry-After`, rate-limit headers, `Location` on a 3xx, the platform's request-id header); `Set-Cookie` is dropped; every response gets
`X-Content-Type-Options: nosniff`, `Content-Security-Policy: sandbox; default-src 'none'` and `Content-Disposition: attachment`. Test (`test/relay-scan.test.ts`): a
held value withheld in raw, base64 (three alignments), hex, percent, JSON and `\u` forms, split across two chunks and across the header and body; a `sk-…`, a JWT, a
`"client_secret":"x"` and a PEM withheld; an empty-string `api_key` member passes; an upstream 401 whose body quotes a key hint is replaced; response headers are exactly
the allow-list plus the three forced ones; the cut stream sends no more bytes after the hit (a byte counter on the fake upstream's socket); a seeded property test mixes
random JSON with one planted copy at a random offset and always catches it.

**`KBOX-25` Relay profiles: default-deny, named operations, `mustDeny` regression lists.** Source: design §5.5. A profile's allow rule is `{id, method, host,
pathTemplate, query}`; template segments are literals or typed parameters (`{id:[A-Za-z0-9_-]{1,128}}`); a trailing `{rest:**}` is allowed only where a profile names it
and each tail segment is still validated. A key's own allow set widens only by approval, and the box refuses to propose a rule matching a `mustDeny` sample (`KBOX-7`).
`mustDeny` is the **regression list**; default-deny is the boundary. Each entry carries concrete sample requests, including the canonicalisation variants of `KBOX-13`.
The deny test sends every sample through the relay with the default profile and with a test profile whose allow set is widened as far as the registry permits, and
expects 400 or 403 and **no upstream call**. The credential-shape scanner is the backstop. The mechanism is built here with a test profile; each platform unit supplies
its profile's content. Test (`test/profile-engine.test.ts`): template matching (literal, typed parameter, `{rest:**}`, a trailing slash, a segment of 129 characters);
widening refusal; the deny test harness itself fails when a sample is allowed (positive control with a deliberately leaky profile).

**`KBOX-23` Registry checks at startup.** Source: design §5.1. The box refuses to start if any fails, and the same checks run as tests: an issuer with
`revealOnce: true` exports a `lister`; a `relay` profile has a non-empty `mustDeny` and no `allow` rule matches any `mustDeny` sample request; a platform listed in
`relayDenyOnly` (Vercel and ElevenLabs in v1) exports a `mustDeny` list and no `relay`. Adding a platform is one folder `src/platforms/<id>/` plus one registry line.
Test (`test/registry.test.ts`): a fixture platform that breaks each check fails startup with a fixed code naming the platform; the real registry passes.

**`KBOX-32` The relay endpoint and the pass: what agents and `with-keys` rely on.** Source: design §2, §4; shapes decided here. A pass is a relay token as in
`KBOX-10`, generated on the machine. It is carried in the profile's declared header(s) (OpenAI: `Authorization: Bearer <pass>`; Supabase: `apikey: <pass>`, and
`Authorization: Bearer <pass>`, which supabase-js also sends; Google: `Authorization: Bearer <pass>`). Relay URL: `https://api.keys.<domain>/r/<keyref>/<path>`;
Google: `/r/<keyref>/<host>/<path>`. `GET /r/_/grants` (relay token) returns `{machine, grants:[{keyref, platform, name, projects, env}]}` where `env` is the
profile's `envForClients(relayUrl)` with the pass left as the literal `"<pass>"` (the client substitutes its own pass). The profiles' `envForClients`: OpenAI
`{OPENAI_BASE_URL: <relay>/v1, OPENAI_API_KEY: "<pass>"}`; Supabase `{SUPABASE_URL: <relay>, SUPABASE_SECRET_KEY: "<pass>"}` (relay url is
`https://api.keys.<domain>/r/<keyref>`); Google `{KBOX_GOOGLE_RELAY_URL: <relay>}` (no standard client variable exists; decided here). `_` is not a valid keyref
(`[a-z0-9]{6,24}`). A pass works on `/r/*` only, never on `/api/*`. Test (`test/relay-contract.test.ts`): each profile's env map is pinned; a pass in the wrong header
for its profile is 401; `/r/_/grants` lists only the granted keys of that machine and no value; a keyref of 5 or 25 characters or with an upper-case letter never
routes; a pass for machine A does not list B's grants; the OpenAI SDK's own request shape (an `Authorization` header and a `/v1/...` path under the base URL) is
replayed from a recorded fixture and reaches the matched rule.

**`KBOX-47` The in-code egress gate.** Source: design §1.1, §1.5 (layer 3). Every outbound request of core and relay goes through one module. It refuses a host no registered
adapter declares, and any resolved address that is private, link-local or loopback (including `169.254.169.254` and IPv4-mapped IPv6). Resolution happens once and the
connection uses the resolved address (no second lookup). The connector is a port, so tests use a fake. Test (`test/egress-gate.test.ts`): undeclared host, each private range, the
metadata address, IPv4-mapped IPv6, a name that resolves first to a public and then to a private address (pinned to the first), a redirect target outside the list refused;
the production wiring is run against literal-IP URLs without opening any socket (the refusal is before connect).

### Unit `rotate`: the orchestrator, reconcile, the scheduler, the paste source, key issue and deliveries

**`KBOX-51` The rotation state machine, intent first, reconcile by list.** Source: design §5.2. State per run is persisted in `meta.db`; one run per key at a time
(structural: a unique index). Steps: (1) planned (scheduler, platform expiry, owner or agent request); admin and master keys wait at `awaiting_approval`; (2) write the row
`issuing {run, intentName}` before any platform call, `intentName = kbox_<ref>_g<N>_<run8>` (lower case, valid on every platform; Supabase requires `^[a-z_][a-z0-9_]+$`, 4 to
64 characters, VERIFIED); (3) acquire: `Issuer.issue(req, intentName, master)` or a paste task (`KBOX-12`); (4) store as generation N+1 `pending`, N stays `current`; (5) verify the
new key with the verifier before any push; (6) push to every destination recording a receipt (the platform's object id) per destination, "make it so": a repeat finds its receipt
and updates that object; the workstation destination is a delivery (`KBOX-34`); (7) redeploy where `needsRedeploy` and wait for `ready`; (8) check with the verifier again;
(9) promote: N+1 `current`, N to `grace` until `revokeAt = now + grace` (per key; 24 h by default when any runtime destination exists, else 1 h); (10) revoke N at the platform,
then **confirm it is dead** before marking it `retired`: a 404 (`absent`) is not proof; the confirmation is the verifier **rejecting the old value** (the vault still holds it),
or, where a platform has no verifier call that can test a key, the `KeyLister` showing the id absent or disabled in the region and project recorded with the key; if the
verifier says the old value still works or cannot be reached, the key stays in `grace` and step 10's failure path applies. The old value stays in the vault for fingerprints
only and is never lent or pushed again. **Reconcile** on start and daily: a run holds a **lease** while a process works on it; reconcile skips leased keys, and on start runs
only after resume has re-leased unfinished runs; for every issuer it lists the platform's keys; a `kbox_…` key matching an unleased `issuing` intent with no stored generation is an
orphan from a crash between steps 3 and 4: it is revoked and confirmed, the run returns to step 2 with a new run id, and the audit log records it; a `kbox_…` key matching no intent or
generation raises one notice. Test (`test/rotation.test.ts`, fakes through the ports, `FakeClock`): a crash injected after each step resumes from the persisted step; crash between
platform create and vault store gives the orphan found by `list` and revoked; revoke returning 404 while the verifier still accepts the old value (wrong-region sample) leaves it
`grace`, retried, one notice; verifier rejecting gives `retired`; a daily reconcile during an in-flight run (between issue and `vault.put`) revokes nothing; an unleased `issuing` row after a
crash is reconciled; a push repeated after a crash updates its receipt's object and creates none; `overlap: false` order (set new, push, redeploy at once, rollback sets the old value
back); a second run for the same key is refused.

**`KBOX-17` Failure keeps the old key.** Source: design §5.2. A failure at steps 3 to 8 rolls back: re-push generation N to the destinations already changed and redeploy those that were
redeployed; revoke N+1 at the platform (if issued) and confirm it as in step 10; mark it `failed`. The owner gets **one notice** per failed run: a Web Push for admin and master keys
and a `rotation.failed` event (mission control raises the desk card) for every class; it names the step and the names-only reason and confirms the old key still works. A failure at
step 10 retries with backoff (S-249; first retry after 1 minute, doubling to a cap of 1 hour; decided here) and one notice says "the old key is still on; the box keeps trying"
(`rotation.old_key_still_on`). Platforms with `overlap: false` skip grace; the approval page says "open connections drop briefly". Test: a fault injected at each of steps 3 to 8 leaves the
old key current in every destination, the new one revoked, and exactly one notice; a fault during rollback itself (a destination that refuses the re-push) keeps the run `failed` with a second
named notice only for that destination; the retry schedule on `FakeClock`; the canary is absent from the failure texts.

**`KBOX-52` The scheduler.** Source: design §5.2. Each key has `rotateEvery` (90 days by default). The due date is the earlier of the schedule and `expiresAt - grace - 1 day`, moved earlier
where needed so that at most one admin or master rotation falls due per day (a schedule, not a cap: a manual "replace now" is never held back). For an admin or master key "due" opens
an approval (a box-originated proposal, `KBOX-7`) and the old key keeps working while it waits. Test (`test/scheduler.test.ts`, `FakeClock`, a seeded property test): for any set of keys, at most one
admin or master rotation is due per day and every due date is no later than the unstaggered one; an expiry earlier than the schedule wins; a manual rotation is never delayed; a due admin key
opens exactly one approval and a second tick opens none.

**`KBOX-15` Class is computed and never lowered by a caller.** Source: design §5.1. The class is the higher of `capabilities().classify(scope)` and the owner's mark. Mission control may mark a
key admin but never lower one. A caller asking the box to issue an "ordinary" key whose scope the adapter classes admin gets an admin key and an approval (`POST /api/keys` answers `class: "admin"`
and `approval_id`). Any key that can create keys is `master`. `demote` is a phone action. Test: a table of (platform fixture, scope) to class; `mark_admin` raises and a lowering request is refused;
an ordinary request with an admin scope returns an approval and issues nothing before the approval; a master scope is never issuable through `POST /api/keys`.

**`KBOX-16` Admin keys go only to runtime destinations.** Source: design §5.1. A destination with `readableBy: 'api'` (Vercel `encrypted` env; Google Secret Manager; Supabase
edge-function secrets until a probe shows their `GET` holds no value) is refused for admin and master keys. The phone page for a `runtime` destination says "code deployed to <app> can read this key".
Test: each destination fixture with `readableBy: api` is refused for admin and master and accepted for ordinary; the page words for a runtime destination; a destination whose `properties()` changes at
runtime is rechecked at push.

**`KBOX-12` Phone paste flow.** Source: design §3, §5.3. A paste task appears only in the Key box app's queue (`/p/<id>`); the box never sends a link to it; the page checks the installed app's display
mode as a convenience, not a boundary. For a paste-source key, `add_key` and `rotate_key` open a paste task instead of an approval: the paste, with its assertion, **is** the approval of that one action
(decided here; one action per approval holds). Opening the queue needs a view session (`KBOX-9`) and then shows the owner's setup phrase; the fixed rule on every paste page is **"Only paste where you see
your phrase."** The page names the platform, key, machine grant and scope in the box's words, with the adapter's own link to the platform's key page (never from mission control), and asks the owner to create
the key on the phone. The value goes in a masked field with autocomplete off; the POST carries the value plus the passkey assertion and device-key signature over `SHA-256("kbox-v1-paste" ‖ pasteId ‖ nonce)`.
The box checks the value: the core length floor (16 bytes, refused below), the adapter's **strict shape check** (prefix, core alphabet and core length), and the platform verifier; then stores it and never
echoes it. A value failing the shape check is refused for platforms whose format is known; coverage (`KBOX-18`) follows from the shape check only, never from length alone. A failed check shows the verifier's
names-only reason and keeps the field for a retry (HTTP 422 `rejected`). Test (`test/paste.test.ts`): a paste without the device signature, with an assertion for another paste id, with a reused nonce or
without a view session is refused and stores nothing; a 15-byte value refused and a 16-byte value with a failing shape refused; a good value is stored, verified, and absent from the response and every surface
(canary); the retry keeps the field; no response contains a URL to the box; the 16 against 32 floor disagreement of mission control's KREQ-14 is not copied: this rule's floor is 16 and the shape check decides
(see open point 2).

**`KBOX-34` Key issue, rotations, retired generations and deliveries: the routes mission control and `hand-off` call.** Source: design §6.3, §6.6, §6.7 (AKEY-3, AKEY-4); shapes decided here. All scope `control`.
- `POST /api/keys` body `{platform, name, projects, scope, label?, destinations?, rotate_every_days?}`: an ordinary key on a platform with an issuer is created at once (`201 {keyref, class, status}`);
  an admin or master class result opens an `add_key` approval (`202 {keyref, class, approval_id}`); a paste-source platform opens a paste task (`202 {keyref, class, paste_task_id}`, no link). The key's env `name` is
  `[A-Z][A-Z0-9_]*`.
- `POST /api/rotations` body `{keyref}`: ordinary starts a run (`201 {run_id}`), admin or master opens a `rotate_key` proposal or paste task (`202 {approval_id | paste_task_id}`); a run already exists gives `conflict`.
- `POST /api/retired?platform=<id>&project=<p>&name=<NAME>` with `Content-Type: application/octet-stream` and the old value as the body (the `hand-off` stream; no phone approval, because a retired value grants no use and is
  never lent; decided here): stores it as a retired generation under a key record (created if absent, class from the adapter) and answers `201 {keyref, gen, coverage}`; a value failing the adapter's shape check is stored
  uncovered (`coverage: none`) and never fingerprinted; the value is in no response and no log.
- `GET /api/deliveries` returns `{deliveries:[{delivery_id, keyref, project, name, gen}]}`; `GET /api/deliveries/{id}/value` returns the ordinary value as `application/octet-stream` (the only route with a value,
  `KBOX-2`); `POST /api/deliveries/{id}/ack` marks it delivered and the delivery row keeps no value. A delivery stays available until acked (retry-safe). An unacknowledged delivery older than the key's grace period
  raises one `box.notice` (decided here: no deadline stalls the run, it waits). A delivery exists only for an **ordinary** key; the route refuses any other class with 403.
Test (`test/key-routes.test.ts`): each route's response shape pinned; the three outcomes of `POST /api/keys`; `/api/retired` with a canary value: stored, covered only if it passes the shape check, absent from every response
and surface, never lent (`lend` refuses a retired generation); a delivery value route is refused for an admin key and after the ack; an ack for an unknown id is `not_found`; the retried delivery returns identical bytes.

### Unit `share`: the fingerprint file for the workstation guard

**`KBOX-18` Key formats and watch coverage.** Source: design §5.6. The box computes each key's tier from the real stored value and the adapter's `shape` (prefix, alphabet, core length range, `random`), records it in
metadata and shows it. **Windowed:** a random core of at least 32 characters over an alphabet of at least 16 symbols (so every 24-character window in every shared form holds at least 72 bits); probes keep the
stride of devbox admin-secrets-spec §3. **Anchored:** a random core of at least 72 bits (measured core length times log2 of the alphabet size) with a fixed public prefix of at least 4 characters; the matcher finds the prefix's
encoded form then compares an HMAC over the characters that follow which depend on core bytes alone (full-core digests, no windows; it misses copies with the prefix cut off). **Not watched:** everything else, and the approval
page says so. Eligibility comes from the adapter's strict shape check or box generation only, never from a pasted value's length. A UNVERIFIED length can at worst move a key between tiers. Test (`test/coverage.test.ts`):
boundaries 31/32 characters, alphabets of 15/16 symbols, 71/72 bits, prefix of 3/4 characters; a long human-chosen paste that fails the shape check is `none`; a 28-character `GOCSPX-` core is anchored; a JWT's
signature (43 characters, HS256) is windowed; the tier of every row of design §5.6's table with a synthetic value of the stated length; a seeded property test: tier is monotone in core length.

**`KBOX-33` The share file, format v3: what devbox's `admin-match` reads.** Source: design §6.5, devbox `admin-secrets-spec.md` §3 (v2); layout decided here. The file is one JSON envelope
`{"format":"kbox-share","v":3,"body_b64":"…","sig_b64":"…"}` where `sig_b64` is an Ed25519 signature over the **exact bytes** of `body_b64` decoded, so a reader verifies the signature before parsing and needs no canonicalisation.
The body is JSON `{header, entries, probes, coverage}`:
- `header = {v:3, version, issued_at, salt_b64, set_id, stride}`: `version` is a strictly increasing integer (never reused, never lower, kept across restarts); `salt_b64` is 32 random bytes, new for every version; `set_id` is
  SHA-256 hex of the sorted (project, name, gen, retired) list; `stride` is as v2 (minimum form length minus 23, 9 at the floor). There is no `baseline` member (the box has no repositories; devbox's matcher treats absence as empty).
- `entries`: windowed `{project, name, gen, retired, tier:"windowed", form, len, digest}` with `digest = HMAC-SHA256(salt, form)` as hex; anchored `{project, name, gen, retired, tier:"anchored", form, anchor, len, digest}` where
  `anchor` is the form's leading characters fixed by prefix bytes alone (the adapter's public prefix in that form) and `digest = HMAC-SHA256(salt, the following len characters fixed by core bytes alone)`, no windows. Forms come from
  `shareForms` (`KBOX-54`): raw and the six base64 interiors; hex, percent and `\u` forms are never shared.
- `probes`: for windowed entries, one probe per window start `j`: the 4-byte keyed BLAKE2b(salt, form[j:j+24]) as hex, with `{entry, j}`; a window lies wholly inside a random core (no window touches a prefix, a JWT header or payload).
  A hit is verified by the entry's HMAC over the `len` characters ending at the window, as in v2.
- `coverage`: one item for every admin and master key `{project, name, gen, tier: windowed|anchored|none}`, so "not watched" is explicit.
Contents: current and retired generations of every admin and master key (ordinary keys are not in the file); the old Supabase database password and other keys that fail the shape check are `none`. The signing key is Ed25519, kept in the
vault as a master value, and its public half is in `GET /api/meta` (`box.share_public_key_ed25519_b64`) and in the control enrol answer. `GET /api/share` (scope `control`) returns the current envelope with the header
`KB-Share-Version: <version>`. A new version is written whenever a generation, a retirement or a coverage tier changes and is announced by one `share.version` event after the file is durable. Test (`test/share-file.test.ts`,
`test/fixtures/share-v3/`): the box-written file over a synthetic store of fake values is read by a **reference matcher written in the test kit from devbox admin-secrets-spec §4's CI backend** and finds every planted raw and
base64 copy (all six alignments, wrapped at 64 and 76 columns) and nothing else; a prefix-cut anchored copy is not found (documents the limit); a 28-character `GOCSPX-` core gets an anchored entry and no windows; no window
covers a prefix or JWT header; `version` strictly increases across restarts and after a crash between write and announce (the file is never announced before it is durable, never rewritten with a lower version); the signature
fails on one flipped body byte; no core byte of any canary is in the file beyond the declared public prefix and `anchor` equals the adapter's public prefix; HMAC, BLAKE2b and Ed25519 known-answer vectors pass. The corpus
(`store.json` of synthetic values, `share.json`, `planted/*`) is the cross-repo golden that devbox unit 9 runs against its `admin-match` v3 backend; this closes the ordering gap noted in "Contradictions".

### Unit `google`: the box's own identity toward Google Cloud

**`KBOX-41` OIDC issuer, workload identity exchange, scoped impersonation and the API-key issuer.** Source: design §5.4 (Google Cloud / Firebase). Master = the **box's own OIDC identity** (no downloadable service-account key
exists). The box serves `https://keys.<domain>/.well-known/openid-configuration` and a JWKS, and signs short JWTs (ES256, a vault key of master class) with fixed claims. A Workload Identity Federation pool and provider in the owner's project
trusts that issuer and its principal has Token Creator on the service accounts the box may impersonate; the target list is stored per key and an impersonation target outside it is refused. Admin use (inside core only): STS exchange
(UNVERIFIED: `POST https://sts.googleapis.com/v1/token` and its parameters) then `POST https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{sa}:generateAccessToken` (host and method path VERIFIED), requested
with only the OAuth scopes the key's profile names (for example `datastore`, `devstorage.read_write`), never `cloud-platform` (a request carrying it for the relay is refused); the `scope` request field is UNVERIFIED. The token is held in
the scanner's match set while it lives (`KBOX-14`). Ordinary API keys and Firebase web keys: `https://apikeys.googleapis.com` `POST /v2/{parent=projects/*/locations/*}/keys`, `GET .../keyString`, `DELETE`, `GET .../keys` (list),
`PATCH` (restrictions; field names UNVERIFIED), all VERIFIED as paths in revision 1. Destinations: Secret Manager `addVersion` (UNVERIFIED) is `readableBy: 'api'`, ordinary keys only. Rotation of the signing key: publish the new key in the
JWKS, wait out Google's cache (duration UNVERIFIED), switch, drop the old; master class, so it needs an approval. The `google` relay profile (host as the first path segment; allow and `mustDeny` lists exactly as design §5.5) is supplied
here. Test (`test/google.test.ts`, `fakePlatform()` for Google hosts): the discovery document and JWKS shape; an ES256 JWT and the JWKS verify with an independent verifier in the test; token claims fixed (a request to change
audience or subject is refused); a token request with `cloud-platform` for relay refused; a target outside the list refused; the profile deny test (every §5.5 Google sample gives 403, no upstream call; samples confirmed against the API
discovery documents by the probe, `KBOX-42`); the issuer passes the `issuer` and `lister` contract suites; a created key's response with a canary value is absent from errors and logs; the injected token is withheld if echoed by an
upstream.

**`KBOX-24` The service-account grant check.** Source: design §5.4. When a Google grant is proposed, and again daily, core impersonates the target service account and calls `testIamPermissions` on its project (path UNVERIFIED,
probed by the unit). The permissions tested are `iam.serviceAccountKeys.create`, `iam.serviceAccounts.getAccessToken`, `iam.serviceAccounts.signBlob`, `iam.serviceAccounts.signJwt`, `iam.serviceAccounts.actAs`,
`iam.serviceAccounts.implicitDelegation`, `resourcemanager.projects.setIamPolicy`, `storage.hmacKeys.create` and `secretmanager.versions.access`. If the service account holds any of them, the grant is refused at proposal time, or
suspended with one notice when found by the daily check. Test: a fake IAM host returning each of the nine permissions one at a time refuses the grant naming the permission; none passes; the daily check suspends an existing grant
and raises exactly one notice; an unreachable `testIamPermissions` fails closed (grant refused or suspended, never allowed).

### Unit `vercel`

**`KBOX-36` The Vercel adapter: classic master token, per-project ordinary tokens, sensitive env.** Source: design §5.4 (Vercel), Q5/C-685, S-716. Master = a classic, team-scoped access token, pasted once and self-rotating
(`selfRotate: true`); it stays on the box. Tokens: `POST https://api.vercel.com/v3/user/tokens` with `teamId` or `slug`, body `name` (required), `expiresAt` (ms), `projectId` (VERIFIED); the response's `bearerToken` appears only
there (`revealOnce: true`, so a `lister` is required: `GET /v6/user/tokens`; revoke `DELETE /v3/user/tokens/{tokenId}`). `classify` returns `ordinary` for a token made with `projectId` and `master` for any other. Project tokens are
ordinary keys with the use right; the box makes one per project, rotates it and delivers it like any ordinary key. UNVERIFIED: that the Vercel CLI works with a project-scoped token. Destination: `POST /v10/projects/{idOrName}/env`
(VERIFIED) with `type: "sensitive"` for admin values and `encrypted` for ordinary ones; sensitive values are write-only once created and allowed only for preview and production targets (VERIFIED); `encrypted` for an admin key is
refused (`KBOX-16`); upsert, update and delete of env vars and redeploy (`POST /v13/deployments` with `deploymentId`) are UNVERIFIED. Verifier: an authenticated `GET` of the token's own user (path UNVERIFIED). No relay profile in v1;
`relayDenyOnly` with the pinned `mustDeny` list of design §5.5 (`/v{n}/user/tokens{rest:**}` VERIFIED path; the rest UNVERIFIED). Key formats: `vcp_` prefix (VERIFIED), core length UNVERIFIED (anchored at 24 or more, windowed at 32 or
more, `KBOX-18`). First act: the live probe of `KBOX-42` including whether the Vercel CLI works with a project-scoped token. Test (`test/vercel.test.ts`, `fakePlatform()`): canary create response never in errors or logs; the
`classify` table; project-token rotation revokes the old id; an admin env push uses `sensitive` and `encrypted` for an admin key is refused; `shape` accepts real-format fixtures and refuses near misses; verifier statuses
(`ok`, `rejected`, `unreachable`); the adapter exports `mustDeny` and no `relay`; the `issuer`, `lister`, `verifier` and `destination` contract suites pass.

**`KBOX-26` Vercel project operations: a closed list of three.** Source: design §5.1. Agents ask, through mission control and the control token, for exactly three named operations: `createProject`; `setDomain` (add, remove or
move a domain on a named project); and `setTeamSetting` (one setting from a fixed list that excludes members, invites, tokens, integrations and billing). Each runs inside core in the Vercel adapter with the master token and
typed parameters (project-name shape, domain-name shape, setting key from the list). No other operation exists, the master token is lent to nothing else for this, and the names are code (adding one is an update). Results carry no value.
`createProject` needs no approval; `setDomain` and `setTeamSetting` are phone approvals, one action each, because a domain change can send a name to another project (decided in the design, easily reversed). The routes are
`POST /api/vercel/projects`, `POST /api/vercel/domains` and `POST /api/vercel/settings` (scope `control`; the last two create proposals of the kinds in `KBOX-53`; decided here). Test: each operation accepts only its typed
parameters; a setting outside the list (members, invites, tokens, integrations, billing) is `rejected`; no other operation name exists (the registry exports exactly three); `setDomain` and `setTeamSetting` open an approval and
`createProject` does not; the result schemas have no value member.

### Unit `supabase`

**`KBOX-37` The Supabase adapter.** Source: design §5.4 (Supabase), §5.5. Master = a personal access token, pasted (whether a PAT can be created by API is UNVERIFIED; assumed dashboard-only). Issuer (VERIFIED from the Management API file):
`POST /v1/projects/{ref}/api-keys` (query `reveal`; body `type` of `publishable` or `secret`, `name` matching `^[a-z_][a-z0-9_]+$` 4 to 64 characters, `description`, `secret_jwt_template`), `GET /v1/projects/{ref}/api-keys[/{id}]`,
`PATCH` (name, description, template only), `DELETE` (query `reveal`, `was_compromised`, `reason`); the object has `api_key` (nullable), `id`, `type` (`legacy|publishable|secret`), `prefix`, `hash`, `name`. **What `reveal` returns is
UNVERIFIED**; until the probe settles it the adapter treats every create as `revealOnce` (create with `reveal=true`, never rely on a later `GET`) and exports a `lister`. Classes: `secret` is admin, `publishable` ordinary. Database
password (`PATCH /v1/projects/{ref}/database/password`, body `{password}`, VERIFIED): the box generates 32 random bytes as base64url (43 characters), `overlap: false`; the rotation is deferred with the CI destination (design §13)
and the adapter implements only the call and its test. Destination: edge-function secrets `POST|GET|DELETE /v1/projects/{ref}/secrets` (VERIFIED); the `GET` schema has a required `value`, so `readableBy: 'api'` (ordinary only,
`KBOX-16`) until a probe shows it holds only a digest. Relay profile `supabase` (origin `https://<ref>.supabase.co` exact per key; allow: PostgREST on named tables with methods named per key, `POST /rest/v1/rpc/<fn>` on named
functions, Storage objects in named buckets and `POST /storage/v1/object/list/<bucket>`; `mustDeny`: `/auth/v1/{rest:**}`, `/pg/{rest:**}`, `/graphql/v1`, `/functions/v1/{rest:**}`,
`/storage/v1/object/sign/{rest:**}`, `/storage/v1/object/upload/sign/{rest:**}`, `/storage/v1/bucket{rest:**}`, `/realtime/v1/{rest:**}`, `/rest/v1/` root, and any `Accept-Profile` or `Content-Profile` other than `public`; paths
UNVERIFIED). Formats: `sb_secret_` prefix (VERIFIED), length UNVERIFIED, tier by measured length. Test (`test/supabase.test.ts`): canary create response never in errors or logs; `classify`; `shape` fixtures; the profile deny test (every
sample 403, no upstream call, also with the widened test profile); the three contract suites; a `reveal` response with `api_key: null` is a fixed error, not a stored empty value; name pattern enforced on `intentName`.

### Unit `openai`

**`KBOX-38` The OpenAI adapter.** Source: design §5.4 (OpenAI), §5.5. Master = an organization admin key, self-rotating (`POST|GET /v1/organization/admin_api_keys`, `GET|DELETE .../{key_id}`, VERIFIED). Issuer for ordinary project keys
(VERIFIED): `POST /v1/organization/projects/{project_id}/service_accounts` (response has `api_key`), and **`POST .../service_accounts/{service_account_id}/api_keys`** with body `name`, `expires_in_seconds`, `scopes` (response `value`); revoke
`DELETE /v1/organization/projects/{project_id}/api_keys/{api_key_id}`; list `GET .../projects/{project_id}/api_keys`. Rotation keeps the service account and changes only its key; the box sets a platform expiry. Classes: project service-account
keys ordinary (admin if the owner marks them); admin keys master. Relay profile `openai` (only for a key the owner marks admin): allow `POST /v1/responses`, `POST /v1/chat/completions`, `POST /v1/embeddings`, `GET /v1/models`,
`POST /v1/audio/{speech|transcriptions|translations}`; `mustDeny` (VERIFIED): `/v1/organization/{rest:**}`, `POST /v1/realtime/client_secrets`, `POST /v1/realtime/translations/client_secrets`,
`POST /v1/realtime/transcription_sessions`, `POST /v1/realtime/sessions`, `POST /v1/chatkit/sessions`, `POST /v1/chatkit/sessions/{id}/cancel`, `/v1/webhook_endpoints{rest:**}`. Formats: `sk-admin-` and `sk-svcacct-` prefixes, long cores,
lengths UNVERIFIED, windowed when admin. First act: the live probe, which also re-checks the create-key path (design §3 revision, A8). Test (`test/openai.test.ts`): canary create response never in errors or logs; `classify`; `shape`; the
profile deny test; the three contract suites; an upstream 401 quoting a masked key is replaced (`KBOX-14`) end to end through the relay; the OpenAI SDK request shape replay reaches an allow rule.

### Unit `elevenlabs`

**`KBOX-39` The ElevenLabs adapter.** Source: design §5.4 (ElevenLabs), §5.5. Master = a workspace admin's key with service-account rights, pasted. Issuer (VERIFIED from the official OpenAPI file):
`POST /v1/service-accounts/{service_account_user_id}/api-keys` (body `name` and `permissions`, both required, a list of permission types or `"all"`; optional `allowed_ips`, `expires_at_unix`, `character_limit`, concurrency limits,
`third_party_disable_allowed`; response `key_id` and **`xi-api-key`**), list, `PATCH`, `DELETE .../api-keys/{api_key_id}` and `POST .../{api_key_id}/disable`. `classify`: `"all"` or any workspace, service-account or key-management permission is
`master`, otherwise `ordinary`; the permission-type names are read from the OpenAPI enum by the unit and stored in `src/platforms/elevenlabs/permissions.json`. The adapter takes the region per key (`https://api.elevenlabs.io` or
`https://api.us.elevenlabs.io`, VERIFIED). No relay profile in v1; `relayDenyOnly` with the pinned `mustDeny` list of design §5.5 (`/v1/service-accounts{rest:**}`, `/v1/workspaces/api-keys/{rest:**}`, `/v1/workspace/{rest:**}`,
`POST /v1/single-use-token/{token_type}`, `GET /v1/convai/conversation/get-signed-url`, `.../get_signed_url`, `.../token`, `POST /v1/convai/realtime/client_secrets`, `/v1/convai/secrets{rest:**}`). Formats: `sk_` prefix, commonly 48 hex,
UNVERIFIED, windowed if admin or master. Test (`test/elevenlabs.test.ts`): canary create response never in errors or logs; `classify` table over the enum; the region switch; a `mustDeny` list exported and no `relay`; the `issuer`,
`lister` and `verifier` contract suites; `shape` fixtures.

### Unit `paste`: Anthropic and Stripe

**`KBOX-40` Paste-only platforms: Anthropic and Stripe.** Source: design §5.4 (Anthropic, Stripe), §5.3. These platforms cannot create keys by API (owner statement), so each exports only `verifier`, `pasteGuide` and `shape` (and, for
Anthropic, a `lister`). Anthropic: paste, then verify with an authenticated `GET /v1/models` (UNVERIFIED as the cheapest check); the admin key (`sk-ant-admin01-`, master) is pasted too and is used to list keys (`GET /v1/organizations/api_keys`,
with a status filter, VERIFIED in revision 1) and to retire the old key after a paste rotation (`POST /v1/organizations/api_keys/{api_key_id}` with `status` of `inactive` or `archived`; path VERIFIED in revision 1, statuses from SDK docs).
Claude login tokens (`sk-ant-o…`) are out of scope (S-349 class). Stripe: restricted keys are dashboard-only (owner statement, not verified); paste, and verify with a call the key's restriction allows; the paste page asks which one from an
adapter list (`rk_live_` prefix, long core, UNVERIFIED). Neither has a relay profile or a deny list in v1: an owner-marked admin key on these platforms cannot be used by agents (S-713) until a later unit builds the profile. Ordinary keys on
platforms without an issuer are not the box's business (design §5.3: mission control's desk card, metadata only in mission control). Test (`test/paste-platforms.test.ts`): `shape` fixtures and near misses for each prefix; the verifier
statuses over `fakePlatform()` (200, 401, 403, timeout); the retire-after-paste-rotation call sequence for Anthropic with the old key rejected by the verifier before it is marked `retired` (`KBOX-51` step 10); the registry check that
neither exports `relay`; the paste flow end to end through the real `/p/<id>` route with `softAuthenticator()` for each platform; the `verifier` contract suite.

## Fixed words on the box's pages

Pinned in `src/pure/words.ts` and tested (`KBOX-8`): the update sentence of `KBOX-6`; "Only paste where you see your phrase." (`KBOX-12`); "Reason given by <machine>/<agent> (not checked)" (`KBOX-8`); "code deployed to <app> can read this key"
(`KBOX-16`); "enrol <label> for relay (request seen from <address>; the label and the address are not checked)" (`KBOX-11`); "open connections drop briefly" (`KBOX-17`); "response withheld: it carried a key" and "upstream refused the key" (`KBOX-14`); "These limits do
not stop an approved update that is malicious." (`KBOX-46`); the two recovery cases (`KBOX-20`).

## Journeys (one smoke test per journey, test-doctrine section 5)

`test/journeys/` starts the real core and relay as separate processes on unix sockets in a temp directory, with `fakePlatform()` upstreams, a `FakeClock` where the process takes one, and `softAuthenticator()`: J1 setup then approve a rotation of an
admin key; J2 a relayed call with a granted pass, a refused call and a withheld response; J3 a full rotation of an ordinary key with a delivery and its ack; J4 an update bundle approved and installed, then a bad bundle rolled back; J5 recovery after a
reboot; J6 a share file written, announced and read by the reference matcher. Each is run by `node --test test/journeys/<name>.test.ts`. Not testable here and reported as UNVERIFIED by their units: the real Oracle instance, the real Caddy, the
real console capture and every live platform call.

## Limits, stated and not rules

The residual risks of design §9 hold unchanged and are not rules: R1 agent-written, agent-reviewed code (an approved update with a backdoor reads every value; Q7/S-714 accept it); R2 runtime destinations; R3 relay use and a leaked pass; R4 approval by
persuasion; R5 the web address; R6 narrower workstation scan; R7 synced passkeys; R8 single box, no value backups; R10 responses; R12 Oracle reclaim; R13 paste look-alike; R14 control token; R15 the free name can disappear; R16 Vercel project tokens.
R11 (database password rotation) waits for the deferred CI destination, which is not in this repo (design §13). Cut or deferred, with cost: design §13.

## Build units

| Unit | Rules | Needs | Probes |
|---|---|---|---|
| scaffold | KBOX-27, KBOX-28, KBOX-35, KBOX-42 | — | — |
| forms | KBOX-54 | scaffold | — |
| kernel-store | KBOX-2, KBOX-4, KBOX-5, KBOX-10, KBOX-19, KBOX-29, KBOX-30, KBOX-31, KBOX-43, KBOX-45, KBOX-50 | scaffold | — |
| kernel-approve | KBOX-7, KBOX-8, KBOX-9, KBOX-11, KBOX-20, KBOX-22, KBOX-49, KBOX-53 | kernel-store | — |
| update | KBOX-1, KBOX-6, KBOX-21, KBOX-44, KBOX-46, KBOX-48 | kernel-approve | — |
| relay | KBOX-3, KBOX-13, KBOX-14, KBOX-23, KBOX-25, KBOX-32, KBOX-47 | kernel-approve, forms | — |
| rotate | KBOX-12, KBOX-15, KBOX-16, KBOX-17, KBOX-34, KBOX-51, KBOX-52 | kernel-approve | — |
| share | KBOX-18, KBOX-33 | kernel-store, forms | — |
| google | KBOX-24, KBOX-41 | relay, rotate | — |
| vercel | KBOX-26, KBOX-36 | relay, rotate | — |
| supabase | KBOX-37 | relay, rotate | — |
| openai | KBOX-38 | relay, rotate | — |
| elevenlabs | KBOX-39 | relay, rotate | — |
| paste | KBOX-40 | rotate | — |

- Every `KBOX` id (1 to 54) is in exactly one row; the Needs graph is acyclic. No probes: the live platform probes of `KBOX-42` are the adapter units' first act, reported before code, not gate probes.
- Order: `scaffold`, then `forms` and `kernel-store` (parallel), then `kernel-approve`, then `update`, `relay`, `rotate` and `share` (parallel; `share` needs only `kernel-store` and `forms`), then the six adapter units (parallel).
  The owner's phone setup (design §10 sequence step 1) can happen after `update`. Devbox unit 9 needs `share`'s golden corpus on main; mission control's units need this spec and `kernel-store`'s routes.
- This spec lands on main first, then goes to a fresh `worker-adversary`, before any unit starts. Every implementation brief carries the line "If a pre-existing test conflicts with your task, leave it red and state the conflict — do not modify the test." and names the narrowest test command. Every unit starts by writing its failing tests. Full suite (`node --test`) once at a unit's end, submitted through `runq run --why "<reason>" -- node --test`.
- Splits from the design's unit list (decided here): design unit 2 (kernel) becomes `kernel-store` and `kernel-approve` so the Opus seat sees only the approval binding; design unit 8 becomes five units (Vercel, Supabase, OpenAI, ElevenLabs, paste), as the design says "one unit per row when built"; `scaffold` and `forms` are added so toolchain, test kit and the shared forms algorithm have one home (code-doctrine: one home for any hash, encoding or parser).

**Per unit:**

- **`scaffold`**: `worker-routine`, effort medium. Risk: a check that is green because it is loose. Touches new `package.json`, `tsconfig.json`, `.nvmrc`, `.gitignore`, `runtime.lock` (placeholder format only), `src/ports/*.ts` (types of design §5.1), `test/arch.test.ts`, `test/kit/*`, `test/contracts/*.contract.ts` (suites with the fake runs), `test/kit/kit.test.ts`. Failing tests first: the `KBOX-27` and `KBOX-28` fixtures that must fail, the probe-file check, `assertAbsent` finding planted copies. Narrowest: `node --test test/arch.test.ts test/kit/kit.test.ts`.
- **`forms`**: `worker-routine`, effort high. Risk: a form or alignment missing, so a copy of a key passes the scanner or the share file. Touches new `src/pure/forms.ts`, `test/forms.test.ts`, `test/fixtures/forms/*`. Failing tests first: the per-form tables and the substring property. Narrowest: `node --test test/forms.test.ts`.
- **`kernel-store`**: `worker-routine`, effort high. Risk: a value, a length or a digest reaches the database, a log, an error or an event. Touches new `src/pure/{canonical,errors}.ts`, `src/shell/{vault-fs,db,audit,http,clock,random,events}.ts`, `src/main-core.ts` (frame only), `src/pure/schemas.ts`, `deploy/{keybox.service,keyrelay.service}`, `test/{api-frame,control-read,events,deploy-units,canary}.test.ts`, `test/journeys/process-split.test.ts`. Failing tests first: `KBOX-4` placeholder tests, `KBOX-5` column-name test, `KBOX-29` error table, `KBOX-31` long poll. Narrowest: `node --test test/api-frame.test.ts` (then the file of the rule being built).
- **`kernel-approve`**: `worker-complex`. Opus because: a flaw in assertion, device-key, slot or recovery binding lets a workstation-rooted agent approve its own action. Touches new `src/pure/{webauthn,cose,challenge,slots,words,pushcrypto}.ts`, `src/shell/{approvals,approvers,push,console,tokens}.ts`, `src/web/*` (app shell, `sw.js`, manifest, setup, approve, recover pages: plain `.js`), `src/data/wordlist.txt`, `test/{setup,slots,approval-binding,machine-tokens,recovery,web-push,proposal-routes}.test.ts`. Failing tests first: the `KBOX-9` refusal table, the `KBOX-7` slot table, the `KBOX-20` recovery table. Narrowest: `node --test test/approval-binding.test.ts`.
- **`update`**: `worker-complex`. Opus because: one path that installs bytes other than the approved hash, or over another base, hands every key to agent-written code. Touches new `src/pure/{tar,release-hash}.ts`, `src/shell/{updater,idle-watch,systemd}.ts`, `deploy/{cloud-init.yaml,Caddyfile,runtime.config.json}`, `docs/setup-checklist.md`, `runtime.lock` (real format), `test/{update,idle-watch,bootstrap-text}.test.ts`. Failing tests first: the tar refusal table and the approval-base tests. Narrowest: `node --test test/update.test.ts`.
- **`relay`**: `worker-complex`. Opus because: one header, path-normalisation, redirect or error path sends an admin value or a newly minted credential to a caller. Touches new `src/main-relay.ts`, `src/pure/{target-parse,rule-match,profile,scanner}.ts`, `src/shell/{relay-http,lend-socket,egress}.ts`, `src/data/credential-shapes.json`, `src/platforms/registry.ts`, `test/{lend,relay-forward,relay-scan,profile-engine,registry,relay-contract,egress-gate}.test.ts`. Failing tests first: the canonicalisation and query tables, the deny harness with a leaky profile as positive control. Narrowest: `node --test test/relay-forward.test.ts`.
- **`rotate`**: `worker-routine`, effort high. Risk: a failure path revokes the old key while a destination still holds it (an outage). Touches new `src/pure/{rotation-machine,scheduler,class}.ts`, `src/shell/{orchestrator,paste,deliveries,reconcile}.ts`, `src/web/paste.js`, `test/{rotation,scheduler,paste,key-routes}.test.ts`. Failing tests first: the crash-at-each-step table and the wrong-region 404 case. Narrowest: `node --test test/rotation.test.ts`.
- **`share`**: `worker-routine`, effort high. Risk: a probe window or anchor digest touching a non-random byte makes the file a guess oracle (S-128). Touches new `src/pure/{coverage,share-build}.ts`, `src/shell/share-writer.ts`, `test/{coverage,share-file}.test.ts`, `test/fixtures/share-v3/*`, `test/kit/reference-matcher.ts`. Failing tests first: the reference-matcher corpus and the no-core-byte canary test. Narrowest: `node --test test/share-file.test.ts`.
- **`google`**: `worker-routine`, effort high. Risk: a token scope, audience or service account broad enough to mint keys or tokens. Touches new `src/platforms/google/*`, `docs/probes/google.md`, `test/google.test.ts`. Failing tests first: the profile deny test and the nine-permission grant check. Narrowest: `node --test test/google.test.ts`. First act: the live probe, reported before code.
- **`vercel`**, **`supabase`**, **`openai`**, **`elevenlabs`**: each `worker-routine`, effort medium. Risk: an adapter logs or throws with a create response that holds the new key. Touches new `src/platforms/<id>/*`, `docs/probes/<id>.md`, `test/<id>.test.ts`. Failing tests first: the canary create-response test and the `classify` table (Vercel also the three-operation closed list; Supabase and OpenAI also the profile deny test). Narrowest: `node --test test/<id>.test.ts`. **First act of each: a live probe of every UNVERIFIED item named in its rule on a throwaway project, reported before code (`KBOX-42`); for Vercel including whether the Vercel CLI works with a project-scoped token; for Supabase the `reveal` result and `GET /secrets` values.**
- **`paste`**: `worker-routine`, effort medium. Risk: a paste route that stores or echoes a value that failed its checks. Touches new `src/platforms/{anthropic,stripe}/*`, `docs/probes/{anthropic,stripe}.md`, `test/paste-platforms.test.ts`. Failing tests first: the shape near-miss tables. Narrowest: `node --test test/paste-platforms.test.ts`. First act: the live probe of the Anthropic verification call and the retire path, reported before code.

## Decided while writing

1. **Toolchain** (Node 24 LTS, type stripping, `tsc --noEmit` dev-only as the single dev dependency, `node:test`, strict flags): the choices the brief asked for; the table above.
2. **Two extra units** (`scaffold`, `forms`) and two splits (kernel into store and approve; unit 8 into five) so each seat sees one concern.
3. **Rule ids 27 to 54** are written for this spec; each cites the design section it makes buildable. Ids 1 to 26 are the design's.
4. **No `SO_PEERCRED`**: Node has no peer-credential API, so socket mode and directory ownership are the access check (`KBOX-3`, `KBOX-45`).
5. **Wire frame** (`KBOX-29`): error shape, code list, 64 KiB JSON body bound, `*_at` integer milliseconds, request ids, `KB-Api-Version`.
6. **Event and meta shapes** (`KBOX-30`, `KBOX-31`): the closed event-kind table, integer cursor, 25 s hold, an empty batch at timeout, events never deleted.
7. **Action kinds and enrol routes** (`KBOX-53`): the closed list of fifteen kinds; unauthenticated `POST /api/enrol` and its status poll; `control` enrol needs the window, `relay` enrol only proposes.
8. **Approver-add registration**: a one-time 10-minute code shown on the approving app and typed at the registration step (the design lists the approval, not how the new device joins).
9. **Paste is the approval** for a paste-source add or rotate (one action per approval holds).
10. **Challenge construction details**: JCS restricted to integers; view challenge `SHA-256("kbox-v1-view" ‖ nonce)`; paste challenge `SHA-256("kbox-v1-paste" ‖ pasteId ‖ nonce)`; the device-key signature is raw r‖s over the 32 challenge bytes.
11. **Words for codes**: 12 words from the BIP-39 English list (132 bits) for the setup, recovery and registration codes; only the hash is kept.
12. **Release hash text format** and mode normalisation (`0755`/`0644`); one pax global header first is accepted for `git archive`; health check is `GET /healthz` showing H within 60 s.
13. **Idle watch** reads `/proc` (no Oracle API call), keeps memory at 30% of `MemTotal` (design: above 25%), warns within 5 points.
14. **Relay**: pass headers per profile (several declared headers must agree), `GET /r/_/grants`, the `envForClients` maps (Google's is `KBOX_GOOGLE_RELAY_URL`), upstream connect timeout 10 s and no total timeout, failure codes `bad_token`, `bad_path`, `bad_query`, `method_override`, `upstream_unreachable`, `upstream_timeout`, `withheld`.
15. **Share file layout**: a signed envelope over the raw body bytes (no canonicalisation), no `baseline` member, `GET /api/share`, the `share.version` event only after the file is durable.
16. **Retired hand-off** (`POST /api/retired`) needs no phone approval (a retired value is never lent); a value failing the shape check is stored `none`.
17. **Deliveries**: list, `/value` octet-stream, ack; an unacked delivery older than the key's grace raises one notice and never stalls the run; ordinary class only.
18. **Rotation failure retry**: first retry at 1 minute, doubling to 1 hour (S-249 gives no numbers).
19. **Vercel operation routes** (`KBOX-26`): `POST /api/vercel/{projects,domains,settings}`.
20. **Forms oracle**: devbox's `admin-match` forms through its test seam if usable, else hand vectors plus the substring property; the builder reports which.
21. **The phone app** is plain `.js` with JSDoc under `checkJs` (no build step), so the approved bytes are the served bytes.
22. **Share reference matcher** in the test kit plus a golden corpus replaces unit 6's test against a devbox backend that does not exist yet.

## Open points

1. **Owner (intent), S-711 wording.** Card C-692 amends S-711 to "an authenticator app synced only to a Google account never signed in on the owner's machines"; until it lands the filed statement says "does not sync". This spec and `KBOX-48` follow the amended wording. Nothing to decide except to let C-692 land.
2. **Floor for pasted values.** Design `KBOX-12` says a 16-byte core floor; mission control's KREQ-14 notes that its docstring and message disagree (16 against 32). `KBOX-12` uses 16 plus the adapter's strict shape check. If the owner wants 32, it is one constant (decide with devbox's amendment; not an owner intent question).
3. **To read at build time and report:** `node:sqlite` in the pinned Node 24 patch (`KBOX-5`); that Node's `stripTypeScriptTypes` is available for the arch check; a published WebAuthn assertion test vector (`KBOX-9`); every UNVERIFIED item named in `KBOX-36` to `KBOX-41` and `KBOX-24` (each by its adapter unit's probe); the Oracle monitoring figures and console capture (`KBOX-21`, `KBOX-20`); the exact Run Command plugin disable command (`KBOX-1`); whether deSEC offers an authenticator app, TLS-ALPN-01 for a `dedyn.io` name and DNSSEC (`KBOX-48`); Google's JWKS cache time (`KBOX-41`); real key lengths (`KBOX-18`).
4. **Devbox side, for its own spec:** unit 9's v3 backend reads `KBOX-33`'s envelope and runs the golden corpus; it must define what an absent `baseline` means (this spec says empty). Unit 10's `keybox-enrol`, `with-keys` and `hand-off` call `KBOX-53`, `KBOX-32` and `KBOX-34` as written.
5. **Mission-control side, for its own spec:** the control client calls `KBOX-29` to `KBOX-31`, `KBOX-34`, `KBOX-53` and `KBOX-26`'s three routes; how old mission-control code treats new event kinds is its own rollback note.
