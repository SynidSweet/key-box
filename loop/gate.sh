#!/usr/bin/env bash
# derived-from: gate-template v2
# key-box gate: type check, the full node --test suite, the architecture probe (positive and negative
# controls), the test-weakening classifier against LOOP_BASE_COMMIT. Run it with the compound-loop
# driver as `-G loop/gate.sh`, or by hand: LOOP_WORKDIR=<tree> LOOP_BASE_COMMIT=<sha> loop/gate.sh
# A project copy keeps this line instead of the one above:
#   # derived-from: gate-template v2
# so drifted copies can be found (`grep -rL 'derived-from: gate-template v2'`).
#
# Keep the copy IN THE REPO and run it with `loop-driver.sh -G <path>`: the
# driver runs the copy committed at the slice's base, so a session cannot edit
# the gate that judges it. A gate kept in a scratchpad is lost with it.
#
# INVOCATION CONTRACT — everything comes from env (the compound-loop driver
# sets it for -g and -G alike):
#   LOOP_WORKDIR           work tree to judge (manual use: first positional arg)
#   LOOP_BASE_COMMIT       the slice's base (manual use: BASE_COMMIT)
#   LOOP_RUN_DIR           driver run dir: logs, flakes.tsv (optional)
#   LOOP_SLICE_N           slice number (0 = preflight / baseline)
#   LOOP_SKILL_DIR         deterministic-gates skill dir: the classifier is
#                          $LOOP_SKILL_DIR/scripts/test_mod_classifier.py — NEVER
#                          derived from this file's location (a base-commit copy
#                          has no ../scripts)
#   LOOP_AUTHORISED_FLIPS  orchestrator-authorised test paths (space-separated)
#   gate.sh --preflight    run once before slice 1 (loop-driver does this for -G)
#
# EXIT, by precedence: any GATE-ERROR -> 3; else any FAIL -> 1; else a valid
# escalation -> 2; else 0.
#   GATE-ERROR = the instrument could not reach a verdict (config missing,
#   classifier missing or unreadable, base unresolvable, probe lock timeout, a
#   probe flaking in two slices). The driver stops on 3 without a retry.
#
# CHECK ORDER: the cheap checks (base, escalation, pins, classifier, lockfile,
# secrets, suite, typecheck, test growth) ALL run, always. The expensive probes
# are skipped once a cheap check FAILed or errored, and the summary lists them
# as "SKIPPED (earlier FAIL)" — never as missing. The gate ends with a
# one-line-per-check summary and a final "GATE: <verdict>" line.
#
# FAIL-CLOSED: a check that cannot run is a GATE-ERROR or a FAIL, never a skip.
set -u

MODE=gate; ARG_WT=""
for a in "$@"; do case $a in --preflight) MODE=preflight;; *) ARG_WT=$a;; esac; done

# --- adapt these per project (env overrides win) ------------------------------
# The host suite is every test file except the root-only files, which the gate runs as root in a container (see process-split below):
# the KBOX-45 uid journey and kb-install's uid half (KBOX-6). SPLIT_FILE is a space-separated list.
SPLIT_FILE=${SPLIT_FILE:-test/journeys/process-split.test.ts test/install-root.test.ts}
# Every file type `node --test` runs (.ts .mts .js .mjs .cjs), so a test in another type cannot go unrun; only the SPLIT_FILE files are left out.
SPLIT_EXCLUDES=""; for f in $SPLIT_FILE; do SPLIT_EXCLUDES="$SPLIT_EXCLUDES ! -path $f"; done
HOST_SUITE='node --test $(find test -type f \( -name "*.ts" -o -name "*.mts" -o -name "*.js" -o -name "*.mjs" -o -name "*.cjs" \)'"$SPLIT_EXCLUDES"' | sort)'
SUITE_CMD=${SUITE_CMD:-$HOST_SUITE}        # exit 0 = suite green
SUITE_FAILING_IDS_CMD=${SUITE_FAILING_IDS_CMD:-}
                                         # prints failing test IDs, one per line,
                                         # as <repo-relative file>::<test name>
                                         # (e.g. from vitest's JSON reporter or
                                         # pytest --junitxml). Unset: a red suite
                                         # is always FAIL.
TYPECHECK_CMD=${TYPECHECK_CMD:-node node_modules/typescript/bin/tsc --noEmit}         # optional; exit 0 = green
PIN_PATHS=${PIN_PATHS:-}                 # byte-protected paths (contracts, governance tests)
GATE_PINNED_PATHS=${GATE_PINNED_PATHS-loop/probes/arch.sh tsconfig.json} # files THIS gate depends on (suite config,
                                         # probe helpers): byte-checked like pins
LOCKFILES=${LOCKFILES-package-lock.json}                 # e.g. "pnpm-lock.yaml"; a change FAILs...
DEPS_ALLOWED=${DEPS_ALLOWED:-0}          # ...unless this slice may add dependencies
SECRET_RE=${SECRET_RE:-'(sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{32,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJhbGciOi[A-Za-z0-9_-]{20,}\.)'}
EXTRA_TEST_GLOBS=${EXTRA_TEST_GLOBS-test/contracts/*.contract.ts test/arch/*.ts}   # files that act as tests but match no naming
                                         # convention, e.g. 'probe/*.py' (classifier
                                         # --extra-test-glob)
ACCEPT_DECLARED_FLIPS=${ACCEPT_DECLARED_FLIPS:-0}
                                         # 0: a PRINTED-FOR-REVIEW change passes only if
                                         #    declared in .loop-forced-flips AND its path
                                         #    is in LOOP_AUTHORISED_FLIPS
                                         # 1: declared alone is enough (orchestrator reviews
                                         #    every declared flip before the next slice)
TESTS_MUST_GROW=${TESTS_MUST_GROW:-1}    # 0 for refactor / bug-fix slices. A WEAK signal:
                                         # a dummy test passes it.
TEST_COUNT_RE=${TEST_COUNT_RE:-'^\s*((it|test)(\.each\([^)]*\)[^(]*)?\(|(async\s+)?def\s+test_)'}
TEST_COUNT_GLOBS=${TEST_COUNT_GLOBS:-'*.test.ts *.test.tsx *.test.js *.test.mjs *.spec.ts *.spec.js *test_*.py *_test.py'}
PROBES=${PROBES-arch}                       # required probe names, e.g. "api ui"
ALLOW_NO_PROBE=${ALLOW_NO_PROBE:-0}      # 1 only for work with no runtime surface
PROBE_FILE_PATTERN=${PROBE_FILE_PATTERN:-loop/probes/%s.sh}
                                         # where probe <name> lives (preflight runs the
                                         # probes that already exist at base)
PROBE_RUNNER=${PROBE_RUNNER:-}           # command prefix, called as `<runner> <name>`;
                                         # default: bash <PROBE_FILE_PATTERN>
PROBE_LOCK=${PROBE_LOCK:-}               # optional lock file taken around all probes
PROBE_LOCK_WAIT=${PROBE_LOCK_WAIT:-600}  # seconds; a lock timeout is a GATE-ERROR
PROBE_FLAKY=${PROBE_FLAKY:-}             # probes re-run ONCE on failure (FLAKE)
# PROBE CONTROL CONTRACT: probe <name> must print "<name> POSITIVE PASS" (the
# known-good case passes) AND "<name> NEGATIVE PASS" (a known-bad case is
# rejected) and exit 0. Both lines are required for every required probe; a
# probe without its negative control proves nothing.
# ------------------------------------------------------------------------------

WT=${LOOP_WORKDIR:-$ARG_WT}
BASE=${LOOP_BASE_COMMIT:-${BASE_COMMIT:-}}
SLICE=${LOOP_SLICE_N:-0}
LOOP_SKILL_DIR=${LOOP_SKILL_DIR:-/home/petter/.claude/skills/deterministic-gates}
CLASSIFIER=""; [ -n "${LOOP_SKILL_DIR:-}" ] && CLASSIFIER="$LOOP_SKILL_DIR/scripts/test_mod_classifier.py"
# LOOP_RUN_DIR set: the loop driver owns that dir and its logs stay. Unset (a
# manual or GATE_SELFCHECK run): the gate makes its OWN temp dir and removes it
# on every path — pass, fail, error, INT/TERM (P-INFRA-3: nothing left under
# $TMPDIR, nothing left unreadable). A failing run prints the logs' tails
# BEFORE the dir goes (show_failure_logs), never silently.
OWN_TMP=""
if [ -z "${LOOP_RUN_DIR:-}" ]; then
  OWN_TMP=$(mktemp -d "${TMPDIR:-/tmp}/gate.XXXXXX") || { echo "GATE-ERROR: cannot create a temp dir under ${TMPDIR:-/tmp}" >&2; exit 3; }
fi
LOGDIR="${LOOP_RUN_DIR:-$OWN_TMP}/gate-logs/s$SLICE-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$LOGDIR" 2>/dev/null
export GATE_LOGDIR="$LOGDIR"   # probes/suites may put scratch files here; it is cleaned with the dir
FAIL_LOGS_SHOWN=0
show_failure_logs() { # own temp dir only: the logs are about to be deleted, so print the tails
  [ -n "$OWN_TMP" ] && [ "$FAIL_LOGS_SHOWN" = 0 ] && [ -d "$LOGDIR" ] || return 0
  FAIL_LOGS_SHOWN=1
  local f
  for f in "$LOGDIR"/*.log "$LOGDIR"/*.log.rerun "$LOGDIR"/failing-ids.err; do
    [ -s "$f" ] || continue
    echo "== log tail (removed with the temp dir): $f =="; tail -15 "$f" | sed 's/^/    | /'
  done
}
cleanup_tmp() {
  [ -n "$OWN_TMP" ] || return 0
  # a probe or suite may have left a file unreadable (mode 000): fix modes, then remove
  chmod -R u+rwX "$OWN_TMP" 2>/dev/null || echo "gate: could not chmod $OWN_TMP before removal" >&2
  rm -rf "$OWN_TMP" || echo "gate: could not remove temp dir $OWN_TMP" >&2
}
on_signal() { echo "gate: interrupted by $1" >&2; show_failure_logs; exit "$2"; }
trap cleanup_tmp EXIT
trap 'on_signal INT 130' INT
trap 'on_signal TERM 143' TERM

GERR=0; FAIL=0; ESC=""; SUITE_RED_ESCALATED=""
SUMMARY=()
status() { # <check> <STATUS> [detail]
  local line="$1: $2"; [ -n "${3:-}" ] && line="$line — $3"
  SUMMARY+=("$line"); echo "[$line]"
  case $2 in FAIL) FAIL=1;; GATE-ERROR) GERR=1;; esac
}
finish() {
  echo "== summary =="
  printf '%s\n' "${SUMMARY[@]}"
  local label=GATE; [ "$MODE" = preflight ] && label=PREFLIGHT
  if [ "$GERR" -ne 0 ] || [ "$FAIL" -ne 0 ]; then show_failure_logs; fi
  if [ "$GERR" -ne 0 ]; then echo "$label: GATE-ERROR (exit 3)"; exit 3; fi
  if [ "$MODE" = preflight ]; then
    [ "$FAIL" -ne 0 ] && { echo "$label: GATE-ERROR (exit 3)"; exit 3; }
    echo "$label: PASS"; exit 0
  fi
  [ "$FAIL" -ne 0 ] && { echo "$label: FAIL (exit 1)"; exit 1; }
  [ -n "$ESC" ] && { echo "$label: ESCALATED (valid escalation, every other check green; exit 2)"; exit 2; }
  echo "$label: PASS"; exit 0
}
words() { local -n _out=$1; read -r -a _out <<< "$2"; }   # split without glob expansion
in_list() { local x; for x in $2; do [ "$x" = "$1" ] && return 0; done; return 1; }

# --- config and base ----------------------------------------------------------
[ -n "$WT" ] && cd "$WT" 2>/dev/null || { status config GATE-ERROR "no work tree (LOOP_WORKDIR or a positional path)"; finish; }
CFG=""
[ "$SUITE_CMD" = CHANGE_ME ] && CFG="$CFG SUITE_CMD is not set;"
[ -z "$CLASSIFIER" ] && CFG="$CFG LOOP_SKILL_DIR is not set (the classifier is found through it);"
[ -z "$PROBES" ] && [ "$ALLOW_NO_PROBE" != 1 ] && CFG="$CFG no PROBES configured (set ALLOW_NO_PROBE=1 only for work with no runtime surface);"
for p in $PROBES; do [[ "$p" =~ ^[A-Za-z0-9_-]+$ ]] || CFG="$CFG probe name '$p' is not [A-Za-z0-9_-];"; done
if [ -n "$CFG" ]; then status config GATE-ERROR "${CFG%;}"; else status config PASS; fi
if [ -z "$BASE" ]; then status base GATE-ERROR "no base (LOOP_BASE_COMMIT or BASE_COMMIT)"
elif git rev-parse --verify -q "$BASE^{commit}" >/dev/null; then status base PASS "$BASE"
else status base GATE-ERROR "'$BASE' is not a commit in this repo"; fi

# --- probes (shared by gate and preflight) -------------------------------------
probe_cmd() { # name -> runs the probe
  if [ -n "$PROBE_RUNNER" ]; then bash -c "$PROBE_RUNNER $(printf '%q' "$1")"
  else bash "$(printf "$PROBE_FILE_PATTERN" "$1")"; fi
}
probe_once() { # name logfile -> 0 if exit 0 and both control lines printed
  local rc; probe_cmd "$1" > "$2" 2>&1; rc=$?
  PROBE_WHY=""
  [ "$rc" -ne 0 ] && PROBE_WHY="exited $rc;"
  grep -q "^$1 POSITIVE PASS" "$2" || PROBE_WHY="$PROBE_WHY no '$1 POSITIVE PASS' line;"
  grep -q "^$1 NEGATIVE PASS" "$2" || PROBE_WHY="$PROBE_WHY no '$1 NEGATIVE PASS' line (the negative control must reject a known-bad case);"
  [ -z "$PROBE_WHY" ]
}
record_flake() { # name -> 0, or 1 if this probe has now flaked in 2+ slices of this run
  [ -n "${LOOP_RUN_DIR:-}" ] || { echo "note: no LOOP_RUN_DIR — flake of $1 not recorded across slices"; return 0; }
  printf '%s\t%s\t%s\n' "$SLICE" "$1" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$LOOP_RUN_DIR/flakes.tsv"
  [ "$(awk -F'\t' -v p="$1" '$2 == p {print $1}' "$LOOP_RUN_DIR/flakes.tsv" | sort -u | wc -l)" -lt 2 ]
}
run_probes() { # names...
  local name log
  if [ -n "$PROBE_LOCK" ]; then
    exec 9>>"$PROBE_LOCK"
    if ! flock -E 3 -w "$PROBE_LOCK_WAIT" 9; then
      status probe-lock GATE-ERROR "probe lock $PROBE_LOCK not acquired in ${PROBE_LOCK_WAIT}s (a lock timeout is not a work FAIL)"
      for name in "$@"; do status "probe $name" "SKIPPED (probe lock)"; done
      exec 9>&-; return
    fi
  fi
  for name in "$@"; do
    log="$LOGDIR/probe-$name.log"
    if probe_once "$name" "$log"; then status "probe $name" PASS
    elif in_list "$name" "$PROBE_FLAKY"; then
      local first=$PROBE_WHY
      if probe_once "$name" "$log.rerun"; then
        if record_flake "$name"; then
          status "probe $name" FLAKE "FLAKE $name: failed ($first) then passed on its one re-run — the orchestrator reviews this (a pass-on-rerun can be a real race)"
        else
          status "probe $name" GATE-ERROR "FLAKE $name: $name has flaked in 2 slices of this run — fix the probe before trusting it ($LOOP_RUN_DIR/flakes.tsv)"
        fi
      else status "probe $name" FAIL "$first re-run: $PROBE_WHY (log $log)"; fi
    else status "probe $name" FAIL "$PROBE_WHY (log $log)"; sed 's/^/    | /' "$log" | tail -10; fi
  done
  [ -n "$PROBE_LOCK" ] && { flock -u 9; exec 9>&-; }
}

# =============================== PREFLIGHT ======================================
if [ "$MODE" = preflight ]; then
  if [ "$GERR" -eq 0 ]; then
    if [ ! -f "$CLASSIFIER" ]; then status classifier GATE-ERROR "not found at $CLASSIFIER"
    elif python3 "$CLASSIFIER" --self-test > "$LOGDIR/classifier-self-test.log" 2>&1; then status classifier PASS "self-test PASS"
    else status classifier GATE-ERROR "self-test FAILED ($LOGDIR/classifier-self-test.log)"; fi
    # Probes that ALREADY EXIST at base must show both controls now. Probes a
    # slice is about to create cannot be preflighted; the per-slice control
    # contract enforces them.
    EXISTING=()
    for p in $PROBES; do
      if git cat-file -e "$BASE:$(printf "$PROBE_FILE_PATTERN" "$p")" 2>/dev/null; then EXISTING+=("$p")
      else status "probe $p" "NOT RUN" "not at base yet — its controls are enforced per slice"; fi
    done
    [ "$GERR" -eq 0 ] && [ ${#EXISTING[@]} -gt 0 ] && run_probes "${EXISTING[@]}"
  fi
  finish
fi

# ================================= GATE =========================================
[ "$GERR" -ne 0 ] && { for p in $PROBES; do status "probe $p" "SKIPPED (earlier FAIL)"; done; finish; }

# --- escalation: honoured only with all three fields AND every other check green
if [ -f .loop-escalation ]; then
  E=0
  for f in BLOCKED MEASUREMENT WOULD-UNBLOCK; do
    grep -q "^$f:" .loop-escalation || { echo "ESCALATION REJECTED: missing $f"; E=1; }
  done
  if [ $E -eq 0 ]; then ESC=yes; status escalation PASS "valid (decided after every other check)"
  else status escalation FAIL "ESCALATION REJECTED: .loop-escalation needs BLOCKED, MEASUREMENT and WOULD-UNBLOCK lines"; fi
fi

# The work tree as a tree object, built through a TEMPORARY index (the real
# index is not touched), so new untracked files are visible to every diff.
TMPIDX="$LOGDIR/wt-index"
WT_TREE=$(GIT_INDEX_FILE="$TMPIDX" git read-tree HEAD && GIT_INDEX_FILE="$TMPIDX" git add -A && GIT_INDEX_FILE="$TMPIDX" git write-tree)
rm -f "$TMPIDX"
[ -n "$WT_TREE" ] || status worktree GATE-ERROR "could not snapshot the work tree"

# --- pins: protected paths and the gate's own dependencies -----------------------
if [ -n "$WT_TREE" ]; then
  words PINS "$PIN_PATHS $GATE_PINNED_PATHS"
  CHANGED=""
  for p in "${PINS[@]}"; do git diff --quiet "$BASE" "$WT_TREE" -- "$p" || CHANGED="$CHANGED $p"; done
  if [ ${#PINS[@]} -eq 0 ]; then status pins "OFF" "no PIN_PATHS / GATE_PINNED_PATHS"
  elif [ -n "$CHANGED" ]; then status pins FAIL "changed vs base:$CHANGED"
  else status pins PASS "${#PINS[@]} path(s) byte-identical to base"; fi
fi

# --- classifier: WEAKENING always fails; review hunks need declaration (+ authorisation)
if [ -z "$CLASSIFIER" ] || [ ! -f "$CLASSIFIER" ]; then
  status classifier GATE-ERROR "classifier not found at '${CLASSIFIER:-<LOOP_SKILL_DIR unset>}'"
else
  words GLOBS "$EXTRA_TEST_GLOBS"; CARGS=()
  for g in "${GLOBS[@]}"; do CARGS+=(--extra-test-glob "$g"); done
  CLOG="$LOGDIR/classifier.log"
  python3 "$CLASSIFIER" "$PWD" "$BASE" --strict "${CARGS[@]}" > "$CLOG" 2>&1; CEXIT=$?
  if [ "$CEXIT" -eq 0 ]; then status classifier PASS "CLEAN"
  elif [ "$CEXIT" -ne 1 ]; then status classifier GATE-ERROR "classifier exited $CEXIT — its output is NOT a verdict: $(tail -1 "$CLOG")"
  elif grep -q '\[WEAKENING\]' "$CLOG"; then
    grep '\[WEAKENING\]' "$CLOG" | head -8
    status classifier FAIL "WEAKENING: $(grep '\[WEAKENING\]' "$CLOG" | sed -E 's/^[[:space:]]+([^:]+):.*/\1/' | sort -u | tr '\n' ' ')"
  else
    FLAGGED=$(grep '\[PRINTED-FOR-REVIEW\]' "$CLOG" | sed -E 's/^[[:space:]]+([^:]+):.*/\1/' | sort -u)
    if [ -z "$FLAGGED" ]; then status classifier GATE-ERROR "classifier failed without a readable verdict: $(tail -1 "$CLOG")"
    else
      grep '\[PRINTED-FOR-REVIEW\]' "$CLOG" | head -8
      WHY=""
      for f in $FLAGGED; do
        if ! grep -qE "^$f( |$)" .loop-forced-flips 2>/dev/null; then WHY="$WHY $f: not declared in .loop-forced-flips;"
        elif [ "$ACCEPT_DECLARED_FLIPS" != 1 ] && ! in_list "$f" "${LOOP_AUTHORISED_FLIPS:-}"; then
          WHY="$WHY $f: declared but not authorised (not in LOOP_AUTHORISED_FLIPS);"
        fi
      done
      if [ -n "$WHY" ]; then status classifier FAIL "flagged for review —${WHY%;}"
      else status classifier PASS "only declared forced flips:$(echo $FLAGGED) — ORCHESTRATOR READS EACH DIFF"
        [ -n "${LOOP_RUN_DIR:-}" ] && cp .loop-forced-flips "$LOGDIR/forced-flips.txt"; fi
    fi
  fi
fi

# --- lockfiles: no new dependencies unless this slice may add them -----------------
if [ -z "$LOCKFILES" ]; then status lockfile OFF "no LOCKFILES"
elif [ -n "$WT_TREE" ]; then
  words LOCKS "$LOCKFILES"; LCH=""
  for l in "${LOCKS[@]}"; do git diff --quiet "$BASE" "$WT_TREE" -- "$l" || LCH="$LCH $l"; done
  if [ -z "$LCH" ]; then status lockfile PASS "unchanged"
  elif [ "$DEPS_ALLOWED" = 1 ]; then status lockfile PASS "changed:$LCH (DEPS_ALLOWED=1 — orchestrator reviews the new packages)"
  else status lockfile FAIL "changed:$LCH — no new dependencies approved for this slice"; fi
fi

# --- secret-shaped strings in the added lines --------------------------------------
if [ -n "$WT_TREE" ]; then
  HITS=$(git diff "$BASE" "$WT_TREE" | grep -E '^\+' | grep -v '^+++' | grep -cE "$SECRET_RE")
  if [ "$HITS" -gt 0 ]; then status secrets FAIL "$HITS added line(s) look like a secret"
  else status secrets PASS; fi
fi

# --- suite: green, or red ONLY on tests an honest escalation names -------------------
SLOG="$LOGDIR/suite.log"
if bash -c "$SUITE_CMD" > "$SLOG" 2>&1; then status suite PASS
else
  tail -15 "$SLOG" | sed 's/^/    | /'
  if [ -z "$ESC" ]; then status suite FAIL "red ($SLOG)"
  elif [ -z "$SUITE_FAILING_IDS_CMD" ]; then status suite FAIL "red, and no SUITE_FAILING_IDS_CMD to prove the escalation names every failing test"
  else
    bash -c "$SUITE_FAILING_IDS_CMD" 2>"$LOGDIR/failing-ids.err" | sed '/^[[:space:]]*$/d' > "$LOGDIR/failing-ids.txt"
    if [ ! -s "$LOGDIR/failing-ids.txt" ]; then status suite FAIL "red, but SUITE_FAILING_IDS_CMD listed no failing test"
    else
      VERDICT=$(python3 - "$BASE" "$WT_TREE" "$LOGDIR/failing-ids.txt" <<'PY'
import re, subprocess, sys
base, wt_tree = sys.argv[1], sys.argv[2]
failing = [l.strip() for l in open(sys.argv[3], encoding="utf-8") if l.strip()]
if not failing:
    print("FAIL no failing test IDs to check")
    sys.exit()
line = next((l for l in open(".loop-escalation", encoding="utf-8") if l.startswith("BLOCKED:")), "")
m = re.match(r"BLOCKED:\s*pre-existing tests?(?:\(s\))?\s+(.+?)\s+conflicts?\s+with\b", line)
if not m:
    print("FAIL BLOCKED line does not name test IDs as 'pre-existing test(s) <id>[, <id>…] conflict with …'")
    sys.exit()
named = [i.strip().strip("`'\"") for i in m.group(1).split(",") if i.strip()]
missing = [f for f in failing if f not in named]
if missing:
    print("FAIL failing test(s) not named in the escalation: " + ", ".join(missing))
    sys.exit()
for i in named:
    if "::" not in i:
        print(f"FAIL named test '{i}' is not a <file>::<test> ID")
        sys.exit()
    path = i.split("::", 1)[0]
    if subprocess.run(["git", "cat-file", "-e", f"{base}:{path}"], capture_output=True).returncode != 0:
        print(f"FAIL {path} (named test's file) is not pre-existing at base")
        sys.exit()
    if subprocess.run(["git", "diff", "--quiet", base, wt_tree, "--", path]).returncode != 0:
        print(f"FAIL {path} (named test's file) differs from base — an escalated test must be untouched")
        sys.exit()
print("OK " + ", ".join(failing))
PY
)
      if [[ "$VERDICT" == OK* ]]; then
        SUITE_RED_ESCALATED=yes
        status suite "RED, ESCALATED" "every failing test is named in .loop-escalation and byte-identical to base: ${VERDICT#OK }"
      else status suite FAIL "red: ${VERDICT#FAIL }"; fi
    fi
  fi
fi

# --- process-split: the root-only journey (KBOX-45), run as root inside a throwaway container ----------------------------------
# The uid-switch half of KBOX-45 needs root and makes `kbt-*` system users. That never happens on this host: the file runs as root in
# an official node:24 container with the work tree mounted read-only and copied in, and the container is removed after the run.
# KB_REQUIRE_UIDSWITCH=1 is set, and the test fails (never skips) when it cannot switch uid. No docker, no pass: there is no
# fallback to the host. The run must have passed at least one test and have no failed, skipped or todo test.
SPLIT_IMAGE=${SPLIT_IMAGE:-node:24}
SPLIT_LOG="$LOGDIR/process-split.log"
if ! command -v docker > /dev/null 2>&1; then
  status process-split FAIL "docker is not available; the root-only test runs in a container and is never run on the host"
elif docker run --rm --init --network none --memory 1g --pids-limit 512 -v "$PWD":/src:ro -e KB_REQUIRE_UIDSWITCH=1 "$SPLIT_IMAGE" \
    bash -c "mkdir /work && cd /src && tar cf - --exclude=./node_modules --exclude=./.git . | tar xf - -C /work && cd /work && timeout 240 node --test $SPLIT_FILE" > "$SPLIT_LOG" 2>&1 \
  && grep -Eq '^ℹ pass [1-9]' "$SPLIT_LOG" && grep -Eq '^ℹ fail 0$' "$SPLIT_LOG" && grep -Eq '^ℹ skipped 0$' "$SPLIT_LOG" && grep -Eq '^ℹ todo 0$' "$SPLIT_LOG"; then
  status process-split PASS "$(grep -E '^ℹ pass' "$SPLIT_LOG") as root in a $SPLIT_IMAGE container"
else
  tail -15 "$SPLIT_LOG" | sed 's/^/    | /'
  status process-split FAIL "red, skipped or did not run ($SPLIT_LOG)"
fi

# --- typecheck -------------------------------------------------------------------------
if [ -z "$TYPECHECK_CMD" ]; then status typecheck OFF "no TYPECHECK_CMD"
elif bash -c "$TYPECHECK_CMD" > "$LOGDIR/typecheck.log" 2>&1; then status typecheck PASS
else tail -10 "$LOGDIR/typecheck.log" | sed 's/^/    | /'; status typecheck FAIL "red ($LOGDIR/typecheck.log)"; fi

# --- tests grow (strict TDD; a WEAK signal) ---------------------------------------------
# git grep takes options only BEFORE the pattern and revs only AFTER it.
if [ "$TESTS_MUST_GROW" != 1 ]; then status test-growth OFF "TESTS_MUST_GROW=$TESTS_MUST_GROW"
else
  words TGLOBS "$TEST_COUNT_GLOBS"
  T0=$(git grep -hcE "$TEST_COUNT_RE" "$BASE" -- "${TGLOBS[@]}" 2>/dev/null | awk -F: '{s+=$NF} END {print s+0}')
  T1=$(git grep --untracked -hcE "$TEST_COUNT_RE" -- "${TGLOBS[@]}" 2>/dev/null | awk -F: '{s+=$NF} END {print s+0}')
  if [ "$T1" -gt "$T0" ]; then status test-growth PASS "$T0 -> $T1"
  else status test-growth FAIL "test count did not grow ($T0 -> $T1); set TESTS_MUST_GROW=0 for a refactor/bug-fix slice"; fi
fi

# --- probes: expensive, skipped once a cheap check failed ----------------------------------
if [ -z "$PROBES" ]; then status probes OFF "ALLOW_NO_PROBE=1 — mocked-test green proves NOTHING about the surface"
elif [ "$FAIL" -ne 0 ] || [ "$GERR" -ne 0 ]; then for p in $PROBES; do status "probe $p" "SKIPPED (earlier FAIL)"; done
else words PLIST "$PROBES"; run_probes "${PLIST[@]}"; fi

finish
