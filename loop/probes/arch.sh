#!/usr/bin/env bash
# Gate probe `arch`: the architecture tests (KBOX-27, KBOX-28, KBOX-35, KBOX-42) on the real tree.
#   POSITIVE: the unmodified tree passes test/arch.test.ts.
#   NEGATIVE: for each planted violation, a scratch copy of the tree with only that violation makes the
#             repo-tree test of the intended check fail. A check that stays green on its plant is loose.
# Prints "arch POSITIVE PASS" and "arch NEGATIVE PASS" and exits 0 only when both controls hold.
set -u
ROOT=$(pwd)
SCRATCH=${GATE_LOGDIR:-$(mktemp -d "${HOME}/.cache/key-box-probe.XXXXXX")}/arch-plants
NODE_TEST=(node --test --test-name-pattern='own tree passes')

if ! node --test test/arch.test.ts > "$SCRATCH.positive.log" 2>&1; then
  echo "arch: the architecture tests are red on the tree itself"; tail -20 "$SCRATCH.positive.log"; exit 1
fi
echo "arch POSITIVE PASS"

fresh_copy() { # a clean copy of the tracked and new files, with the real node_modules
  rm -rf "$SCRATCH"; mkdir -p "$SCRATCH"
  git ls-files -co --exclude-standard -z | xargs -0 cp --parents -t "$SCRATCH" || return 1
  ln -s "$ROOT/node_modules" "$SCRATCH/node_modules"
}
plant() { # <label> <check name the repo-tree test is called> <file> <content>
  local label=$1 check=$2 file=$3 content=$4
  fresh_copy || { echo "arch: could not copy the tree"; return 1; }
  mkdir -p "$SCRATCH/$(dirname "$file")"; printf '%s' "$content" > "$SCRATCH/$file"
  (cd "$SCRATCH" && "${NODE_TEST[@]}" test/arch.test.ts > "$SCRATCH.run.log" 2>&1)
  if [ $? -eq 0 ]; then echo "arch: plant '$label' left the architecture tests green"; return 1; fi
  if ! grep -q "✖ .*own tree passes the $check check" "$SCRATCH.run.log"; then
    echo "arch: plant '$label' failed, but not in the '$check' check"; tail -15 "$SCRATCH.run.log"; return 1
  fi
  echo "plant '$label': red in '$check'"
}
edit_package() { # <label> <check> <node expression over p>
  fresh_copy || return 1
  (cd "$SCRATCH" && node -e "const fs=require('fs');const p=JSON.parse(fs.readFileSync('package.json','utf8'));$3;fs.writeFileSync('package.json',JSON.stringify(p))")
  (cd "$SCRATCH" && "${NODE_TEST[@]}" test/arch.test.ts > "$SCRATCH.run.log" 2>&1)
  if [ $? -eq 0 ]; then echo "arch: plant '$1' left the architecture tests green"; return 1; fi
  grep -q "✖ .*own tree passes the $2 check" "$SCRATCH.run.log" || { echo "arch: plant '$1' failed, but not in the '$2' check"; return 1; }
  echo "plant '$1': red in '$2'"
}

BAD=0
plant 'Date.now in pure' 'pure core' src/pure/planted.ts $'export const t = Date.now();\n' || BAD=1
plant 'node:fs in pure' 'pure core' src/pure/planted.ts $'import * as fs from \'node:fs\';\nexport { fs };\n' || BAD=1
plant 'shell import from ports' 'layers' src/ports/planted.ts $'import { x } from \'../shell/nothing.ts\';\nexport { x };\n' || BAD=1
plant 'import cycle' 'import cycles' src/pure/planted-a.ts $'import { b } from \'./planted-b.ts\';\nexport const a = b;\n' || BAD=1
plant 'silent catch' 'catches' src/shell/planted.ts $'export const f = (g: () => void): void => {\n  try {\n    g();\n  } catch {\n  }\n};\n' || BAD=1
plant 'package import' 'import specifiers' src/shell/planted.ts $'import x from \'lodash\';\nexport { x };\n' || BAD=1
plant 'enum' 'erasable syntax' src/shell/planted.ts $'export enum E {\n  A,\n}\n' || BAD=1
plant 'any' 'zero counts' src/shell/planted.ts $'export let x: any = 1;\n' || BAD=1
plant 'kit reaches the verifier' 'kit independence' test/kit/planted.ts $'import { v } from \'../../src/pure/cose.ts\';\nexport { v };\n' || BAD=1
plant 'platform with no probe report' 'probe reports' src/platforms/planted/index.ts $'export const p = 1;\n' || BAD=1
plant 'type error' 'tsc --noEmit' src/shell/planted.ts $'export const n: number = \'a\';\n' || BAD=1
edit_package 'a dependencies key' 'toolchain' 'p.dependencies={left:"1.0.0"}' || BAD=1
edit_package 'a third dev dependency' 'toolchain' 'p.devDependencies.eslint="9.0.0"' || BAD=1
edit_package 'an unpinned range' 'toolchain' 'p.devDependencies.typescript="^"+p.devDependencies.typescript' || BAD=1

[ -z "${GATE_LOGDIR:-}" ] && rm -rf "$(dirname "$SCRATCH")"
[ "$BAD" -eq 0 ] || exit 1
echo "arch NEGATIVE PASS"
