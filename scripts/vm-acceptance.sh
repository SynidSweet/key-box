#!/usr/bin/env bash
# release-v2: the hermetic VM acceptance run (design 5.3, release-v2). Boots a candidate setup file (`user-data`) twice in an offline
# virtual machine and checks the disk afterwards. Needs a host with /dev/kvm and docker; nothing is installed on the host. The guest
# has no network (-nic none) and a clock two years before the file's KB_TIME_FLOOR, so the bootstrap must wait at stage 0 (`time`).
#   bash scripts/vm-acceptance.sh <user-data>          (through runq on devbox: --place devbox)
# Each check prints one PASS or FAIL line; the exit code is 0 only when every check passed. Takes about 20 minutes.
set -euo pipefail

# The throwaway container: Alpine, pinned by digest. The guest: Ubuntu's generic 24.04 x86-64 cloud image, checked against Ubuntu's SHA256SUMS.
ALPINE=alpine@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
IMAGE_NAME=noble-server-cloudimg-amd64.img
IMAGE_BASE=https://cloud-images.ubuntu.com/noble/current
# Bounds, in seconds. Every wait polls a named condition and gives up at its bound.
BOOT1_TIME_BOUND=1800  # boot 1: until `step` reads `time`
BOOT1_HOLD=600         # boot 1: `step` stays `time` for this long, then power off
BOOT2_RUN=300          # boot 2: runs this long, then power off
POWER_BOUND=120        # after system_powerdown, until qemu exits (then `quit`)
POLL=45                # between looks at the disk

# ------------------------------------------------------------------------------------------------------------------ host side
if [ "${1:-}" != "--inside" ]; then
  USERDATA=${1:-}
  [ -n "$USERDATA" ] && [ -r "$USERDATA" ] || { echo "usage: vm-acceptance.sh <user-data>" >&2; exit 2; }
  [ -c /dev/kvm ] || { echo "vm-acceptance: this host has no /dev/kvm" >&2; exit 2; }
  command -v docker >/dev/null || { echo "vm-acceptance: no docker" >&2; exit 2; }
  USERDATA=$(readlink -f "$USERDATA")
  SELF=$(readlink -f "${BASH_SOURCE[0]}")
  CACHE=$HOME/.cache/key-box-vm
  mkdir -p "$CACHE"
  SUMS=$(curl --proto '=https' -fsSL "$IMAGE_BASE/SHA256SUMS" | grep -E " \*?$IMAGE_NAME\$") || { echo "vm-acceptance: no SHA256SUMS line for $IMAGE_NAME" >&2; exit 2; }
  WANT=${SUMS%% *}
  [[ $WANT =~ ^[0-9a-f]{64}$ ]] || { echo "vm-acceptance: unreadable SHA256SUMS line" >&2; exit 2; }
  have() { [ -f "$CACHE/$IMAGE_NAME" ] && [ "$(sha256sum < "$CACHE/$IMAGE_NAME" | cut -c1-64)" = "$WANT" ]; }
  if ! have; then
    curl --proto '=https' -fsSLo "$CACHE/$IMAGE_NAME.part" "$IMAGE_BASE/$IMAGE_NAME"
    mv "$CACHE/$IMAGE_NAME.part" "$CACHE/$IMAGE_NAME"
    have || { echo "vm-acceptance: the downloaded image does not match Ubuntu's SHA256SUMS" >&2; exit 2; }
  fi
  echo "image: $IMAGE_NAME sha256 $WANT (checked against $IMAGE_BASE/SHA256SUMS)"
  echo "container: $ALPINE"
  NAME=kbvm-$$
  trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
  docker run --rm --name "$NAME" --device /dev/kvm --memory=3g --memory-swap=3g \
    -e IMAGE_NAME="$IMAGE_NAME" \
    -v "$CACHE/$IMAGE_NAME:/img/$IMAGE_NAME:ro" -v "$USERDATA:/in/user-data:ro" -v "$SELF:/harness.sh:ro" \
    "$ALPINE" sh -c 'apk add --no-cache bash >/dev/null && exec bash /harness.sh --inside'
  exit $?
fi

# ------------------------------------------------------------------------------------------------------------------ inside the container
apk add --no-cache qemu-system-x86_64 qemu-img mtools e2fsprogs dosfstools sfdisk socat coreutils >/dev/null
W=/work
mkdir -p "$W"
cd "$W"

FLOOR=$(sed -n 's/^ *KB_TIME_FLOOR=\([0-9][0-9]*\)$/\1/p' /in/user-data)
[ -n "$FLOOR" ] || { echo "vm-acceptance: no KB_TIME_FLOOR value line in the user-data" >&2; exit 2; }
RTC=$(date -u -d "@$((FLOOR - 63072000))" +%Y-%m-%dT%H:%M:%S)   # two years (730 days) before the floor

# The NoCloud seed: vfat, label CIDATA, with the candidate, a meta-data and a junk AppleDouble file.
truncate -s 8M seed.img
mkfs.vfat -n CIDATA seed.img >/dev/null
printf 'instance-id: kb-vm-acceptance\nlocal-hostname: keybox-vm\n' > meta-data
printf 'junk\000' > junk
mcopy -i seed.img /in/user-data ::user-data
mcopy -i seed.img meta-data ::meta-data
mcopy -i seed.img junk ::._user-data
qemu-img create -q -f qcow2 -b "/img/$IMAGE_NAME" -F qcow2 overlay.qcow2

FAILS=0
check() { # <name> <command...>: one PASS or FAIL line
  local name=$1; shift
  if "$@"; then echo "PASS $name"; else echo "FAIL $name"; FAILS=$((FAILS + 1)); fi
}
now() { date +%s; }
mon() { printf '%s\n' "$1" | socat -t2 - UNIX-CONNECT:"$W/mon" 2>/dev/null | tr -d '\r'; }
alive() { kill -0 "$QPID" 2>/dev/null; }

start_vm() { # <boot number>
  rm -f "$W/mon"
  qemu-system-x86_64 -enable-kvm -m 2048 -smp 2 -nic none -rtc "base=$RTC" -display none \
    -serial "file:$W/console-$1.log" -monitor "unix:$W/mon,server,nowait" \
    -drive "file=$W/overlay.qcow2,if=virtio,format=qcow2,cache=writethrough" \
    -drive "file=$W/seed.img,if=virtio,format=raw,readonly=on" &
  QPID=$!
  local until=$(( $(now) + 30 ))
  while [ ! -S "$W/mon" ]; do  # condition: the monitor socket exists
    alive || { echo "vm-acceptance: qemu did not start" >&2; exit 2; }
    [ "$(now)" -lt "$until" ] || { echo "vm-acceptance: no monitor socket within 30 s" >&2; exit 2; }
    sleep 1
  done
}
power_off() { # powerdown, then quit at the bound
  mon system_powerdown >/dev/null || true
  local until=$(( $(now) + POWER_BOUND ))
  while alive && [ "$(now)" -lt "$until" ]; do sleep 2; done  # condition: qemu has exited
  if alive; then echo "note: the guest did not power off within ${POWER_BOUND}s; quit from the host"; mon quit >/dev/null || true; fi
  wait "$QPID" 2>/dev/null || true
}

# Reading the disk: a raw copy of the overlay, its root partition found by sfdisk, journal replayed on the COPY, files read with debugfs.
PART=
snapshot() { # [live]: with `live` the guest is stopped for the copy and continued after
  [ "${1:-}" = live ] && mon stop >/dev/null
  rm -f "$W/snap.raw"
  local rc=0
  qemu-img convert -U -f qcow2 -O raw "$W/overlay.qcow2" "$W/snap.raw" || rc=$?
  [ "${1:-}" = live ] && mon cont >/dev/null
  [ "$rc" -eq 0 ] || return 1
  local start
  start=$(sfdisk -d "$W/snap.raw" | sed 's/ //g' | awk -F'[=,]' '/type=0FC63DAF/ { if ($4 + 0 > best) { best = $4 + 0; start = $2 } } END { print start }')
  [ -n "$start" ] || return 1
  PART="$W/snap.raw?offset=$((start * 512))"
  e2fsck -fy "$PART" >/dev/null 2>&1 || [ $? -le 1 ]  # 0 or 1 (journal replayed, fixed): a clean read
}
rd() { debugfs -R "cat $1" "$PART" 2>/dev/null; }
has() { debugfs -R "stat $1" "$PART" 2>&1 | grep -q '^Inode:'; }
trimmed() { rd "$1" | tr -d '\r\n '; }

# ------------------------------------------------------------------------------------------------------------------ boot 1
echo "boot 1: rtc base $RTC (floor $FLOOR)"
start_vm 1
until=$(( $(now) + BOOT1_TIME_BOUND ))
seen=0
while :; do  # condition: `step` reads `time` on the disk
  alive || { echo "vm-acceptance: the guest stopped by itself during boot 1" >&2; break; }
  if snapshot live 2>/dev/null && [ "$(trimmed /var/lib/kb-bootstrap/step)" = time ]; then seen=1; break; fi
  [ "$(now)" -lt "$until" ] || break
  sleep "$POLL"
done
if [ "$seen" -eq 1 ]; then
  echo "boot 1: step reads time; holding ${BOOT1_HOLD}s"
  until=$(( $(now) + BOOT1_HOLD ))
  while alive && [ "$(now)" -lt "$until" ]; do sleep 10; done  # condition: the hold has run its time
else
  echo "boot 1: step never read time within ${BOOT1_TIME_BOUND}s"
fi
power_off
snapshot || { echo "FAIL boot 1: the disk could not be read"; exit 1; }

# The units of ours: none may be enabled (a link in any .wants/.requires directory) and no unit file of theirs may sit in /etc/systemd/system.
ours='kb-[a-z]*\.(service|path)|keybox\.service|keyrelay\.service|caddy\.service'
nothing_enabled() {
  local d
  for d in $(debugfs -R 'ls -p /etc/systemd/system' "$PART" 2>/dev/null | awk -F/ '$6 ~ /\.(wants|requires)$/ { print $6 }'); do
    debugfs -R "ls -p /etc/systemd/system/$d" "$PART" 2>/dev/null | awk -F/ '{ print $6 }' | grep -Eq "^($ours)\$" && return 1
  done
  ! has /etc/systemd/system/keybox.service
}
masked() { debugfs -R "stat $1" "$PART" 2>&1 | grep -q '/dev/null'; }
lacks() { ! has "$1"; }
no_ubuntu() { ! rd /etc/passwd | grep -q '^ubuntu:'; }
no_code_text() { has /var/log/cloud-init-output.log && ! rd /var/log/cloud-init-output.log | grep -q 'code:'; }

check "boot1 step is time" test "$(trimmed /var/lib/kb-bootstrap/step)" = time
check "boot1 no ubuntu entry in /etc/passwd" no_ubuntu
check "boot1 getty@tty1 is masked" masked /etc/systemd/system/getty@tty1.service
check "boot1 no /etc/keybox/nftables.nft" lacks /etc/keybox/nftables.nft
check "boot1 no unit of ours is enabled" nothing_enabled
check "boot1 no stopped file" lacks /var/lib/kb-bootstrap/stopped
check "boot1 cloud-init-output.log holds no code: text" no_code_text

# ------------------------------------------------------------------------------------------------------------------ boot 2
echo "boot 2: same disk, ${BOOT2_RUN}s"
start_vm 2
until=$(( $(now) + BOOT2_RUN ))
while alive && [ "$(now)" -lt "$until" ]; do sleep 10; done  # condition: boot 2 has run its time
power_off
snapshot || { echo "FAIL boot 2: the disk could not be read"; exit 1; }
cut_off_names_time() { has /var/lib/kb-bootstrap/cut-off && rd /var/lib/kb-bootstrap/cut-off | grep -q 'cut off at: time'; }
no_second_run() { ! has /var/lib/kb-bootstrap/stopped || ! rd /var/lib/kb-bootstrap/stopped | grep -q 'a second run'; }
check "boot2 cut-off exists and names time" cut_off_names_time
check "boot2 no stopped file saying a second run" no_second_run

if [ "$FAILS" -eq 0 ]; then echo "ALL PASS"; exit 0; fi
echo "$FAILS FAILED; console logs:"; tail -n 20 "$W"/console-*.log || true
exit 1
