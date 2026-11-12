#!/usr/bin/env bash
# evict.sh — one documented response action: find Red's access and throw them out.
#
# This is the "what did you do about Red" bullet. It is evidence-first: it lists what it finds,
# prints the commands it would run, and only acts with --apply.
#
# Usage:
#   sudo bash evict.sh --from <RED_IP>            # report only
#   sudo bash evict.sh --from <RED_IP> --apply    # kill sessions, then remove their persistence
#
# Order matters and it is the same order you write about:
#   1. identify the sessions and processes tied to Red's source IP
#   2. screenshot that (evidence)
#   3. kill the sessions
#   4. remove the persistence that would let them back in
#   5. re-check: nothing listening out, nothing scheduled, nothing new in authorized_keys

set -u
SRC_IP=""
APPLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --from) SRC_IP="${2:-}"; shift 2 ;;
    --apply) APPLY=1; shift ;;
    *) echo "usage: bash evict.sh --from <RED_IP> [--apply]"; exit 1 ;;
  esac
done
[ -z "$SRC_IP" ] && { echo "usage: bash evict.sh --from <RED_IP> [--apply]"; exit 1; }

STAMP="$(date +%H-%M)"
LOG="$HOME/evict-$STAMP.txt"
say() { echo "$*" | tee -a "$LOG"; }
act() { if [ "$APPLY" -eq 1 ]; then say "  [DO]   $*"; eval "$*" >>"$LOG" 2>&1; else say "  [WOULD] $*"; fi; }

say "=== evict.sh  host=$(hostname)  target=$SRC_IP  apply=$APPLY  $(date) ==="

say ""
say "---- 1. sessions and connections from $SRC_IP ----"
who -a 2>/dev/null | sed 's/^/  /'
say "  established connections:"
ss -tnp 2>/dev/null | grep -E "$SRC_IP" | sed 's/^/  /' || say "  (none right now)"
say "  sshd processes:"
ps -eo pid,ppid,user,etime,cmd | grep -E "[s]shd:.*$SRC_IP" | sed 's/^/  /' || say "  (none)"

say ""
say "---- 2. processes owned by the users those sessions belong to ----"
USERS="$(who | awk '{print $1}' | sort -u | tr '\n' ' ')"
say "  logged in users: $USERS"
for u in $USERS; do
  ps -u "$u" -o pid,user,etime,cmd --no-headers 2>/dev/null | sed 's/^/  /' | head -12
done

say ""
say "---- 3. outbound callbacks (a shell Red is holding looks like this) ----"
ss -tupn 2>/dev/null | grep -E ':4[0-9]{3}|:1[0-9]{4}|:4444|:9001' | sed 's/^/  /' || say "  (none obvious)"

say ""
say "---- 4. persistence that would let them back in ----"
say "  cron:"
crontab -l 2>/dev/null | sed 's/^/    /'
for d in /var/spool/cron/crontabs /etc/cron.d; do ls -la "$d" 2>/dev/null | sed 's/^/    /'; done
say "  ssh keys:"
sudo find /home /root -name authorized_keys -exec echo "    {}" \; -exec cat {} + 2>/dev/null
say "  user units:"
systemctl --user list-timers --all 2>/dev/null | sed 's/^/    /'
say "  suspicious processes with a deleted or tmp binary:"
for p in /proc/[0-9]*; do
  exe="$(readlink "$p/exe" 2>/dev/null)" || continue
  case "$exe" in *"(deleted)"|/tmp/*|/dev/shm/*) say "    pid $(basename "$p")  $exe" ;; esac
done

if [ "$APPLY" -eq 1 ]; then
  say ""
  say "---- 5. acting ----"
  for u in $USERS; do
    [ "$u" = "$(id -un)" ] && { say "  [SKIP] $u is me"; continue; }
    act "pkill -KILL -u $u"
  done
  for pat in "sshd: .*$SRC_IP" "bash -i" "nc -e" "ncat" "socat"; do
    act "pkill -KILL -f '$pat'"
  done
  act "bash $(dirname "$0")/sweep_linux.sh --remove"

  say ""
  say "---- 6. verify ----"
  say "  connections now:"
  ss -tnp 2>/dev/null | grep -E "$SRC_IP" | sed 's/^/  /' || say "  [OK] no connection to $SRC_IP"
  say "  crontab now:"
  crontab -l 2>/dev/null | sed 's/^/    /' || say "    (empty)"
  say "  listeners:"
  ss -tulpn 2>/dev/null | grep -vE '127.0.0.1|::1' | sed 's/^/  /'
  say ""
  say "Wait two minutes and look again. If anything returns, there is a second mechanism, which is"
  say "the most valuable sentence in the blue report."
else
  say ""
  say "Report only. Nothing changed. Re-run with --apply to act, after you screenshot this output."
fi
say ""
say "Log: $LOG"
