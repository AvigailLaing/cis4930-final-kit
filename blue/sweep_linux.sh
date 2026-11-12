#!/usr/bin/env bash
# sweep_linux.sh — find the common red persistence and remove it.
# Dry run by default. It prints evidence first, which is what you screenshot.
#
# Usage:
#   bash sweep_linux.sh                     # report only, changes nothing
#   sudo bash sweep_linux.sh --remove       # actually remove what it found
#
# Removal here covers: crontab entries, user/system systemd units matching the
# bad patterns, shell profile lines, and drop files in /tmp. Deleting accounts and
# changing passwords is an endgame action, do that by hand with lockdown steps.

set -u
REMOVE=0
[ "${1:-}" = "--remove" ] && REMOVE=1
U="${2:-$(id -un)}"
HOMEDIR="$(getent passwd "$U" | cut -d: -f6)"
PAT='dev/tcp|bash -i|nc -e|ncat|socat|base64 -d|curl -s.*sh|wget.*-O-'
FOUND=0

note() { echo "  [FOUND] $*"; FOUND=$((FOUND+1)); }
act()  { if [ "$REMOVE" -eq 1 ]; then echo "  [REMOVED] $*"; else echo "  [DRY RUN] would: $*"; fi; }

echo "================= SWEEP: $U on $(hostname) ================="
[ "$REMOVE" -eq 0 ] && echo "  (dry run, nothing will change)"

echo
echo "---- user crontab ----"
crontab -l 2>/dev/null | grep -nE "$PAT" | while read -r line; do
  echo "  [FOUND] crontab: $line"
done
if crontab -l 2>/dev/null | grep -qE "$PAT"; then
  crontab -l 2>/dev/null | grep -vE "$PAT" > /tmp/.cron_clean.$$
  act "rewrite crontab without the matching lines"
  [ "$REMOVE" -eq 1 ] && crontab /tmp/.cron_clean.$$ && echo "  [OK] crontab rewritten, now:"
  [ "$REMOVE" -eq 1 ] && crontab -l
  rm -f /tmp/.cron_clean.$$
fi

echo
echo "---- system crontabs ----"
sudo grep -rnE "$PAT" /etc/cron* /etc/crontab /var/spool/cron 2>/dev/null | while read -r line; do
  echo "  [FOUND] $line"
done

echo
echo "---- systemd units matching the patterns ----"
for f in $(sudo grep -rlE "$PAT" /etc/systemd/system /usr/lib/systemd/system /home/*/.config/systemd 2>/dev/null); do
  note "unit file: $f"
  sudo grep -E 'ExecStart|OnUnitActiveSec' "$f" 2>/dev/null | sed 's/^/      /'
  act "systemctl disable --now $(basename "$f") ; rm -f $f"
  if [ "$REMOVE" -eq 1 ]; then
    sudo systemctl disable --now "$(basename "$f")" 2>/dev/null
    sudo rm -f "$f"
  fi
done

echo
echo "---- user timers ----"
systemctl --user list-timers --all 2>/dev/null | sed 's/^/  /'

echo
echo "---- shell profiles ----"
for f in "$HOMEDIR/.bashrc" "$HOMEDIR/.profile" /root/.bashrc /root/.profile; do
  [ -f "$f" ] || continue
  if grep -qE "$PAT|dev/tcp" "$f" 2>/dev/null; then
    note "callback line in $f:"
    grep -nE "$PAT|dev/tcp" "$f" | sed 's/^/      /'
    act "delete those lines from $f"
    if [ "$REMOVE" -eq 1 ]; then
      sudo cp "$f" "/tmp/.$(basename "$f").bak"
      sudo grep -vE "$PAT|dev/tcp|^# .*-profile$" "/tmp/.$(basename "$f").bak" > /tmp/.clean.$$ && sudo cp /tmp/.clean.$$ "$f"
      rm -f /tmp/.clean.$$ "/tmp/.$(basename "$f").bak"
    fi
  fi
done

echo
echo "---- ssh keys ----"
sudo find /home /root -name authorized_keys -exec echo "  {}" \; -exec cat {} + 2>/dev/null | head -20
echo "  (remove only the added line, keep any legitimate key, and screenshot before/after)"

echo
echo "---- executables dropped in tmp ----"
find /tmp /var/tmp /dev/shm -maxdepth 2 -type f -perm -u+x 2>/dev/null | sed 's/^/  /'

echo
echo "---- processes with a deleted or odd binary ----"
for p in /proc/[0-9]*; do
  exe="$(readlink "$p/exe" 2>/dev/null)" || continue
  case "$exe" in
    *"(deleted)"|/tmp/*|/dev/shm/*)
      echo "  [FOUND] $(basename "$p") exe=$exe cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null | cut -c1-100)"
      act "kill -9 $(basename "$p")"
      [ "$REMOVE" -eq 1 ] && sudo kill -9 "$(basename "$p")" 2>/dev/null ;;
  esac
done

echo
echo "================= SUMMARY ================="
if [ "$REMOVE" -eq 1 ]; then
  echo "  Removal pass done. Now verify:"
else
  echo "  Dry run only. Re-run with --remove to act."
fi
echo "  ss -tupn                      # no listener to Kali"
echo "  crontab -l                    # clean"
echo "  systemctl list-timers --all   # no rogue timers"
echo "  wait 3 minutes, check again    # if it returns, there is a second mechanism"
