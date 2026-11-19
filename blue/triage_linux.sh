#!/usr/bin/env bash
# triage_linux.sh — "what changed, and what looks wrong". Run it every couple of minutes.
# Read-only. It changes nothing, so it is safe to run while Red is still active.
#
# Usage: bash triage_linux.sh [user]

set -u
U="${1:-$(id -un)}"
D="$HOME/blue_baseline"
REF=""
[ -f "$D/stamp.txt" ] && REF="$D/stamp.txt"

hr() { echo; echo "---- $* ----"; }
hit() { echo "  [!!] $*"; }

# A script that stops to ask for a password mid-round is worse than one that reports
# less. If sudo cannot run without a prompt, run every check unprivileged instead.
if ! command sudo -n true 2>/dev/null; then
  echo "  [i] sudo wants a password on this account: privileged reads skipped"
  echo "      run as root or a sudoer for the full picture"
  sudo() { "$@"; }
fi

hr "listeners and connections (with the PID that owns them)"
sudo ss -tupn 2>/dev/null | head -30

# The packet's own advice: match every listening service to something you run, and
# treat an established outbound connection you cannot explain as a reverse shell.
hr "listeners that were not there at baseline (a bind shell lands here)"
if [ -f "$D/listeners.txt" ]; then
  diff <(sudo ss -tulpn 2>/dev/null) "$D/listeners.txt" 2>/dev/null | grep '^[<>]' | sed 's/^/  /' || echo "  no change"
else
  echo "  no baseline yet. run: bash blue.sh baseline"
fi

hr "new connections since baseline, outliers only"
if [ -f "$D/conn.txt" ]; then
  diff <(ss -tupn 2>/dev/null) "$D/conn.txt" 2>/dev/null | grep '^>' | grep -vE 'sshd|:22 |ESTAB.*10\.42' | sed 's/^/  /' | head -15 || echo "  no change"
  echo "  (ignore your own ssh session, and 10.42.x is red, so anything ESTAB to it is a callback)"
fi

hr "kernel modules (the Phase 3 rootkit check: trust the kernel, not ps)"
if [ -f "$D/modules.txt" ]; then
  diff <(lsmod | awk '{print $1}' | sort) "$D/modules.txt" 2>/dev/null | grep '^[<>]' | sed 's/^/  /' || echo "  no change"
else
  echo "  no module baseline, showing current"
  lsmod | head -8
fi
[ -n "$REF" ] && sudo find /lib/modules -newer "$REF" -type f 2>/dev/null | head -10
if command -v lsmod >/dev/null 2>&1; then
  DETRITUS="$(lsmod | awk '{print $1}' | grep -vE '^(Module|nf_|xt_|ip_|udp|tcp|af_|binfmt|bridge|stp|llc|cfg80211|rfkill|snd|soundcore|intel|kvm|irqbypass|dm_|xfs|btrfs|ext4|mbcache|jbd2|crc16|overlay|loop|fuse|autofs4|raid|sd_|scsi|t10_|libata|ahci|virtio|virtio_)' || true)"
  [ -n "$DETRITUS" ] && echo "  review: $(echo $DETRITUS | tr '\n' ' ')"
fi

hr "processes running from places processes should not live"
for p in /proc/[0-9]*; do
  pid="${p#/proc/}"
  exe="$(readlink "$p/exe" 2>/dev/null)" || continue
  case "$exe" in
    /tmp/*|/var/tmp/*|/dev/shm/*|/home/*|/run/*)
      hit "pid $pid  exe=$exe  cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null | cut -c1-120)" ;;
    *"(deleted)")
      hit "pid $pid  exe=$exe (binary deleted while running)" ;;
  esac
done

hr "process tree (look for shells whose parent is cron or systemd)"
ps auxf | grep -vE "grep|ps auxf" | tail -40

hr "approved user list, from the blue packet"
# The packet hands you this list. Anything with a login shell that is not on it, and
# any sudo right held by someone the packet does not mark admin, is report material.
# Edit these two lines if the final's list differs.
APPD_USERS="ftruman htruman abrennan lmoran bbriggs cbraxford dcooper jholcomb hawk2hill lpalmer bob exim"
APPD_ADMIN="htruman lmoran hawk2hill lpalmer"
for u in $(awk -F: '$3>=1000 && $7 !~ /(nologin|false)$/ {print $1}' /etc/passwd 2>/dev/null); do
  case " $APPD_USERS " in *" $u "*) ;; *) hit "login shell, not on the approved list: $u" ;; esac
done
for u in $(getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' ' '); do
  [ -n "$u" ] || continue
  case " $APPD_ADMIN " in *" $u "*) ;; *) hit "in the sudo group but not on the admin list: $u" ;; esac
done
for f in /etc/sudoers.d/*; do
  [ -f "$f" ] || continue
  case "$(basename "$f")" in README) continue ;; esac
  who="$(sudo awk '{print $1}' "$f" 2>/dev/null | head -1)"
  case "$who" in ''|Defaults|\#*) continue ;; %*) hit "sudo drop-in for group $who: $(basename "$f")"; continue ;; esac
  case " $APPD_ADMIN " in
    *" $who "*) ;;
    *) hit "sudo right held by $who, who is not on the packet's admin list ($(basename "$f"))" ;;
  esac
done

hr "user list drift"
if [ -f "$D/users.txt" ]; then
  diff <(getent passwd) "$D/users.txt" | grep '^[<>]' || echo "  no change"
else
  echo "  no baseline, showing current:"
  getent passwd | awk -F: '$3>=1000 {print $1" uid="$3" shell="$7}'
fi

hr "who can sudo"
getent group sudo 2>/dev/null; getent group wheel 2>/dev/null
[ -f "$D/sudoers.txt" ] && { echo "  sudoers drift:"; diff <(sudo grep -vE '^#|^$' /etc/sudoers 2>/dev/null) <(grep -v '^#' "$D/sudoers.txt" | grep -vE '^(/etc|total|d|-)' ) 2>/dev/null | head; }

hr "crontabs, with the suspicious patterns flagged"
{ crontab -l 2>/dev/null; ls -la /var/spool/cron/crontabs 2>/dev/null; } | sed 's/^/  /'
if crontab -l 2>/dev/null | grep -nE 'dev/tcp|curl|wget|base64|python -c|perl -e|bash -i|nc '; then
  hit "crontab contains a callback-looking command (above)"
fi
sudo grep -rnE 'dev/tcp|curl|wget|base64|bash -i|nc -e' /etc/cron* /var/spool/cron 2>/dev/null | head -10

hr "systemd: recent unit files and user timers"
[ -n "$REF" ] && sudo find /etc/systemd /lib/systemd /usr/lib/systemd "$HOME/.config/systemd" \
  -newer "$REF" -type f 2>/dev/null | head -20
sudo find / -name '*.timer' -newermt '-45 minutes' 2>/dev/null | grep -v snap | head -20
systemctl list-timers --all 2>/dev/null | head -15
echo "  (user scope, easy to miss:)"
systemctl --user list-timers --all 2>/dev/null | head -10

hr "ssh keys"
sudo find /home /root -name authorized_keys -exec ls -l {} + 2>/dev/null
sudo find /home /root -name authorized_keys -exec echo "== {}" \; -exec cat {} + 2>/dev/null | tail -20

hr "recently written files in the usual drop spots"
[ -n "$REF" ] && sudo find /etc /home /root /usr/local /tmp /var/tmp -newer "$REF" -type f 2>/dev/null \
  | grep -vE '\.log$|blue_baseline|/proc/' | head -30

hr "shell profiles changed"
[ -n "$REF" ] && sudo find /home /root -maxdepth 2 -name '.bashrc' -o -maxdepth 2 -name '.profile' 2>/dev/null \
  | xargs -r ls -l 2>/dev/null | head

hr "auditd, if it is loaded"
if command -v aureport >/dev/null 2>&1; then
  sudo aureport -k --summary 2>/dev/null | head -20
  for k in cron systemd user_ssh user_profile honeyfile new_units etcpasswd tmp_write; do
    out="$(sudo ausearch -k "$k" -i --start recent 2>/dev/null | tail -6)"
    [ -n "$out" ] && { echo "  == key: $k"; echo "$out" | sed 's/^/    /'; }
  done
else
  echo "  auditd not installed"
fi

hr "installed files that were modified (slow, worth one run)"
echo "  run: sudo dpkg -V | head -20"

echo
echo "If you found something: screenshot it, then run sweep_linux.sh"
