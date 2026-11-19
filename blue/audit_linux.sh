#!/usr/bin/env bash
# audit_linux.sh — find the basic weaknesses on this box, then fix the safe ones.
#
# This is the blue-side scanner. red's scanner is "red.sh privesc"; this one asks the same
# questions but from the defender's chair, and it can close the easy holes in one pass.
#
# Usage, ON THE PD:
#   bash blue.sh audit              # report only, changes nothing
#   sudo bash blue.sh audit --fix   # fix the safe ones, print BEFORE and AFTER for each
#
# Never touched, on purpose:
#   - anonymous FTP (the scoring engine checks it, turning it off loses points)
#   - sshd access for the scored account (you would break the SSH check)
#   - anything that needs a service restart you cannot verify afterwards

set -u
FIX=0
[ "${1:-}" = "--fix" ] && FIX=1
FOUND=0
FIXED=0

hr() { echo; echo "---- $* ----"; }
bad() { echo "  [FINDING] $*"; FOUND=$((FOUND+1)); }
good() { echo "  [ok] $*"; }
fixit() {
  if [ "$FIX" -eq 1 ]; then
    echo "     [FIX] $*"
    eval "$@" >/dev/null 2>&1 && FIXED=$((FIXED+1))
  else
    echo "     [would fix] $*"
  fi
}

echo "=== audit_linux.sh  host=$(hostname)  user=$(id -un)  fix=$FIX  $(date) ==="

# 1. sudo rights -------------------------------------------------------------
hr "sudo rules"
sudo -n -l 2>/dev/null | sed 's/^/  /' | head -15 || echo "  (needs a password to list)"
if sudo -n -l 2>/dev/null | grep -qE '\(ALL(:ALL)?\) (NOPASSWD: )?ALL'; then
  bad "an account has blanket sudo (ALL:ALL). That is the phase 3 escalation"
  echo "     fix by hand: visudo, remove the rule, or use a dedicated group"
fi
for f in /etc/sudoers.d/*; do
  [ -f "$f" ] || continue
  grep -qE 'ALL' "$f" 2>/dev/null && { bad "sudo drop-in grants ALL: $f"; }
done

# 2. SUID binaries -----------------------------------------------------------
hr "SUID set on binaries that are not SUID by default"
# The old hardcoded list missed python3.13 and base64, which is exactly what the
# practice pod had. Compare against the stock Debian set instead, and strip the
# version suffix so python3.13 and python3 both resolve.
STOCK_SUID="dbus-daemon-launch-helper Xorg.wrap ssh-keysign polkit-agent-helper-1 pppd chfn chsh sudo passwd su newgrp gpasswd fusermount fusermount3 pkexec mount umount ntfs-3g unix_chkpwd chage expire sg snap-confine chrome-sandbox nvidia-modprobe"
BAD_SUID=0
while IFS= read -r b; do
  [ -n "$b" ] || continue
  base="$(basename "$b")"
  stem="$(echo "$base" | sed -E 's/(python|perl|ruby|php)[0-9.]+$/\1/')"
  case " $STOCK_SUID " in *" $base "*) continue ;; esac
  case " $STOCK_SUID " in *" $stem "*) continue ;; esac
  BAD_SUID=$((BAD_SUID+1))
  bad "SUID on $b (not SUID by default)"
  echo "     package owner: $(dpkg -S "$b" 2>/dev/null | head -1 | cut -d: -f1 || echo 'no dpkg owner')"
  fixit "sudo chmod u-s $b"
done <<EOF
$(find / -perm -4000 -type f 2>/dev/null)
EOF
[ "$BAD_SUID" -eq 0 ] && good "no unexpected SUID binaries"
COUNT_SUID="$(find / -perm -4000 -type f 2>/dev/null | wc -l)"
echo "  total SUID binaries: $COUNT_SUID (a normal Debian box has 10 to 15)"

# 3. empty passwords and UID 0 -------------------------------------------------
hr "accounts"
EMPTY="$(sudo awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null)"
if [ -n "$EMPTY" ]; then
  for u in $EMPTY; do bad "account with no password: $u"; fixit "sudo passwd -l $u"; done
else
  good "no account has an empty password"
fi
EXTRA_ROOT="$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd)"
[ -n "$EXTRA_ROOT" ] && { for u in $EXTRA_ROOT; do bad "UID 0 account that is not root: $u"; done; } || good "only root has UID 0"

# 4. sshd --------------------------------------------------------------------
hr "sshd configuration"
SSHD_CONF=/etc/ssh/sshd_config
if [ -f "$SSHD_CONF" ]; then
  grep -qiE '^\s*PermitRootLogin\s+yes' "$SSHD_CONF" && bad "PermitRootLogin yes" && echo "     fix: drop-in with 'PermitRootLogin no'"
  grep -qiE '^\s*PermitEmptyPasswords\s+yes' "$SSHD_CONF" && bad "PermitEmptyPasswords yes"
  grep -qiE '^\s*PasswordAuthentication\s+yes' "$SSHD_CONF" && good "password auth on (needed if the scoring check logs in this way)"
fi
if [ ! -f /etc/ssh/sshd_config.d/99-blue-hardening.conf ]; then
  bad "no hardening drop-in present"
  fixit "printf 'PermitRootLogin no\nPermitEmptyPasswords no\nMaxAuthTries 3\n' | sudo tee /etc/ssh/sshd_config.d/99-blue-hardening.conf && sudo sshd -t && sudo systemctl reload ssh"
else
  good "hardening drop-in already in place"
fi

# 5. web root permissions ------------------------------------------------------
hr "web root"
for d in /var/www /var/www/html; do
  [ -d "$d" ] || continue
  WW="$(find "$d" -type f -perm -o+w 2>/dev/null | head -10)"
  if [ -n "$WW" ]; then
    echo "  world-writable files under $d:"
    echo "$WW" | sed 's/^/    /'
    bad "world-writable file in the web root (this is how phase 3's web shell was planted)"
    for f in $WW; do fixit "sudo chmod o-w $f"; done
  else
    good "no world-writable files in $d"
  fi
done

# 6. cron permissions ----------------------------------------------------------
hr "cron"
[ -f /etc/crontab ] && { PERMS="$(stat -c '%a' /etc/crontab)"; [ "$PERMS" = "600" ] && good "/etc/crontab is 600" || { bad "/etc/crontab is $PERMS"; fixit "sudo chmod 600 /etc/crontab"; }; }
[ -d /var/spool/cron/crontabs ] && { PERMS="$(stat -c '%a' /var/spool/cron/crontabs)"; echo "  /var/spool/cron/crontabs perms: $PERMS"; }
echo "  current crontabs:"
crontab -l 2>/dev/null | sed 's/^/    /' || echo "    (none for this user)"
sudo ls -la /etc/cron.d 2>/dev/null | sed 's/^/    /' | head -8

# 7. FTP, deliberately not fixed -----------------------------------------------
hr "FTP (scored, do not disable)"
if command -v vsftpd >/dev/null 2>&1 || systemctl list-units --all 2>/dev/null | grep -qi ftp; then
  grep -qiE '^\s*anonymous_enable\s*=\s*YES' /etc/vsftpd.conf 2>/dev/null && echo "  anonymous FTP is ON. The scoring engine checks it, so leave it on."
  echo "  [do not touch] turning anonymous access off loses the FTP check"
fi

# 8. auditd ---------------------------------------------------------------------
hr "auditd"
if systemctl is-active --quiet auditd 2>/dev/null; then
  good "auditd is running, $(sudo auditctl -l 2>/dev/null | wc -l) rules loaded"
else
  bad "auditd is not running, so nothing you need to detect is being recorded"
  fixit "sudo apt-get install -y auditd && sudo systemctl enable --now auditd"
fi

# 9. packages, report only ------------------------------------------------------
hr "package drift (report only, do not upgrade mid-round)"
if command -v apt >/dev/null 2>&1; then
  UPG="$(apt list --upgradable 2>/dev/null | grep -c upgradable)"
  echo "  upgradable packages: ${UPG:-unknown} (an upgrade mid-round can restart services and cost points)"
fi

echo
echo "=== SUMMARY: $FOUND finding(s), $FIXED fixed ==="
if [ "$FIX" -eq 0 ]; then
  echo "Report only. Re-run with --fix to close the safe ones, and screenshot BEFORE and AFTER."
else
  echo "Now verify the scored services still answer:"
  echo "  nmap -Pn -p 0,21,22,80 $(hostname -I | awk '{print $1}')"
  echo "And log the hardening for the report:"
  echo "  bash evidence.sh \"hardening: suid find removed\" \"PD /usr/bin/find\" \"audit_linux.sh --fix\""
fi
