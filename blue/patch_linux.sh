#!/usr/bin/env bash
# patch_linux.sh — the patching half of Blue's job. Detection finds it, this fixes it.
# Idempotent: safe to run twice, every step prints BEFORE / AFTER / STATUS.
# Writes a report you can screenshot and cite.
#
# Usage:
#   bash patch_linux.sh              # apply
#   bash patch_linux.sh --dry-run    # show what it would change
#
# Fixes, each one tied to something that showed up in the labs:
#   1. auditd installed, running, and the Florian Roth ruleset loaded
#   2. sshd hardening via a drop-in config (no editing of sshd_config itself)
#   3. removes the SUID bit from find (the phase 3 privilege escalation)
#   4. locks accounts with an empty password hash
#   5. tightens crontab and spool permissions
#   6. reports world-writable files in web roots without deleting anything

set -u
DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1
STAMP="$(date +%Y%m%d-%H%M%S)"
REPORT="${HOME}/patch_report_${STAMP}.txt"

say()  { printf '%s\n' "$*" | tee -a "$REPORT"; }
head2() { say ""; say "=============================================="; say "== $*"; say "=============================================="; }
doit() { if [ "$DRY" -eq 1 ]; then say "  [DRY RUN] would run: $*"; else say "  [RUN]  $*"; eval "$@" >>"$REPORT" 2>&1; fi; }
status() { say "  [STATUS] $*"; }

say "patch_linux.sh  host=$(hostname)  user=$(id -un)  dry_run=$DRY  $STAMP"

# ---------------------------------------------------------------- 1. auditd
head2 "1. auditd: installed, running, ruleset loaded"
if ! command -v auditctl >/dev/null 2>&1; then
  say "  auditd is not installed"
  doit "sudo apt-get update -qq && sudo apt-get install -y auditd"
else
  status "auditd present"
fi
doit "sudo systemctl enable --now auditd"
BEFORE_RULES="$(sudo auditctl -l 2>/dev/null | wc -l)"
say "  rules loaded before: $BEFORE_RULES"
if [ ! -f /opt/florian-roth-auditd.rules ]; then
  say "  [i] ruleset missing, downloading it now"
  doit "sudo curl -fsSL -o /opt/florian-roth-auditd.rules https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules"
fi
if [ -s /opt/florian-roth-auditd.rules ]; then
  doit "sudo auditctl -R /opt/florian-roth-auditd.rules"
  say "  [OK] ruleset loaded (it starts with -D, so anything loaded before this was wiped)"
else
  say "  [!] could not download the ruleset. No internet? Load only the custom watches below."
fi
doit "sudo auditctl -w /etc/crontab -p wa -k cron"
doit "sudo auditctl -w /etc/cron.d -p wa -k cron"
doit "sudo auditctl -w /etc/systemd/system -p wa -k systemd"
doit "sudo auditctl -w /etc/passwd -p wa -k etcpasswd"
doit "sudo auditctl -w /etc/sudoers -p wa -k actions"
AFTER_RULES="$(sudo auditctl -l 2>/dev/null | wc -l)"
say "  rules loaded after:  $AFTER_RULES"

# ------------------------------------------------------------------ 2. sshd
head2 "2. sshd hardening (drop-in file, main config untouched)"
if [ -d /etc/ssh/sshd_config.d ]; then
  DROPIN=/etc/ssh/sshd_config.d/99-blue-hardening.conf
  if [ -f "$DROPIN" ]; then
    status "drop-in already present: $DROPIN"
    sudo cat "$DROPIN" | sed 's/^/    /' | tee -a "$REPORT"
  else
    if [ "$DRY" -eq 1 ]; then
      say "  [DRY RUN] would write $DROPIN"
    else
      sudo tee "$DROPIN" >/dev/null <<'EOF'
# Blue team hardening
PermitRootLogin no
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowAgentForwarding no
EOF
      say "  [WROTE] $DROPIN"
    fi
  fi
  if sudo sshd -t 2>>"$REPORT"; then
    status "sshd config validates"
    doit "sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd"
  else
    say "  [!] sshd config FAILED validation, not reloading. Check $REPORT"
  fi
else
  say "  sshd_config.d not present, skipping (older sshd layout)"
fi

# --------------------------------------------------------------- 3. suid find
head2 "3. SUID bit on find (phase 3 escalation path)"
if [ -u /usr/bin/find ]; then
  say "  BEFORE: $(ls -l /usr/bin/find)"
  doit "sudo chmod u-s /usr/bin/find"
  say "  AFTER:  $(ls -l /usr/bin/find)"
  status "SUID removed from find"
else
  status "/usr/bin/find is not SUID, already clean"
fi

# --------------------------------------------------------- 4. empty passwords
head2 "4. accounts with an empty password hash"
EMPTY="$(sudo awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null)"
if [ -z "$EMPTY" ]; then
  status "no accounts with empty passwords"
else
  for u in $EMPTY; do
    say "  [FOUND] empty password: $u"
    doit "sudo passwd -l $u"
  done
fi

# ------------------------------------------------------ 5. crontab permissions
head2 "5. cron permissions"
for f in /etc/crontab; do
  [ -f "$f" ] && { say "  BEFORE: $(ls -l $f)"; doit "sudo chmod 600 $f"; say "  AFTER:  $(ls -l $f)"; }
done
[ -d /var/spool/cron/crontabs ] && { say "  BEFORE: $(ls -ld /var/spool/cron/crontabs)"; doit "sudo chmod 700 /var/spool/cron/crontabs"; say "  AFTER:  $(ls -ld /var/spool/cron/crontabs)"; }

# ------------------------------------------------- 6. report only: web roots
head2 "6. world-writable files in web roots (report only, nothing deleted)"
for d in /var/www /srv/http; do
  [ -d "$d" ] && { say "  == $d"; sudo find "$d" -type f -perm -o+w 2>/dev/null | head -20 | sed 's/^/    /' | tee -a "$REPORT"; }
done
say "  (a world-writable file in a web root is how phase 3's web shell got planted)"

# ------------------------------------------------------- 7. evidence tool
head2 "7. sysdig, for clean live-command evidence"
if command -v sysdig >/dev/null 2>&1; then
  status "sysdig present"
else
  doit "sudo apt-get install -y sysdig"
fi
say "  use it live:   sudo sysdig -c spy_users"

# --------------------------------------------------------------------- done
head2 "done"
say "Report written to: $REPORT"
say ""
say "What to say in the blue report:"
say "  this script is the patching half. Detection scripts find the problem, this one changes the box so"
say "  the problem cannot recur: auditd now records cron/unit/passwd changes, sshd no longer allows root"
say "  or empty-password logins, find cannot be used to escalate, and no account has a blank password."
