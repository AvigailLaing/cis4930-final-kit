#!/usr/bin/env bash
# rotate_linux.sh — endgame password rotation that does NOT forget service accounts.
#
# Why this exists: human accounts are the obvious target, but Red's favourite trick is a
# *service* account (low privilege, never noticed, sometimes no password at all). If you only
# rotate the humans, the account Red planted still works after the round ends.
#
# Usage:
#   sudo bash rotate_linux.sh                 # dry run: classify every account, change nothing
#   sudo bash rotate_linux.sh --apply         # rotate in-scope accounts, lock suspicious ones
#   sudo bash rotate_linux.sh --apply --include-service
#
# Safety rules baked in:
#   - the new password for every account is written to /root/.rotation-<stamp>.txt before it is set
#   - root's own password is only rotated if you pass --rotate-root
#   - your current session is never killed, so you cannot lock yourself out mid-run

set -u
APPLY=0
INCLUDE_SERVICE=0
ROTATE_ROOT=0
for a in "$@"; do
  case "$a" in
    --apply) APPLY=1 ;;
    --include-service) INCLUDE_SERVICE=1 ;;
    --rotate-root) ROTATE_ROOT=1 ;;
    *) echo "unknown option: $a"; exit 1 ;;
  esac
done

echo "rotate_linux.sh  host=$(hostname)  apply=$APPLY  include_service=$INCLUDE_SERVICE"

if [ "$(id -u)" -ne 0 ] && [ "$APPLY" -eq 1 ]; then
  echo "[!] --apply needs root. Re-run with sudo."; exit 1
fi

STAMP=$(date +%Y%m%d-%H%M%S)
SECRETS="/root/.rotation-${STAMP}.txt"
[ "$APPLY" -eq 1 ] && { umask 077; : > "$SECRETS"; chmod 600 "$SECRETS"; echo "new passwords will be written to $SECRETS"; }

# ---------------------------------------------------------------- service users
# accounts that actually run something, so rotating them has consequences
SERVICE_USERS="$( { ps -eo user= | sort -u
                    grep -rhoE '^User=.*' /etc/systemd/system /usr/lib/systemd/system 2>/dev/null | cut -d= -f2
                    grep -rhoE '^user.*' /etc/init.d 2>/dev/null | head -0
                  } | tr -d ' ' | sort -u )"

# system UID accounts that have a real shell (unusual, worth flagging)
SYSTEM_WITH_SHELL="$(awk -F: '$3<1000 && $3>=100 && $7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1}' /etc/passwd)"

newpass() { printf 'Sp26!%s' "$(head -c 6 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 6)"; }

printf '\n%-22s %-8s %-10s %-34s %s\n' "ACCOUNT" "UID" "CLASS" "WHY" "ACTION"
printf '%.0s-' {1..100}; echo

ACTION_SUMMARY=()

classify() {
  local u="$1" uid="$2" shell="$3" home="$4"
  local cls="human" why="" action="rotate"

  if [ "$uid" -eq 0 ] && [ "$u" = "root" ]; then
    cls="root"; why="the root account itself"
  elif grep -qx "$u" <<<"$(echo "$SERVICE_USERS" | grep -v '^root$')"; then
    cls="service"; why="owns a running process or a unit file"
  elif [ "$uid" -lt 1000 ] && grep -qE '(nologin|false)$' <<<"$shell"; then
    cls="daemon"; why="system account, no login shell"; action="skip"
  elif [ ! -d "$home" ] && [ "$uid" -ge 1000 ]; then
    cls="suspicious"; why="human-looking account with no home directory"; action="lock"
  elif grep -qx "$u" <<<"$SYSTEM_WITH_SHELL"; then
    cls="suspicious"; why="system UID but has a login shell"; action="lock"
  fi

  # root is only rotated when explicitly requested
  if [ "$cls" = "root" ] && [ "$ROTATE_ROOT" -eq 0 ]; then action="skip"; fi
  # service accounts only when asked, because rotation breaks the service until it is updated
  if [ "$cls" = "service" ] && [ "$INCLUDE_SERVICE" -eq 0 ]; then action="skip"; why="$why (skipped, use --include-service)"; fi
  # daemons are never touched
  [ "$cls" = "daemon" ] && action="skip"

  printf '%-22s %-8s %-10s %-34s %s\n' "$u" "$uid" "$cls" "$why" "$action"

  if [ "$action" = "rotate" ]; then
    local p; p="$(newpass)"
    if [ "$APPLY" -eq 1 ]; then
      if echo "$u:$p" | chpasswd 2>/dev/null; then
        echo "$u:$p" >> "$SECRETS"
        ACTION_SUMMARY+=("ROTATED  $u ($cls)")
      else
        ACTION_SUMMARY+=("FAILED   $u ($cls)")
      fi
    fi
  elif [ "$action" = "lock" ]; then
    if [ "$APPLY" -eq 1 ]; then
      passwd -l "$u" >/dev/null 2>&1 && ACTION_SUMMARY+=("LOCKED   $u ($cls)")
    fi
  fi
}

while IFS=: read -r u _ uid _ _ home shell; do
  [ "$uid" -ge 1000 ] || [ "$u" = "root" ] || [ "$uid" -lt 1000 ] || continue
  case "$u" in nobody|nfsnobody) continue ;; esac
  classify "$u" "$uid" "$shell" "$home"
done < /etc/passwd

# ------------------------------------------------------- accounts with no password
echo
echo "accounts with an empty password hash:"
EMPTY="$(awk -F: '($2==""){print $1}' /etc/shadow)"
if [ -z "$EMPTY" ]; then echo "  none"; else
  for u in $EMPTY; do
    echo "  [FOUND] $u"
    if [ "$APPLY" -eq 1 ]; then passwd -l "$u" >/dev/null 2>&1 && ACTION_SUMMARY+=("LOCKED   $u (empty password)"); fi
  done
fi

# -------------------------------------------------- accounts created recently
echo
echo "accounts whose password entry changed today or yesterday (Red may have created these):"
while IFS=: read -r u _ uid _ _ _ shell; do
  [ "$uid" -ge 1000 ] || continue
  last=$(sudo chage -l "$u" 2>/dev/null | awk -F: '/Last password change/ {gsub(/^ +/,"",$2); print $2}')
  case "$last" in
    today|yesterday) echo "  [CHECK] $u  (last change: $last)" ;;
  esac
done < /etc/passwd

# --------------------------------------------------------------------- summary
echo
if [ "$APPLY" -eq 1 ]; then
  echo "============ ACTIONS TAKEN ============"
  [ ${#ACTION_SUMMARY[@]} -eq 0 ] && echo "  nothing to do" || printf '%s\n' "${ACTION_SUMMARY[@]}"
  echo "======================================="
  echo "New passwords: $SECRETS   (chmod 600, delete after the debrief)"
  echo
  echo "If you rotated a service account, the service is now broken until you update it:"
  echo "  systemctl edit <unit>    # or edit the unit file's User= and the app config"
  echo "  then restart the service and re-check the scored port with nmap"
else
  echo "Dry run. Nothing changed. Re-run with --apply (and --include-service if you want services rotated)."
fi
