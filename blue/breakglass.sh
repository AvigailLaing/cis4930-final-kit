#!/usr/bin/env bash
# breakglass.sh — Blue team's own way back in.
#
# Why: at endgame you rotate passwords. If Red still holds a session, or if you get kicked out
# mid-cleanup, an account you control plus a key you hold means you are never locked out of the
# host you are defending. This is normal blue-team practice, and it is also the first thing you
# delete during the debrief and the first thing you disclose in the report.
#
# Usage:
#   sudo bash breakglass.sh --create     # create the account and a key, print the credentials
#   sudo bash breakglass.sh --verify     # prove the key still gets in
#   sudo bash breakglass.sh --remove     # delete account, key and credential file (debrief)
#
# Rules of engagement, so nobody reads this as cheating:
#   - the name is obvious on purpose: svc_brkglass, never something that looks like a daemon
#   - disclose it in the blue report: our own recovery account, created in prep, removed at debrief
#   - remove it before the round is scored as finished

set -u
ACTION="${1:---create}"
# Accept both "create" and "--create", so the dispatcher form works:
#   bash blue.sh breakglass create
case "$ACTION" in create|verify|remove) ACTION="--$ACTION" ;; esac
USER_NAME="svc_brkglass"
KEY="/root/.ssh/brkglass_ed25519"
SECRETS="/root/.brkglass-credentials.txt"

newpass() { printf 'Bg26!%s' "$(head -c 8 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 8)"; }

case "$ACTION" in
  --create)
    [ "$(id -u)" -eq 0 ] || { echo "[!] run with sudo"; exit 1; }

    if id "$USER_NAME" >/dev/null 2>&1; then
      echo "[i] $USER_NAME already exists"
      PASS="$(awk -F: -v u="$USER_NAME" '$1==u {print $2}' "$SECRETS" 2>/dev/null)"
      if [ -z "${PASS:-}" ]; then PASS="$(newpass)"; echo "$USER_NAME:$PASS" >> "$SECRETS"; fi
    else
      PASS="$(newpass)"
      useradd -m -s /bin/bash "$USER_NAME"
      echo "$USER_NAME:$PASS" | chpasswd
      usermod -aG sudo "$USER_NAME" 2>/dev/null || usermod -aG wheel "$USER_NAME"
      umask 077; echo "$USER_NAME:$PASS" >> "$SECRETS"; chmod 600 "$SECRETS"
      echo "[CREATED] $USER_NAME with sudo, password recorded in $SECRETS"
    fi

    # a key you hold, so a rotation on the other side does not lock you out
    mkdir -p /root/.ssh
    [ -f "$KEY" ] || ssh-keygen -t ed25519 -N '' -C "brkglass" -f "$KEY" >/dev/null
    install -d -m 700 -o "$USER_NAME" -g "$USER_NAME" "/home/$USER_NAME/.ssh"
    cat "$KEY.pub" >> "/home/$USER_NAME/.ssh/authorized_keys"
    chown "$USER_NAME:$USER_NAME" "/home/$USER_NAME/.ssh/authorized_keys"
    chmod 600 "/home/$USER_NAME/.ssh/authorized_keys"
    echo "[KEY] private key: $KEY"

    # the same key on the account you are using now, in case that password gets rotated
    for h in /root /home/*; do
      [ -d "$h/.ssh" ] || continue
      grep -qF "$(cat "$KEY.pub")" "$h/.ssh/authorized_keys" 2>/dev/null || \
        { cat "$KEY.pub" >> "$h/.ssh/authorized_keys"; echo "[KEY] added to $h/.ssh/authorized_keys"; }
    done

    echo
    echo "Copy the key off the box now, before you need it:"
    echo "  scp root@<this-host>:$KEY ./brkglass_ed25519"
    echo "  ssh -i brkglass_ed25519 $USER_NAME@<this-host>"
    echo
    echo "Add one line to the blue report about it, and run --remove at the debrief."
    ;;

  --verify)
    [ -f "$KEY" ] || { echo "[!] no key at $KEY"; exit 1; }
    echo "[*] key login as $USER_NAME against localhost"
    ssh -i "$KEY" -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=5 \
        "$USER_NAME@127.0.0.1" 'echo "[OK] in as $(id -un)"' \
      || echo "[!] key login failed, check sshd and authorized_keys permissions"
    ;;

  --remove)
    [ "$(id -u)" -eq 0 ] || { echo "[!] run with sudo"; exit 1; }
    userdel -r "$USER_NAME" 2>/dev/null && echo "[REMOVED] account $USER_NAME"
    for h in /root /home/*; do
      [ -f "$h/.ssh/authorized_keys" ] || continue
      grep -v 'brkglass' "$h/.ssh/authorized_keys" > "$h/.ssh/.ak.tmp" 2>/dev/null && \
        mv "$h/.ssh/.ak.tmp" "$h/.ssh/authorized_keys"
    done
    rm -f "$KEY" "$KEY.pub" "$SECRETS"
    echo "[REMOVED] key and credential file"
    echo "Say it in the debrief: the recovery account existed and has been deleted."
    ;;

  *)
    echo "usage: bash breakglass.sh --create | --verify | --remove"
    ;;
esac
