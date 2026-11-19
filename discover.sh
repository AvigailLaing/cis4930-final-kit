#!/usr/bin/env bash
# discover.sh — find the targets. Run ON KALI, first thing in every round.
#
# Fixes since the first version:
#   - it used to scan whatever the default route said, which on this Kali is 10.0.0.0/8 and
#     hung for a minute. It now scans the /24 around your own address, plus 172.16.10.0/24,
#     and refuses to scan anything wider than a /24.
#   - per-host timeouts, so one dead host cannot stall the sweep.
#
# Usage:
#   bash discover.sh                    # local /24 plus 172.16.10.0/24
#   bash discover.sh 172.16.10.0/24     # one specific subnet
#   bash discover.sh --fast             # skip the version scan, ports only

set -u

WANT_FAST=0
SUBNETS=()
for a in "$@"; do
  case "$a" in
    --fast) WANT_FAST=1 ;;
    */*)    SUBNETS+=("$a") ;;
    *)      echo "unknown argument: $a"; exit 1 ;;
  esac
done

# never scan wider than a /24: this is the bug that made it look hung
narrow() {
  case "$1" in
    */8|*/9|*/10|*/11|*/12|*/13|*/14|*/15|*/16|*/17|*/18|*/19|*/20|*/21|*/22|*/23)
      echo "$1" | awk -F'[./]' '{printf "%s.%s.%s.0/24\n", $1, $2, $3}' ;;
    *) echo "$1" ;;
  esac
}

if [ ${#SUBNETS[@]} -eq 0 ]; then
  MY_IP="$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | head -1 | cut -d/ -f1)"
  if [ -n "${MY_IP:-}" ]; then
    SUBNETS+=("$(echo "$MY_IP" | awk -F. '{print $1"."$2"."$3".0/24}')")
  fi
  SUBNETS+=("172.16.10.0/24")
fi

echo "=== discover.sh ==="
echo "my ip : $(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | tr '\n' ' ')"
echo "scan  : ${SUBNETS[*]}"
command -v nmap >/dev/null 2>&1 || { echo "[!] nmap missing"; exit 1; }

PORTS="0,21,22,53,80,389,443,445,3389,5985,8080,8443"
ALLHOSTS=""

for net in "${SUBNETS[@]}"; do
  net="$(narrow "$net")"
  echo
  echo "--- sweep $net (max 20s per host) ---"
  H="$(nmap -sn --max-retries 1 --host-timeout 15s "$net" 2>/dev/null \
        | awk '/Nmap scan report/ {print $NF}' | tr -d '()')"
  if [ -z "$H" ]; then echo "  no hosts"; continue; fi
  echo "$H" | sed 's/^/  up: /'
  ALLHOSTS="$ALLHOSTS $H"
done

PD=""; DC=""; SCORING=""; WAZUH=""
echo
echo "--- classify and fingerprint ---"
for h in $(echo "$ALLHOSTS" | tr ' ' '\n' | sort -u); do
  case "$h" in
    *.254) WAZUH="$h";   echo "  $h  WAZUH (out of scope for red)"; continue ;;
    *.250) SCORING="$h"; echo "  $h  SCORING (out of scope for red)"; continue ;;
  esac
  if [ "$WANT_FAST" -eq 1 ]; then
    OUT="$(nmap -Pn -T4 --max-retries 1 --host-timeout 30s -p "$PORTS" "$h" 2>/dev/null)"
  else
    OUT="$(nmap -Pn -T4 --max-retries 1 --host-timeout 60s -sV --version-light -p "$PORTS" "$h" 2>/dev/null)"
  fi
  OPEN="$(echo "$OUT" | awk '/open/ {print $1}' | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')"
  [ -z "$OPEN" ] && continue

  if echo "$OPEN" | grep -qE '(^|,)(53|389|445|3389|5985)(,|$)'; then
    KIND="WINDOWS / DC"; [ -z "$DC" ] && DC="$h"
  elif echo "$OPEN" | grep -qE '(^|,)(22|21)(,|$)'; then
    KIND="LINUX"; [ -z "$PD" ] && PD="$h"
  else
    KIND="unknown"
  fi
  echo "  $h  $KIND   open: $OPEN"
done

echo
echo "--- what to do with each ---"
[ -n "$PD" ] && echo "  PD ($PD): scored FTP 21, SSH 22, Web 80"
[ -n "$DC" ] && echo "  DC ($DC): scored DNS 53, LDAP 389, maybe WinRM 5985 / RDP 3389"
[ -n "$SCORING" ] && echo "  scoring engine: https://$SCORING:8443"
[ -n "$WAZUH" ] && echo "  wazuh:          https://$WAZUH"

cat > ./targets.env <<EOF
# generated $(date) by discover.sh
export PD_IP=${PD:-CHANGEME}
export DC_IP=${DC:-CHANGEME}
export SCORING_IP=${SCORING:-172.16.10.250}
export WAZUH_IP=${WAZUH:-172.16.10.254}
EOF

echo
echo "--- ./targets.env ---"
cat ./targets.env
echo
echo "Then:  source ./targets.env"
echo "       ssh <user>@\$PD_IP            # default password announced at the start"
echo
echo "These scripts run ON THE TARGET, not on Kali. Copy the kit over first:"
echo "       scp -r . \$PD_IP:/tmp/final-kit"
echo "       ssh \$PD_IP 'cd /tmp/final-kit && bash blue.sh baseline'"
