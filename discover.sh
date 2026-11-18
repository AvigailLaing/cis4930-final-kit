#!/usr/bin/env bash
# discover.sh — find the targets and work out what they are, before you type anything else.
#
# Because the final will NOT reuse the mock's addresses, passwords or service values, every other
# script takes its targets as arguments. This one produces those arguments.
#
# Usage:
#   bash discover.sh                 # sweeps your local /24
#   bash discover.sh 172.16.10.0/24  # or name the subnet
#
# Output: ./targets.env, ready to source:
#   source ./targets.env
#   echo $PD_IP $DC_IP

set -u
SUBNET="${1:-}"

if [ -z "$SUBNET" ]; then
  SUBNET="$(ip route 2>/dev/null | awk '/172\.16|10\./ && /proto kernel/ {print $1}' | head -1)"
fi
[ -z "$SUBNET" ] && SUBNET="172.16.10.0/24"

echo "=== discover.sh ==="
echo "subnet: $SUBNET"
echo "my ip : $(ip -4 addr show scope global 2>/dev/null | awk '/inet /{print $2}' | head -3 | tr '\n' ' ')"

if ! command -v nmap >/dev/null 2>&1; then
  echo "[!] nmap missing. Install it, or fall back to: for i in $(seq 1 254); do ping -c1 -W1 172.16.10.\$i; done"
  exit 1
fi

echo
echo "--- live hosts ---"
HOSTS="$(nmap -sn "$SUBNET" 2>/dev/null | awk '/Nmap scan report/ {print $NF}' | tr -d '()')"
echo "$HOSTS" | sed 's/^/  /'
[ -z "$HOSTS" ] && { echo "  none found. Wrong subnet, or the pod is not up."; exit 1; }

# ports that matter: the scored ones, plus the usual ways in
PORTS="0,21,22,53,80,389,443,445,3389,5985,8080,8443"

echo
echo "--- fingerprint ($PORTS) ---"
PD=""; DC=""; SCORING=""; WAZUH=""

for h in $HOSTS; do
  case "$h" in
    *.254) WAZUH="$h"; echo "  $h  WAZUH (out of scope for red)"; continue ;;
    *.250) SCORING="$h"; echo "  $h  SCORING (out of scope for red)"; continue ;;
  esac
  OUT="$(nmap -Pn -T4 -p "$PORTS" "$h" 2>/dev/null)"
  OPEN="$(echo "$OUT" | awk '/open/ {print $1}' | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')"
  [ -z "$OPEN" ] && continue

  # classify by the ports that are open
  if echo "$OPEN" | grep -qE '(^|,)(53|389|445|3389|5985)(,|$)'; then
    KIND="WINDOWS / DOMAIN CONTROLLER"
    [ -z "$DC" ] && DC="$h"
  elif echo "$OPEN" | grep -qE '(^|,)(22|21)(,|$)'; then
    KIND="LINUX"
    [ -z "$PD" ] && PD="$h"
  else
    KIND="unknown"
  fi
  echo "  $h  $KIND   open: $OPEN"
done

echo
echo "--- what to do with each ---"
[ -n "$PD" ] && echo "  PD  ($PD): scored FTP 21, SSH 22, Web 80. Spray the default password, then privesc."
[ -n "$DC" ] && echo "  DC  ($DC): scored DNS 53, LDAP 389, maybe WinRM/RDP. Spray, then AD work."
[ -n "$SCORING" ] && echo "  scoring engine: https://$SCORING:8443 (blueteam / twinpeaks1blue)"
[ -n "$WAZUH" ] && echo "  wazuh:          https://$WAZUH (admin / Owls4TW*26)"

cat > ./targets.env <<EOF
# generated $(date) by discover.sh — source this, do not hardcode addresses
export PD_IP=${PD:-CHANGEME}
export DC_IP=${DC:-CHANGEME}
export SCORING_IP=${SCORING:-172.16.10.250}
export WAZUH_IP=${WAZUH:-172.16.10.254}
EOF

echo
echo "--- written to ./targets.env ---"
cat ./targets.env
echo
echo "Then:  source ./targets.env"
echo "       ssh <user>@\$PD_IP                        # default password announced at the start"
echo "       bash red.sh plant \$PD_IP 4444 <user> ~/id_rsa.pub"
echo
echo "Reminder: the final does NOT reuse the mock's values. Re-run this in each round, because the pod"
echo "resets between them and addresses can move."
