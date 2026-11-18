#!/usr/bin/env bash
# blue.sh — one entry point for the blue kit. No arguments prints this.
#
#   bash blue.sh baseline [user]      # capture users, cron, units, keys, listeners, procs
#   bash blue.sh triage   [user]      # what changed since baseline, read only
#   bash blue.sh sweep                # dry run, shows persistence it would remove
#   bash blue.sh sweep --remove       # actually remove it
#   bash blue.sh patch                # auditd, sshd hardening, SUID find, empty passwords
#   bash blue.sh patch --dry-run      # show what patching would change
#
# Windows runs inside an admin session on the DC:
#   .\blue\baseline.ps1
#   .\blue\patch_windows.ps1
#   .\blue\lockdown.ps1 -NewAdminPass 'N3wPass!2026'

set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
cmd="${1:-help}"
[ $# -gt 0 ] && shift

case "$cmd" in
  baseline|base)
    exec bash "$DIR/blue/baseline.sh" "$@"
    ;;
  triage|check)
    exec bash "$DIR/blue/triage_linux.sh" "$@"
    ;;
  sweep|clean)
    exec bash "$DIR/blue/sweep_linux.sh" "$@"
    ;;
  patch|harden)
    exec bash "$DIR/blue/patch_linux.sh" "$@"
    ;;
  rotate|passwords)
    exec bash "$DIR/blue/rotate_linux.sh" "$@"
    ;;
  breakglass|recovery)
    exec bash "$DIR/blue/breakglass.sh" "$@"
    ;;
  evict|kick)
    exec bash "$DIR/blue/evict.sh" "$@"
    ;;
  discover|find)
    exec bash "$DIR/discover.sh" "$@"
    ;;
  win|windows)
    cat <<'EOF'
Windows side runs on the DC, in an admin session:

  .\blue\baseline.ps1                         # prep, first thing
  .\blue\patch_windows.ps1                    # prep, then never again
  .\blue\lockdown.ps1 -NewAdminPass '...'     # endgame only

Deploy the detection rules once, during prep:
  sudo cp blue/wazuh_local_rules.xml /var/ossec/etc/rules/final_custom_rules.xml
  sudo /var/ossec/bin/wazuh-analysisd -t
  sudo /var/ossec/bin/wazuh-control restart
EOF
    ;;
  help|*)
    cat <<'EOF'
blue.sh — blue kit entry point

  bash blue.sh baseline [user]     state snapshot: users, groups, cron, units,
                                   keys, listeners, processes, sudoers
  bash blue.sh triage   [user]     diffs live state against that snapshot and
                                   flags odd processes, new units, recent files
  bash blue.sh sweep               dry run: finds the common persistence
  bash blue.sh sweep --remove      removes it, after you screenshot the evidence
  bash blue.sh patch               applies fixes: auditd + ruleset, sshd hardening,
                                   SUID off find, lock empty-password accounts
  bash blue.sh patch --dry-run     shows what patching would change
  bash blue.sh rotate              classify every account, service accounts included
  bash blue.sh rotate --apply --include-service   rotate, including services
  bash blue.sh breakglass create   your own documented way back in
  bash blue.sh evict --from <RED_IP> [--apply]   the response action: find them, throw them out, verify
  bash blue.sh win                 the Windows reminders

Order in the round: baseline (prep) -> patch (prep) -> triage every 2 minutes
                    -> sweep when you find something -> lockdown at minute 20
EOF
    ;;
esac
