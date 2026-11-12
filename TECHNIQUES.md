# Technique -> artefact map

One row per technique. "Look for" is what a defender has to inspect to catch it, which is the column
both reports are built on.

## Offensive, planted by this kit

| Technique | Lab origin | Implemented by | Trigger | Look for (defender) |
|---|---|---|---|---|
| User crontab reverse shell (T1053.003) | Phase 3, intermission | `red/plant_linux.sh` | every 2 min | `crontab -l`, auditd key `cron`, `/var/spool/cron` |
| systemd user service + timer (T1053.006) | Intermission field guide | `red/plant_linux.sh` | 1 min after boot | `systemctl --user list-timers --all`, `~/.config/systemd/user`, auditd key `systemd` |
| Shell profile persistence (T1546.004) | Phase 3 | `red/plant_linux.sh` | on login | auditd key `user_profile`, `.bashrc` mtime |
| SSH authorized_keys (T1098.004) | Phase 3 | `red/plant_linux.sh` | any login | auditd key `user_ssh`, `find /home -name authorized_keys` |
| Rogue local sudo user (T1136.001) | Intermission | `red/plant_linux.sh` | on demand | `/etc/passwd` diff, `getent group sudo`, auditd key `etcpasswd` |
| Scheduled task (T1053.005) | Intermission, malware lab 2 | `red/plant_windows.ps1` | every 2 min | Event 4698, Autoruns Scheduled Tasks |
| Registry Run key (T1547.001) | Intermission, malware lab 2 | `red/plant_windows.ps1` | at logon | Sysmon 13, Autoruns Logon |
| Rogue local admin (T1136.001) | Intermission | `red/plant_windows.ps1` | on demand | 4720 + 4732, `Get-LocalGroupMember` |
| WMI event subscription (T1546.003) | Intermission, malware lab 2 | `red/plant_windows.ps1` | after boot | Sysmon 19-21, Autoruns WMI tab |
| Kerberoasting (T1558.003) | Phase 4 | `red/loot_ad.sh` | on demand | 4769 with 0x17 encryption type |
| AS-REP roasting (T1558.004) | Phase 4 extra credit | `red/loot_ad.sh` | on demand | 4768 with no preauth |
| ACL abuse: ForceChangePassword (T1098) | Phase 4, path C | `red/ad_chain.sh` | on demand | 4724 by an account that is not help desk |
| ACL abuse: WriteDacl -> DCSync (T1003.006) | Phase 4, path C | `red/ad_chain.sh` | on demand | 4662 with replication GUIDs, 4724 |
| Pass-the-hash (T1550.002) | Phase 4 | `red/ad_chain.sh` output | on demand | 4624 type 3 over NTLM from a non-domain host |
| ADCS ESC1 certificate request (T1649) | Phase 4, path B | `red/loot_ad.sh` step 6 | on demand | enrolment events on the CA, 4886/4887 |
| Shell history suppression (T1070.003) | Intermission | manual, one line | at login | missing history for a session that clearly existed |
| Timestomping (T1070.006) | Intermission | manual | on demand | auditd key `T1070_006_timestomp`, file mtime vs ctime |
| Service denial at endgame | Intermission | manual, see red live card | endgame | the scoring engine, plus 7034 / stopped-service events |

## Defensive, implemented by this kit

| Technique | Lab origin | Implemented by | What it catches |
|---|---|---|---|
| State baseline and diff | Intermission field guide | `blue/baseline.sh`, `blue/triage_linux.sh` | any new user, unit, key, listener, process |
| auditd ruleset + custom watches | Malware lab 2, intermission | `blue/patch_linux.sh` | changes to cron, units, passwd, sudoers, home dirs |
| Honeyfile with a read watch | Intermission field guide | `blue/baseline.sh` output | anyone reading a decoy credential file |
| Remove persistence, then verify | Intermission | `blue/sweep_linux.sh` | cron, timers, profile edits, SSH keys, tmp payloads |
| sshd hardening | Phase 1 remediation | `blue/patch_linux.sh` | root login, empty passwords, brute force |
| Remove SUID from find | Phase 3 | `blue/patch_linux.sh` | the exact escalation used in phase 3 |
| Enable account management auditing | Phase 4 (the gap we found) | `blue/patch_windows.ps1` | 4724 password resets, previously invisible |
| Force SMB signing, disable SMBv1 | Phase 4 TA notes | `blue/patch_windows.ps1` | relay attacks |
| Custom Wazuh rules | Phase 4 objective 5 | `blue/wazuh_local_rules.xml` | 4720, 4732, 4698, 7045, Sysmon 13, 19-21, 4662, 4769, 4724, 1102, auditd keys |
| Endgame lockdown | Intermission | `blue/lockdown.ps1` | rogue admins, tasks, Run keys, WMI subscriptions |

## Things that were tried and failed, worth writing about

- SMB relay after coercion: the DC enforces SMB signing, so the relay dies. Good "we tested it and
  here is why it failed" paragraph.
- Wazuh custom rule with `decoded_as json`: never matched Windows events. The parent id has to come
  from `wazuh-logtest` on a real event, not from guessing.
