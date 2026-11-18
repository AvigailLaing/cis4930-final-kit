# CIS4930 Final Practical — Adversary Emulation & Detection Kit

Scripts and runbooks used during the CIS4930 (Cyber Adversarial Tradecraft) final practical.
Everything here runs **only** against machines inside our own NDG pod. Nothing targets a host
outside the reservation, and nothing destroys data.

Authors: Avigail Laing, Christian Taylor

## What is in here

```
red.sh                      one entry point for the offensive kit
blue.sh                     one entry point for the defensive kit
red/
  plant_linux.sh            five persistence mechanisms on Linux
  plant_windows.ps1         four persistence mechanisms on Windows
  loot_ad.sh                AD enumeration, writes ./loot/
  ad_chain.sh               password reset -> WriteDacl -> DCSync -> pass-the-hash
  linux_privesc.sh          rank local Linux escalation paths (sudo, SUID, caps, cron, units)
blue/
  baseline.sh               capture Linux state before the round
  baseline.ps1              capture Windows state before the round
  triage_linux.sh           diff live state against the baseline, flag the oddity
  sweep_linux.sh            find and remove common persistence (dry run by default)
  patch_linux.sh            apply the fixes: auditd, sshd, SUID find, empty passwords
  patch_windows.ps1         enable the audit policy that was missing, SMB signing, Sysmon
  lockdown.ps1              endgame: rogue admins, rogue tasks, Run keys, WMI subscriptions
  rotate_linux.sh           password rotation that classifies humans, daemons, services, rogues
  rotate_windows.ps1        same for Windows, and it knows local (SAM) from domain (AD)
  breakglass.sh/.ps1        our own documented recovery account, created in prep, removed at debrief
  evict.sh                  the response action: find a session by source IP, kill it, remove persistence, verify
  wazuh_local_rules.xml     17 custom detection rules
docs/                       runbooks, live cards, cheat sheet (PDF)
```

## Quick start

On the Kali pod machine:

```bash
git clone <this-repo-url> final-kit
cd final-kit

bash red.sh help        # offensive usage
bash blue.sh help       # defensive usage
```

The two dispatchers find their own directories, so they work from anywhere.

## Requirements mapping

| Assignment requirement | Fulfilled by |
|---|---|
| Red: 5+ separate techniques | `red/plant_linux.sh` (crontab, systemd user timer, .bashrc, authorized_keys, sudo user) and `red/plant_windows.ps1` (scheduled task, Run key, local admin, WMI subscription) |
| Red: 2+ attempts to take down a service | documented in `docs/RED_LIVE_CARD.pdf`, endgame section, with the four screenshots per attempt |
| Red: what we did to wipe a machine | documented in `docs/RED_LIVE_CARD.pdf`, wipe statement section |
| Blue: 5+ incidents | `blue/triage_linux.sh` findings, Autoruns, and Wazuh, logged in the four-field evidence format |
| Blue: how we dealt with password changes | `blue/rotate_linux.sh`, `blue/rotate_windows.ps1` (service accounts included, local vs domain handled), plus `docs/BLUE_LIVE_CARD.pdf` for what survived the rotation |
| Red: 2 Linux privesc methods | `red/linux_privesc.sh` ranks the candidates and prints the escalation command for each |
| Blue: 1 response action | `blue/evict.sh --from <red-ip> --apply` finds the session, kills it, removes persistence, verifies |
| Blue: recovery access | `blue/breakglass.sh`, `blue/breakglass.ps1`. Disclosed in the report and removed at the debrief |
| Blue: custom scripts to defend / automate patching | `blue/baseline*.{sh,ps1}`, `blue/triage_linux.sh`, `blue/sweep_linux.sh`, `blue/patch_linux.sh`, `blue/patch_windows.ps1`, `blue/wazuh_local_rules.xml` |

## Technique to detection map

See [TECHNIQUES.md](TECHNIQUES.md). Every offensive mechanism here is paired with the artefact a
defender would look for, because that pairing is what the reports are graded on.

## Addresses for the final

| Service | Address | Notes |
|---|---|---|
| Wazuh dashboard | https://172.16.10.254 | admin / Owls4TW*26. Agents connected, no Sysmon or auditd yet |
| Scoring engine | https://172.16.10.250:8443 | blueteam / twinpeaks1blue. Settings page holds the password per check |
| Both boxes | 172.16.10.0/24 | out of scope for red |

Custom rules: docs/WAZUH_RULES_DEPLOY.md (GUI first, CLI only if SSH works).

## Safety notes

- `sweep_linux.sh` is a dry run unless you pass `--remove`. Evidence first, deletion second.
- `patch_linux.sh` validates the sshd config with `sshd -t` before reloading, so a bad edit cannot
  lock out the team that is supposed to be defending the box.
- Nothing in this repo reboots, wipes, or shuts down a machine. No service that is being scored is
  stopped by any of the blue scripts.
- No credentials, keys, or passwords are committed here.

## Known environment assumptions

The scripts assume Debian/Ubuntu with systemd on the Linux side and Windows Server on the other.
`docs/PLAYBOOK.pdf` has a "reality check" page explaining how to confirm that and what to do when it
is not true (container without systemd, no auditd, no WinRM).
