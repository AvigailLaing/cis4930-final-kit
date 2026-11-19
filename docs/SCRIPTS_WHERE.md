# Which script runs on which machine

This is the mistake that wastes the most time: half the kit runs on **Kali**, half runs on the
**target box**. Running a target-side script on Kali does not error, it just inspects the wrong machine.

| Script | Runs on | Answers |
|---|---|---|
| `discover.sh` | Kali | which boxes exist, what ports, writes targets.env |
| `red.sh recon` | Kali | AD enumeration against the DC over the network |
| `red.sh chain` | Kali | reset a password, grant replication, dump a hash |
| `red.sh plant` | **the PD** (ssh in first) | five persistence mechanisms on Linux |
| `plant_windows.ps1` | **the DC** (evil-winrm upload) | four persistence mechanisms on Windows |
| `red.sh privesc` | **the PD** | local escalation paths |
| `blue.sh baseline` | **the PD** | state snapshot |
| `blue.sh patch` | **the PD** | auditd, sshd, SUID find, sysdig |
| `blue.sh triage` | **the PD** | what changed since baseline |
| `blue.sh sweep` | **the PD** | find and remove persistence |
| `blue.sh evict` | **the PD** | kill sessions from an IP, remove persistence, verify |
| `blue.sh rotate` | **the PD** | rotate Linux accounts |
| `baseline.ps1`, `patch_windows.ps1`, `lockdown.ps1`, `rotate_windows.ps1` | **the DC** | the Windows half |
| `breakglass.sh` / `.ps1` | each host, in prep | your own recovery account |
| `wazuh_local_rules.xml` | the Wazuh dashboard (GUI) | detections |

## Getting the kit onto the target

```bash
source ./targets.env
scp -r ~/final-kit "$PD_IP:/tmp/final-kit"          # Linux side
ssh "$PD_IP" 'cd /tmp/final-kit && bash blue.sh baseline && sudo bash blue.sh patch'
```

Windows side, inside evil-winrm:

```
upload /home/agentcooper/final-kit/blue/baseline.ps1 C:\ProgramData\baseline.ps1
powershell -ep bypass C:\ProgramData\baseline.ps1
```

## "They are actively attacking me, what do I run?"

In this order, on the PD (or the DC equivalent):

1. `bash blue.sh triage brief` — lists only the findings, not the noise. Screenshot it.
2. Note the four fields for anything real: IOC / WHERE / TOOL / TIME.
3. `bash blue.sh sweep` — dry run, shows what it would remove. Screenshot.
4. `bash blue.sh sweep --remove` — removes it.
5. `bash blue.sh evict --from <RED_IP> --apply` — only if there are live sessions to kill.
6. `ss -tupn ; crontab -l ; systemctl list-timers --all` — verify, then look again in two minutes.

## Reading triage output

It is deliberately verbose because the report needs evidence, but you do not read all of it.
Read the lines starting with `[!!]`, and the section headers `---- ... ----`. Everything else is context
you only open when a `[!!]` line needs explaining.
