#!/usr/bin/env bash
# baseline.sh — capture a "what normal looks like" snapshot in about 20 seconds.
# Run this FIRST, before you look at anything else. Every later question is a diff.
#
# Usage: bash baseline.sh [user]

set -u
U="${1:-$(id -un)}"
D="$HOME/blue_baseline"
mkdir -p "$D"

echo "[*] baselining user=$U into $D"

ss -tupn                                          > "$D/conn.txt"      2>/dev/null
getent passwd                                     > "$D/users.txt"     2>/dev/null
getent group                                      > "$D/groups.txt"    2>/dev/null
crontab -l                                        > "$D/cron.txt"      2>/dev/null
{ ls -la /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron/crontabs 2>/dev/null
  sudo crontab -l 2>/dev/null; }                  >> "$D/cron.txt"     2>/dev/null
{ systemctl list-unit-files --type=service,timer 2>/dev/null
  systemctl list-timers --all 2>/dev/null; }      >  "$D/units.txt"    2>/dev/null
systemctl --user list-timers --all 2>/dev/null    >  "$D/units_user.txt" 2>/dev/null
{ sudo find /home /root -name authorized_keys -exec ls -l {} + 2>/dev/null
  sudo find /home /root -name authorized_keys -exec cat {} + 2>/dev/null; } > "$D/keys.txt" 2>/dev/null
ps auxf                                           > "$D/procs.txt"     2>/dev/null
sudo ss -tulpn                                    > "$D/listeners.txt" 2>/dev/null
ls -la /tmp /var/tmp                              > "$D/tmp.txt"       2>/dev/null
sudo getent shadow -s 2>/dev/null | cut -d: -f1,2 > "$D/shadow_hashes.txt" 2>/dev/null
{ sudo grep -vE '^#|^$' /etc/sudoers 2>/dev/null; ls /etc/sudoers.d 2>/dev/null; } > "$D/sudoers.txt" 2>/dev/null
date                                              > "$D/stamp.txt"
who                                               >> "$D/stamp.txt"
last -a | head -10                                >> "$D/stamp.txt"

echo "[+] saved:"
ls -la "$D"
echo
echo "Diff against it later with:"
echo "  diff <(getent passwd)            $D/users.txt"
echo "  diff <(ss -tupn)                 $D/conn.txt"
echo "  diff <(systemctl list-timers --all) $D/units.txt"
echo
echo "Next, in order:"
echo "  sudo auditctl -R /opt/florian-roth-auditd.rules"
echo "  sudo auditctl -l | wc -l                      # want a few hundred"
echo "  sudo auditctl -w /home/$U/.ssh -p wa -k user_ssh"
echo "  sudo auditctl -w /home/$U/.bashrc -p wa -k user_profile"
echo "  sudo auditctl -w /home/$U/.config/systemd -p wa -k new_units"
echo "  sudo auditctl -w /tmp -p wa -k tmp_write"
echo "  echo 'db_admin: Summer2026!' | sudo tee /home/$U/Documents/passwords.txt"
echo "  sudo auditctl -w /home/$U/Documents/passwords.txt -p r -k honeyfile"
