<#
  baseline.ps1 — DC baselines. Run first, as Administrator, before anything else.

  Usage:
    powershell -ExecutionPolicy Bypass -File .\baseline.ps1
#>

$dir = "C:\blue_baseline"
New-Item -ItemType Directory -Force -Path $dir | Out-Null

Write-Output "[*] baselining into $dir"

Get-LocalUser           | Out-File "$dir\users.txt"     -Encoding utf8
Get-LocalGroupMember Administrators |
                          Out-File "$dir\admins.txt"    -Encoding utf8
Get-ScheduledTask       | Select TaskName,TaskPath,State |
                          Out-File "$dir\tasks.txt"     -Encoding utf8
Get-Service             | Select Name,DisplayName,Status |
                          Out-File "$dir\services.txt"  -Encoding utf8
Get-CimInstance Win32_Process |
  Select Name,ProcessId,ParentProcessId,CommandLine |
                          Out-File "$dir\procs.txt"     -Encoding utf8
Get-NetTCPConnection -State Established,Listen |
  Select LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess,State |
                          Out-File "$dir\conn.txt"      -Encoding utf8
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" |
                          Out-File "$dir\runkey.txt"    -Encoding utf8
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" |
                          Out-File "$dir\runkey_user.txt" -Encoding utf8
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter   -ErrorAction SilentlyContinue |
                          Out-File "$dir\wmi_filters.txt"   -Encoding utf8
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue |
                          Out-File "$dir\wmi_consumers.txt" -Encoding utf8
(Get-Date).ToString() + "  " + (whoami) |
                          Out-File "$dir\stamp.txt"     -Encoding utf8

Write-Output "[+] saved:"
Get-ChildItem $dir | Select Name,Length | Format-Table

Write-Output ""
Write-Output "Diff later with:"
Write-Output "  Compare-Object (Get-Content $dir\admins.txt) (Get-LocalGroupMember Administrators | Out-String -Stream)"
Write-Output "  Compare-Object (Get-Content $dir\runkey.txt) (reg query 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run')"
Write-Output ""
Write-Output "Keep open all round:"
Write-Output "  C:\Tools\Sysinternals Suite\Autoruns64.exe   (Logon, Scheduled Tasks, WMI tabs)"
Write-Output "  C:\Tools\Sysinternals Suite\TCPView.exe"
Write-Output ""
Write-Output "Honeyfile idea:"
Write-Output "  'domain_admin: Summer2026!' | Out-File C:\Users\Administrator\Desktop\passwords.txt"
Write-Output "  then watch Sysmon event 11/1 for anything touching that path"
