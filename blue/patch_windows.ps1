<#
  patch_windows.ps1 — Blue's patching half on the DC. Idempotent, prints BEFORE/AFTER.

  Usage:
    powershell -ExecutionPolicy Bypass -File .\patch_windows.ps1
    powershell -ExecutionPolicy Bypass -File .\patch_windows.ps1 -DryRun

  Fixes, each tied to something from the labs:
    1. audit policy: turns ON the categories that were missing in phase 4,
       including account management, which is why the 4724 password reset was never logged
    2. command line in process creation, so 4688 is actually useful
    3. PowerShell script block logging
    4. SMB signing required, SMBv1 disabled
    5. Sysmon service running
    6. reports local admins and non-Microsoft tasks (fixing those is lockdown.ps1)
#>

param([switch]$DryRun)

$log = "C:\blue_baseline\patch_report_$(Get-Date -Format yyyyMMdd-HHmmss).txt"
New-Item -ItemType Directory -Force -Path "C:\blue_baseline" | Out-Null

function Say($m) { Write-Output $m; Add-Content -Path $log -Value $m }
function Step($m) { Say ""; Say ("=" * 60); Say "== $m"; Say ("=" * 60) }
function Act($what, $block) {
  if ($DryRun) { Say "  [DRY RUN] $what"; return }
  try { & $block; Say "  [DONE] $what" } catch { Say "  [FAILED] $what : $($_.Exception.Message)" }
}

Say "patch_windows.ps1  host=$env:COMPUTERNAME  dry_run=$DryRun  $(Get-Date)"

# ------------------------------------------------------------- 1. audit policy
Step "1. audit policy (the phase 4 gap: no account management auditing)"
$audit = @(
  "Account Logon",
  "Account Management",
  "Directory Service Access",
  "Logon/Logoff",
  "Policy Change",
  "Detailed Tracking",
  "Object Access"
)
Say "  BEFORE:"
(Get-Content $log -ErrorAction SilentlyContinue) | Out-Null
auditpol /get /category:* 2>$null | Select-String -Pattern "Account Management|Directory Service Access|Logon/Logoff" | ForEach-Object { Say ("    " + $_.Line.Trim()) }
foreach ($cat in $audit) {
  Act "auditpol enable '$cat' success+failure" {
    auditpol /set /category:"$cat" /success:enable /failure:enable | Out-Null
  }
}
Say "  AFTER:"
auditpol /get /category:* 2>$null | Select-String -Pattern "Account Management|Directory Service Access|Logon/Logoff" | ForEach-Object { Say ("    " + $_.Line.Trim()) }
Say "  -> Account Management is what logs 4724 password resets. Without it, the whole red chain is invisible."

# --------------------------------------------- 2. command line in 4688 events
Step "2. command line included in process creation events (4688)"
$p = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
Act "set ProcessCreationIncludeCmdLine_Enabled=1" {
  New-Item -Path $p -Force | Out-Null
  Set-ItemProperty -Path $p -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord
}
Say "  value: $((Get-ItemProperty -Path $p -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled)"

# ---------------------------------------------------------- 3. powershell logs
Step "3. PowerShell script block logging"
$ps = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
Act "enable ScriptBlockLogging" {
  New-Item -Path $ps -Force | Out-Null
  Set-ItemProperty -Path $ps -Name EnableScriptBlockLogging -Value 1 -Type DWord
}

# ------------------------------------------------------------------- 4. SMB
Step "4. SMB hardening"
$smb = Get-SmbServerConfiguration
Say "  BEFORE: signing required=$($smb.RequireSecuritySignature)  smb1=$($smb.EnableSMB1Protocol)"
Act "require SMB signing and disable SMBv1" {
  Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSMB1Protocol $false -Force
}
$smb = Get-SmbServerConfiguration
Say "  AFTER:  signing required=$($smb.RequireSecuritySignature)  smb1=$($smb.EnableSMB1Protocol)"
Say "  -> signing blocks relay attacks, which are the usual follow-on to a poisoned name resolution."

# ----------------------------------------------------------------- 5. Sysmon
Step "5. Sysmon service"
$sys = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
if ($null -eq $sys) { $sys = Get-Service -Name Sysmon -ErrorAction SilentlyContinue }
if ($null -eq $sys) {
  Say "  [!] Sysmon is NOT installed. The packet says it will not be, so install it now."
  $exe = $null
  foreach ($p in @("C:\Tools\Sysinternals Suite\Sysmon64.exe", "C:\Tools\Sysmon\Sysmon64.exe", "C:\ProgramData\Sysmon64.exe")) {
    if (Test-Path $p) { $exe = $p; break }
  }
  if (-not $exe) {
    Act "download Sysmon from Sysinternals" {
      $zip = "$env:TEMP\Sysmon.zip"
      Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $zip -UseBasicParsing
      Expand-Archive -Path $zip -DestinationPath "C:\Tools\Sysmon" -Force
    }
    if (Test-Path "C:\Tools\Sysmon\Sysmon64.exe") { $exe = "C:\Tools\Sysmon\Sysmon64.exe" }
  }
  if ($exe) {
    $cfg = "C:\Tools\Sysmon\sysmonconfig.xml"
    if (-not (Test-Path $cfg)) {
      Act "download the SwiftOnSecurity config" {
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile $cfg -UseBasicParsing
      }
    }
    if (Test-Path $cfg) {
      Act "install Sysmon with the SwiftOnSecurity config" { & $exe -accepteula -i $cfg | Out-Null }
    } else {
      Act "install Sysmon with default config (no config file available)" { & $exe -accepteula -i | Out-Null }
    }
    Say "  -> Sysmon event ids that matter: 1 process, 3 network, 11 file, 13 registry, 19-21 WMI"
  } else {
    Say "  [!!] could not find or download Sysmon. No internet? Upload Sysmon64.exe from Kali with evil-winrm:"
    Say "       upload /home/agentcooper/blue/Sysmon64.exe C:\ProgramData\Sysmon64.exe"
    Say "       then: C:\ProgramData\Sysmon64.exe -accepteula -i"
  }
} else {
  Say "  BEFORE: $($sys.Name) = $($sys.Status)"
  Act "start $($sys.Name) and set it to automatic" {
    Set-Service -Name $sys.Name -StartupType Automatic
    if ($sys.Status -ne 'Running') { Start-Service -Name $sys.Name }
  }
  Say "  AFTER:  $((Get-Service -Name $sys.Name).Status)"
}

# ------------------------------------------------------- 6. report, do not fix
Step "6. state to fix by hand (lockdown.ps1 does this)"
Say "  local administrators:"
Get-LocalGroupMember Administrators | ForEach-Object { Say "    $($_.Name)" }
Say "  non-Microsoft scheduled tasks:"
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\Windows\*' } |
  ForEach-Object { Say "    $($_.TaskPath)$($_.TaskName)" }
Say "  Run keys:"
(Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run").Property |
  ForEach-Object { Say "    $_" }

Step "done"
Say "Report: $log"
Say ""
Say "What to say in the blue report:"
Say "  this script is the patching half. The phase 4 lab showed DC01 logged no password resets at all,"
Say "  which is why our own attack left almost no trace. This turns on Account Management and Directory"
Say "  Service Access auditing, adds command lines to 4688, requires SMB signing, and confirms Sysmon."
