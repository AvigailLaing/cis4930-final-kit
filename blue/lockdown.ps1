<#
  lockdown.ps1 — endgame cleanup on the DC. Run at minute 20, not before.
  Screenshot the "before" listing first, then run this, then screenshot the "after".

  Usage:
    powershell -ExecutionPolicy Bypass -File .\lockdown.ps1 -NewAdminPass 'N3wPass!2026'

  Does:
    1. changes the Administrator password
    2. lists and removes non-standard local admin accounts
    3. removes non-Microsoft scheduled tasks that were not in the baseline
    4. removes Run key values that were not in the baseline
    5. removes WMI event subscriptions that were not in the baseline
    6. prints the final state for your screenshot

  Does NOT: delete data, wipe the box, or touch the Wazuh agent.
#>

param(
  [string]$NewAdminPass = "",
  [switch]$DryRun
)

$dir     = "C:\blue_baseline"
$keepAdm = @("Administrator","Domain Admins","Enterprise Admins","SYSTEM","LOCAL SERVICE","NETWORK SERVICE","Domain Admins".ToLower())
$log     = @()
function Say($m) { Write-Output $m; $script:log += $m }

Say "================= BEFORE ================="
Get-LocalGroupMember Administrators | ForEach-Object { Say "admin: $($_.Name)" }
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\Windows\*' } |
  ForEach-Object { Say "task: $($_.TaskPath)$($_.TaskName)" }

if ($DryRun) { Say ""; Say "DRY RUN, stopping here."; return }

# ---------------------------------------------------------- 1. admin password
if ($NewAdminPass -ne "") {
  try {
    Set-LocalUser -Name "Administrator" -Password (ConvertTo-SecureString $NewAdminPass -AsPlainText -Force)
    Say ""
    Say "[CHANGED] Administrator password"
  } catch { Say "[FAILED] password change: $($_.Exception.Message)" }
}

# ------------------------------------------------------------ 2. rogue admins
Say ""
Say "---- removing rogue admins ----"
$baselineAdmins = @()
if (Test-Path "$dir\admins.txt") {
  $baselineAdmins = Get-Content "$dir\admins.txt"
}
Get-LocalGroupMember Administrators | ForEach-Object {
  $name = $_.Name
  $short = ($name -split '\\')[-1]
  $known = $false
  foreach ($k in $keepAdm) { if ($short -ieq $k) { $known = $true } }
  if (Test-Path "$dir\admins.txt") {
    if ($baselineAdmins -match [regex]::Escape($short)) { $known = $true }
  }
  if (-not $known) {
    try {
      Remove-LocalGroupMember -Group "Administrators" -Member $name
      Say "[REMOVED] admin: $name"
    } catch { Say "[FAILED] remove admin $name : $($_.Exception.Message)" }
  }
}

# ------------------------------------------------- 3. non-Microsoft task sweep
Say ""
Say "---- removing non-standard scheduled tasks ----"
$baseTasks = @()
if (Test-Path "$dir\tasks.txt") { $baseTasks = Get-Content "$dir\tasks.txt" }
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\Windows\*' } | ForEach-Object {
  $tn = $_.TaskName
  if ($baseTasks -match [regex]::Escape($tn)) { Say "[KEPT] baseline task: $tn"; return }
  try {
    Unregister-ScheduledTask -TaskName $tn -TaskPath $_.TaskPath -Confirm:$false
    Say "[REMOVED] task: $($_.TaskPath)$tn"
  } catch { Say "[FAILED] task $tn : $($_.Exception.Message)" }
}

# ------------------------------------------------------------- 4. Run key sweep
Say ""
Say "---- Run keys ----"
$baseRun = @()
if (Test-Path "$dir\runkey.txt") { $baseRun = Get-Content "$dir\runkey.txt" }
foreach ($hive in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")) {
  if (-not (Test-Path $hive)) { continue }
  (Get-Item $hive).Property | ForEach-Object {
    $p = $_
    if ($baseRun -notmatch [regex]::Escape($p)) {
      try {
        Remove-ItemProperty -Path $hive -Name $p -Force
        Say "[REMOVED] run key: $hive\$p"
      } catch { Say "[FAILED] run key $p : $($_.Exception.Message)" }
    } else { Say "[KEPT] baseline run key: $p" }
  }
}

# -------------------------------------------------------- 5. WMI subscriptions
Say ""
Say "---- WMI event subscriptions ----"
$baseFilters = @()
if (Test-Path "$dir\wmi_filters.txt") { $baseFilters = Get-Content "$dir\wmi_filters.txt" }
try {
  Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction Stop |
    ForEach-Object {
      if ($baseFilters -match [regex]::Escape($_.Name)) { Say "[KEPT] baseline filter: $($_.Name)"; return }
      Remove-CimInstance -InputObject $_
      Say "[REMOVED] WMI filter: $($_.Name)"
    }
  Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue |
    ForEach-Object {
      if ($baseFilters -match [regex]::Escape($_.Name)) { return }
      Remove-CimInstance -InputObject $_
      Say "[REMOVED] WMI consumer: $($_.Name)"
    }
  Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue |
    Where-Object { $_.Filter -notmatch 'baseline' } |
    ForEach-Object { try { Remove-CimInstance -InputObject $_; Say "[REMOVED] WMI binding" } catch {} }
} catch { Say "[i] no WMI subscriptions present or access denied" }

# ------------------------------------------------------ 6. sessions and state
Say ""
Say "================= AFTER ================="
Get-LocalGroupMember Administrators | ForEach-Object { Say "admin: $($_.Name)" }
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\Windows\*' } |
  ForEach-Object { Say "task: $($_.TaskPath)$($_.TaskName)" }
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
  Select LocalPort,RemoteAddress,RemotePort,OwningProcess |
  Format-Table | Out-String | ForEach-Object { Say $_ }
Say ""
Say "Screenshot this AFTER section. That is your evidence that removal worked."
Say "Then check again in 3 minutes. If anything returns, there is a second mechanism."
