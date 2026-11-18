<#
  rotate_windows.ps1 — endgame password rotation that understands the difference between
  LOCAL accounts and DOMAIN accounts, and that does not forget service accounts.

  The distinction matters more than anything else on this page:
    - A LOCAL account lives in the box's SAM database (Get-LocalUser). It exists on that one
      machine. It cannot be used to log into the domain, and a domain password change does not
      affect it.
    - A DOMAIN account lives in Active Directory (Get-ADUser / net user /domain). It can log into
      any joined machine unless something blocks it. Changing it once changes it everywhere.
    - On a DOMAIN CONTROLLER there are no useful local accounts at all. Every account that matters
      is a domain account. If you rotate "local users" on the DC you have rotated nothing.

  Service accounts are the ones Red likes: often no interactive logon, sometimes a weak or shared
  password, sometimes an SPN (which means it can be kerberoasted). Rotating one breaks its service
  until the service credential is updated too, so this script can do both.

  Usage:
    powershell -ep bypass .\rotate_windows.ps1                       # classify only
    powershell -ep bypass .\rotate_windows.ps1 -Apply                # rotate humans + lock rogues
    powershell -ep bypass .\rotate_windows.ps1 -Apply -IncludeService        # also rotate service accounts
    powershell -ep bypass .\rotate_windows.ps1 -Apply -IncludeService -UpdateServices
#>

param(
  [switch]$Apply,
  [switch]$IncludeService,
  [switch]$UpdateServices,
  [switch]$RotateDomainAdmin,
  [int]$RogueWindowHours = 48
)

$ErrorActionPreference = "Continue"
$stamp   = Get-Date -Format "yyyyMMdd-HHmmss"
$csvPath = "C:\blue_baseline\rotation-$stamp.csv"
$log     = "C:\blue_baseline\rotation-$stamp.txt"
New-Item -ItemType Directory -Force -Path "C:\blue_baseline" | Out-Null

function Say($m) { Write-Output $m; Add-Content -Path $log -Value $m }
function NewPass { param($name) $rand = -join ((48..57)+(65..90)+(97..122) | Get-Random -Count 6 | ForEach-Object {[char]$_}); "Sp26!$rand" }

$role      = (Get-CimInstance Win32_ComputerSystem).DomainRole
$isDC      = ($role -eq 4 -or $role -eq 5)
$computer  = $env:COMPUTERNAME
$rows      = @()

Say "rotate_windows.ps1  host=$computer  domain_role=$role  is_domain_controller=$isDC  apply=$Apply"
Say "Result file: $csvPath"
if (-not $Apply) { Say "CLASSIFY ONLY. Nothing will change. Add -Apply to act." }

if ($isDC) {
  Say ""
  Say "[i] This is a domain controller. There are no useful local accounts here. Every account below is a DOMAIN account."
}

# ------------------------------------------------------------------ discovery
Say ""
Say "================ ACCOUNTS ================"

$localAccounts = @()
if (-not $isDC) {
  $localAccounts = Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, LastLogon
  Say "LOCAL accounts (SAM, this machine only): $($localAccounts.Count)"
  $localAccounts | ForEach-Object { Say ("  {0,-22} enabled={1,-5} pwRequired={2}" -f $_.Name, $_.Enabled, $_.PasswordRequired) }
} else {
  Say "LOCAL accounts (SAM): none that matter on a DC"
}

$domainAccounts = @()
try {
  Import-Module ActiveDirectory -ErrorAction Stop
  $domainAccounts = Get-ADUser -Filter * -Properties Created, ServicePrincipalName, PasswordLastSet |
                    Select-Object SamAccountName, Enabled, Created, ServicePrincipalName, PasswordLastSet
  Say ""
  Say "DOMAIN accounts (AD, work everywhere): $($domainAccounts.Count)"
} catch {
  Say ""
  Say "DOMAIN accounts: (RSAT not installed, using net user /domain)"
  $domainAccounts = net user /domain 2>$null | Select-Object -Skip 4 | ForEach-Object {
    $_.Trim() -split '\s+' | Where-Object { $_ -and $_ -ne 'The' -and $_ -notmatch '^command' }
  } | ForEach-Object { [pscustomobject]@{ SamAccountName = $_ } }
}

# ----------------------------------------------------------- service accounts
Say ""
Say "================ SERVICE ACCOUNTS ================"
$svcNames = [System.Collections.Generic.HashSet[string]]::new()

foreach ($s in Get-CimInstance Win32_Service | Where-Object { $_.StartName -and $_.StartName -notlike '*LocalSystem*' -and $_.StartName -notlike '*NT AUTHORITY*' }) {
  $acct = ($s.StartName -split '\\')[-1]
  [void]$svcNames.Add($acct)
  Say ("  service '{0}' runs as {1}" -f $s.Name, $s.StartName)
}
foreach ($t in Get-ScheduledTask | Where-Object { $_.Principal.UserId }) {
  $acct = ($t.Principal.UserId -split '\\')[-1]
  if ($acct -and $acct -notmatch '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|Users|Authenticated Users)$') {
    [void]$svcNames.Add($acct)
  }
}
if ($domainAccounts -and $domainAccounts[0].PSObject.Properties.Name -contains 'ServicePrincipalName') {
  foreach ($u in $domainAccounts | Where-Object { $_.ServicePrincipalName }) {
    [void]$svcNames.Add($u.SamAccountName)
    Say ("  AD account with an SPN (kerberoastable): {0}" -f $u.SamAccountName)
  }
}
Say ""
Say "Service account shortlist: $([string]::Join(', ', $svcNames))"
if ($svcNames.Count -gt 0 -and -not $IncludeService) {
  Say "[i] These are skipped unless you pass -IncludeService. Rotating one breaks its service until the credential is updated."
}

# ------------------------------------------------------------- rogue accounts
Say ""
Say "================ POSSIBLY MALICIOUS ================"
$cutoff = (Get-Date).AddHours(-$RogueWindowHours)

$recent = @()
if ($domainAccounts -and $domainAccounts[0].PSObject.Properties.Name -contains 'Created') {
  $recent = $domainAccounts | Where-Object { $_.Created -and $_.Created -gt $cutoff }
  foreach ($u in $recent) { Say ("  [NEW] domain account created {0}: {1}" -f $u.Created, $u.SamAccountName) }
} else {
  $ev = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720; StartTime=$cutoff} -ErrorAction SilentlyContinue
  foreach ($e in $ev) { Say ("  [NEW] 4720 at {0}: {1}" -f $e.TimeCreated, ($e.Message -split "`n")[0]) }
}

$noPw = $localAccounts | Where-Object { $_.PasswordRequired -eq $false }
foreach ($u in $noPw) { Say ("  [NO PASSWORD REQUIRED] {0}" -f $u.Name) }

$admins = @()
try {
  $admins = (Get-LocalGroupMember Administrators -ErrorAction Stop).Name
} catch { }
$baselineAdmins = @()
if (Test-Path "C:\blue_baseline\admins.txt") { $baselineAdmins = Get-Content "C:\blue_baseline\admins.txt" }
$newAdmins = $admins | Where-Object { $a = $_; -not ($baselineAdmins -match [regex]::Escape(($a -split '\\')[-1])) }
foreach ($a in $newAdmins) { Say ("  [NOT IN BASELINE] local admin: {0}" -f $a) }

# ------------------------------------------------------------------ rotation
if ($Apply) {
  Say ""
  Say "================ ROTATING ================"
  $targets = @()

  # local human accounts (skip on a DC, there are none that matter)
  if (-not $isDC) {
    foreach ($u in $localAccounts) {
      if ($u.Name -in @('Administrator','Guest','DefaultAccount','WDAGUtilityAccount')) {
        if ($u.Name -eq 'Administrator' -and -not $RotateDomainAdmin) { continue }
      }
      if ($svcNames.Contains($u.Name)) { continue }
      if (-not $u.Enabled) { continue }
      $targets += [pscustomobject]@{ Name=$u.Name; Scope='local' }
    }
  }

  # domain human accounts
  if ($domainAccounts -and $domainAccounts[0].PSObject.Properties.Name -contains 'Enabled') {
    foreach ($u in $domainAccounts) {
      if (-not $u.Enabled) { continue }
      if ($u.SamAccountName -match '\$$') { continue }              # machine accounts
      if ($u.SamAccountName -eq 'krbtgt') { continue }              # never rotate krbtgt mid-round
      if ($svcNames.Contains($u.SamAccountName) -and -not $IncludeService) { continue }
      if ($u.SamAccountName -eq 'Administrator' -and -not $RotateDomainAdmin) { continue }
      $targets += [pscustomobject]@{ Name=$u.SamAccountName; Scope='domain' }
    }
  }

  $results = @()
  foreach ($t in $targets) {
    $new = NewPass $t.Name
    try {
      if ($t.Scope -eq 'local') {
        Set-LocalUser -Name $t.Name -Password (ConvertTo-SecureString $new -AsPlainText -Force)
      } else {
        try {
          Set-ADAccountPassword -Identity $t.Name -Reset -NewPassword (ConvertTo-SecureString $new -AsPlainText -Force) -ErrorAction Stop
        } catch {
          net user $t.Name $new /domain | Out-Null
        }
      }
      $results += [pscustomobject]@{ Account=$t.Name; Scope=$t.Scope; Action='ROTATED'; NewPassword=$new }
      Say ("  [ROTATED] {0,-22} scope={1}" -f $t.Name, $t.Scope)
    } catch {
      $results += [pscustomobject]@{ Account=$t.Name; Scope=$t.Scope; Action='FAILED'; NewPassword='' }
      Say ("  [FAILED]  {0,-22} {1}" -f $t.Name, $_.Exception.Message)
    }
  }

  # lock the obvious rogues
  foreach ($u in $noPw) {
    try {
      Set-LocalUser -Name $u.Name -PasswordNeverExpires $false -ErrorAction Stop
      Disable-LocalUser -Name $u.Name
      $results += [pscustomobject]@{ Account=$u.Name; Scope='local'; Action='DISABLED(no password)'; NewPassword='' }
      Say ("  [DISABLED] {0} (had no password)" -f $u.Name)
    } catch { Say ("  [FAILED] disable {0}: {1}" -f $u.Name, $_.Exception.Message) }
  }

  # service accounts, if asked, and re-point the services
  if ($IncludeService) {
    foreach ($name in $svcNames) {
      $new = NewPass $name
      try {
        net user $name $new /domain 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { Set-LocalUser -Name $name -Password (ConvertTo-SecureString $new -AsPlainText -Force) }
        $results += [pscustomobject]@{ Account=$name; Scope='service'; Action='ROTATED(service)'; NewPassword=$new }
        Say ("  [ROTATED] {0,-22} scope=service" -f $name)
        if ($UpdateServices) {
          foreach ($s in Get-CimInstance Win32_Service | Where-Object { ($_.StartName -split '\\')[-1] -eq $name }) {
            sc.exe config "$($s.Name)" obj= "$($s.StartName)" password= "$new" | Out-Null
            Say ("     updated credential on service {0} and will restart it" -f $s.Name)
            Restart-Service -Name $s.Name -Force -ErrorAction SilentlyContinue
          }
        }
      } catch { Say ("  [FAILED]  {0,-22} {1}" -f $name, $_.Exception.Message) }
    }
  }

  $results | Export-Csv -Path $csvPath -NoTypeInformation
  Say ""
  Say "Credentials written to $csvPath (treat as sensitive, delete after the debrief)"
} else {
  Say ""
  Say "Nothing changed. Add -Apply to rotate."
}

Say ""
Say "============ SCOREBOARD, DO THIS OR YOU LOSE POINTS ============"
Say "  The scoring engine logs in with a real account for some checks (SSH on the PD, LDAP on DC)."
Say "  If you rotate that account and do not tell the scoreboard, the check goes red and you lose points"
Say "  for the rest of the round. The sequence is always:"
Say "    1. rotate the account (this script)"
Say "    2. open https://<scoring-host>:8443 -> Settings -> find that check"
Say "    3. paste the new password, save"
Say "    4. confirm the service is green again, screenshot both states"
Say "  That before/after screenshot is also your best evidence for the report's password section."
Say ""
Say "============ REMINDERS ============"
Say "  rotating a password does NOT remove persistence: scheduled tasks, Run keys, WMI"
Say "  subscriptions and local admins all survive it. Re-check them after this script."
Say "  never rotate krbtgt during the round, it breaks Kerberos for the whole domain."
Say "  after rotating a service account, re-check the scored port with nmap."
Say "  on a DC, a 'local account' change does nothing at all. Everything is in AD."
