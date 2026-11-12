<#
  breakglass.ps1 — Blue team's way back into Windows, with the local-versus-domain lesson
  built into the code.

  On a member server you can create a LOCAL admin. On a domain controller there is no local SAM,
  so the equivalent is a DOMAIN account in Domain Admins. Getting that wrong is the most common
  blue-team mistake on a DC: you think you made a backup admin and you made nothing.

  Usage:
    powershell -ep bypass .\breakglass.ps1 -Create
    powershell -ep bypass .\breakglass.ps1 -Remove

  Disclose it in the report, remove it at the debrief.
#>

param(
  [switch]$Create,
  [switch]$Remove,
  [string]$Account = "svc_brkglass"
)

$ErrorActionPreference = "Continue"
$csv  = "C:\blue_baseline\brkglass.csv"
$role = (Get-CimInstance Win32_ComputerSystem).DomainRole
$isDC = ($role -eq 4 -or $role -eq 5)
$rand = -join ((48..57)+(65..90)+(97..122) | Get-Random -Count 10 | ForEach-Object {[char]$_})
$pw   = "Bg26!$rand"

if (-not $Create -and -not $Remove) { Write-Output "usage: breakglass.ps1 -Create | -Remove"; return }

if ($Create) {
  Write-Output "host=$env:COMPUTERNAME domain_role=$role is_dc=$isDC"
  New-Item -ItemType Directory -Force -Path "C:\blue_baseline" | Out-Null

  if ($isDC) {
    Write-Output "[i] domain controller: creating a DOMAIN account, a local account here is meaningless"
    try {
      Import-Module ActiveDirectory -ErrorAction Stop
      $exists = Get-ADUser -Filter "SamAccountName -eq '$Account'" -ErrorAction SilentlyContinue
      if (-not $exists) {
        New-ADUser -Name $Account -SamAccountName $Account `
                   -AccountPassword (ConvertTo-SecureString $pw -AsPlainText -Force) `
                   -Enabled $true -PasswordNeverExpires $true
        Write-Output "[CREATED] domain account $Account"
      } else {
        Set-ADAccountPassword -Identity $Account -Reset -NewPassword (ConvertTo-SecureString $pw -AsPlainText -Force)
        Write-Output "[RESET] existing domain account $Account"
      }
      Add-ADGroupMember -Identity "Domain Admins" -Members $Account -ErrorAction SilentlyContinue
      Add-ADGroupMember -Identity "Remote Management Users" -Members $Account -ErrorAction SilentlyContinue
      Write-Output "[ADDED] $Account to Domain Admins and Remote Management Users"
    } catch {
      net user $Account $pw /add /domain 2>$null | Out-Null
      net group "Domain Admins" $Account /add /domain 2>$null | Out-Null
      Write-Output "[CREATED] via net user (RSAT missing): $Account"
    }
    Write-Output ""
    Write-Output "Log in with:  evil-winrm -i <this-host> -u '$Account' -p '<password below>'"
  } else {
    Write-Output "[i] member server or workstation: creating a LOCAL administrator"
    if (Get-LocalUser -Name $Account -ErrorAction SilentlyContinue) {
      Set-LocalUser -Name $Account -Password (ConvertTo-SecureString $pw -AsPlainText -Force)
      Write-Output "[RESET] local account $Account"
    } else {
      New-LocalUser -Name $Account -Password (ConvertTo-SecureString $pw -AsPlainText -Force) `
                    -FullName "Break glass" -Description "Blue team recovery" | Out-Null
      Write-Output "[CREATED] local account $Account"
    }
    Add-LocalGroupMember -Group "Administrators" -Member $Account -ErrorAction SilentlyContinue
    Add-LocalGroupMember -Group "Remote Management Users" -Member $Account -ErrorAction SilentlyContinue
    Write-Output "[ADDED] $Account to Administrators and Remote Management Users"
  }

  $scope = if ($isDC) { "domain" } else { "local" }
  "$Account,$pw,$scope,$env:COMPUTERNAME" | Add-Content -Path $csv
  Write-Output ""
  Write-Output "Password: $pw"
  Write-Output "Credentials appended to $csv (sensitive, delete at debrief)"
  Write-Output ""
  Write-Output "One line for the blue report:"
  Write-Output "  'We created a documented recovery account during prep so a mid-round password rotation"
  Write-Output "   could not lock us out of the host we were defending. It was removed at the debrief.'"
}

if ($Remove) {
  if ($isDC) {
    try {
      Remove-ADGroupMember -Identity "Domain Admins" -Members $Account -Confirm:$false -ErrorAction SilentlyContinue
      Remove-ADUser -Identity $Account -Confirm:$false -ErrorAction SilentlyContinue
    } catch {
      net group "Domain Admins" $Account /delete /domain 2>$null | Out-Null
      net user $Account /delete /domain 2>$null | Out-Null
    }
    Write-Output "[REMOVED] domain account $Account and its group memberships"
  } else {
    Remove-LocalGroupMember -Group "Administrators" -Member $Account -ErrorAction SilentlyContinue
    Remove-LocalUser -Name $Account -ErrorAction SilentlyContinue
    Write-Output "[REMOVED] local account $Account"
  }
  Remove-Item $csv -ErrorAction SilentlyContinue
  Write-Output "Say it in the debrief: the recovery account existed and is gone."
}
