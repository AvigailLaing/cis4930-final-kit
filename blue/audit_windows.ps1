# audit_windows.ps1 - read-only audit of the hospital DC. Changes nothing.
#
# The blue packet asks for Windows work the kit had no code for:
#   "Watch for new accounts, group membership changes (Domain Admins especially),
#    odd service-account behavior, and anything touching certificate services."
#   "Kerberoasting, AS-REP roasting, shadow credentials, DCSync and weak cert
#    templates all leave their tracks somewhere."
#   "Install Sysmon and the Sysinternals tools (Autoruns for persistence...)"
#
# This automates that paragraph: an Autoruns-lite sweep plus the AD questions a DC
# can answer about itself.
#
#   powershell -ExecutionPolicy Bypass -File .\blue\audit_windows.ps1
#   powershell -ExecutionPolicy Bypass -File .\blue\audit_windows.ps1 -Hours 6
#
# Every section is wrapped, so one failing check does not stop the rest. It reads
# only: no account, service, template or ACL is modified. Fix by hand, deliberately,
# the same way audit_linux.sh leaves sudoers alone.

param(
    [int]$Hours = 3
)

$ErrorActionPreference = 'Continue'
$script:Findings = 0

function Sec($t)  { Write-Output ''; Write-Output ('---- ' + $t + ' ----') }
function Bad($t)  { Write-Output ('  [FINDING] ' + $t); $script:Findings++ }
function Ok($t)   { Write-Output ('  [ok] ' + $t) }
function Note($t) { Write-Output ('     ' + $t) }

# From the blue packet. If the final's lists differ, edit these two lines.
$ApprovedUsers  = @('ljacoby','whayward','broundtree','lshelvy','jim','arosenfield',
                    'ahorne','emt','doctor','nurse','lpalmer','bob','ljohnson','svc_ehr','Administrator','krbtgt')
$ApprovedAdmins = @('ljacoby','lshelvy','arosenfield','lpalmer','Administrator')

$Since = (Get-Date).AddHours(-$Hours)

Write-Output ('=== audit_windows.ps1  host=' + $env:COMPUTERNAME + '  user=' + $env:USERNAME + '  window=' + $Hours + 'h ===')

# ---------------------------------------------------------------- 1. host
Sec 'host'
try { Write-Output ('  domain: ' + (Get-ADDomain).DNSRoot) } catch { Write-Output '  domain: AD module unavailable, some checks will skip' }
try {
    $svc = Get-Service Sysmon -ErrorAction Stop
    Write-Output ('  sysmon: ' + $svc.Status)
} catch {
    Bad 'Sysmon is not installed, so you have no process-creation telemetry (packet: Event ID 1)'
}

# --------------------------------------------------- 2. privileged groups
Sec 'privileged group membership, against the approved admin list'
foreach ($g in @('Domain Admins','Enterprise Admins','Schema Admins','Backup Operators','Account Operators','Remote Desktop Users')) {
    try {
        $members = @(Get-ADGroupMember -Identity $g -ErrorAction Stop | Select-Object -ExpandProperty SamAccountName)
        Write-Output ('  ' + $g + ': ' + ($members -join ', '))
        foreach ($m in $members) {
            if ($ApprovedAdmins -notcontains $m) { Bad ($m + ' is in ' + $g + ' but is not on the packet admin list') }
        }
    } catch { Write-Output ('  ' + $g + ': could not read') }
}

# --------------------------------------------------- 3. account inventory
Sec 'accounts off the approved list, and accounts created recently'
try {
    $users = @(Get-ADUser -Filter * -Properties whenCreated, ServicePrincipalName, DoesNotRequirePreAuth, msDS-KeyCredentialLink)
    foreach ($u in $users) {
        if ($ApprovedUsers -notcontains $u.SamAccountName) { Bad ('domain account not on the approved list: ' + $u.SamAccountName) }
        if ($u.whenCreated -ne $null) {
            if ($u.whenCreated -gt $Since) { Bad ('account created in the last ' + $Hours + 'h: ' + $u.SamAccountName + ' at ' + $u.whenCreated) }
        }
    }
    Ok ('checked ' + $users.Count + ' domain accounts')
} catch { Write-Output '  AD module unavailable, skipping account inventory'; $users = @() }

# ------------------------------------------ 4. roastable / abusable accounts
Sec 'kerberoastable, AS-REP roastable, and shadow-credential targets'
try {
    $spn = @($users | Where-Object { $_.ServicePrincipalName -and $_.SamAccountName -ne 'krbtgt' })
    if ($spn.Count -gt 0) {
        Bad ([string]$spn.Count + ' account(s) hold an SPN and can be kerberoasted')
        foreach ($u in $spn) { Note ($u.SamAccountName + '  spn=' + ($u.ServicePrincipalName -join ',')) }
    } else { Ok 'no non-krbtgt account holds an SPN' }

    $asrep = @($users | Where-Object { $_.DoesNotRequirePreAuth -eq $true })
    if ($asrep.Count -gt 0) {
        Bad ([string]$asrep.Count + ' account(s) skip Kerberos preauth, so they are AS-REP roastable')
        foreach ($u in $asrep) { Note $u.SamAccountName }
    } else { Ok 'every account requires preauth' }

    # A hyphenated attribute name has to be quoted or PowerShell parses it as subtraction.
    $shadow = @($users | Where-Object { $_.'msDS-KeyCredentialLink' })
    if ($shadow.Count -gt 0) {
        Bad ('shadow credentials on ' + [string]$shadow.Count + ' account(s): red may already hold a key')
        foreach ($u in $shadow) { Note $u.SamAccountName }
    } else { Ok 'no msDS-KeyCredentialLink artifacts' }
} catch { Write-Output '  could not enumerate roastable accounts' }

# ---------------------------------------------------------- 5. certificate
Sec 'certificate templates, ESC1 shape: enrollee supplies the subject'
try {
    $config = (Get-ADRootDSE).configurationNamingContext
    $base = 'CN=Certificate Templates,CN=Public Key Services,CN=' + $config
    $tpl = @(Get-ADObject -SearchBase $base -Filter { objectClass -eq 'pKICertificateTemplate' } -Properties 'msPKI-Certificate-Name-Flag','pKIExtendedKeyUsage' -ErrorAction Stop)
    if ($tpl.Count -eq 0) { Ok 'no certificate templates found, ADCS may not be installed' }
    foreach ($t in $tpl) {
        $flags = 0
        $raw = $t.'msPKI-Certificate-Name-Flag'
        if ($raw -ne $null) { $flags = [int]$raw }
        $eku = @($t.pKIExtendedKeyUsage)
        $clientAuth = (($eku -contains '1.3.6.1.5.5.7.3.2') -or ($eku -contains '2.5.29.37.0'))
        $supplies = (($flags -band 0x1000000) -ne 0)
        if ($supplies -and $clientAuth) {
            Bad ('template ' + $t.Name + ' lets the enrollee supply the subject and grants client auth (ESC1)')
        } else {
            Note ($t.Name + '  flags=' + [string]$flags + '  eku=' + ($eku -join ','))
        }
    }
} catch { Write-Output '  no certificate template access, skipping' }

# ------------------------------------------------- 6. autoruns, the lite version
Sec 'autoruns: Run keys, scheduled tasks, and services that live outside Windows'
foreach ($key in @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
                   'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                   'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run')) {
    try {
        $p = Get-ItemProperty -Path $key -ErrorAction Stop
        $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
            Write-Output ('  ' + $key + ' -> ' + $_.Name + ' = ' + $_.Value)
            if ($_.Value -match 'Temp|ProgramData|Users|AppData|powershell -enc|mshta|wscript|certutil') {
                Bad ('suspicious Run value: ' + $_.Name + ' = ' + $_.Value)
            }
        }
    } catch { }
}
try {
    $tasks = @(Get-ScheduledTask -ErrorAction Stop)
    foreach ($t in $tasks) {
        foreach ($a in @($t.Actions)) {
            if ($a.Execute -match 'powershell|cmd\.exe|wscript|mshta|rundll32|certutil|Temp|AppData') {
                Bad ('scheduled task ' + $t.TaskName + ' runs ' + $a.Execute + ' ' + $a.Arguments)
            }
        }
    }
    Ok ('reviewed ' + $tasks.Count + ' scheduled tasks')
} catch { Write-Output '  could not read scheduled tasks' }
try {
    $svcs = @(Get-CimInstance Win32_Service -ErrorAction Stop)
    foreach ($s in $svcs) {
        if ($s.PathName -eq $null) { continue }
        if ($s.PathName -match 'C:\\Windows\\') { continue }
        Note ('service ' + $s.Name + '  ' + $s.State + '  ' + $s.PathName)
        if ($s.PathName -match 'Temp|ProgramData|Users|AppData') { Bad ('service runs from a user-writable path: ' + $s.Name) }
    }
} catch { Write-Output '  could not enumerate services' }

# ------------------------------------------------------------ 7. event log
Sec ('security events in the last ' + $Hours + ' hours')
try {
    $ev = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720; StartTime=$Since} -ErrorAction Stop)
    if ($ev.Count -gt 0) { Bad ([string]$ev.Count + ' accounts were created during the round (4720)') } else { Ok 'no account creation (4720)' }
} catch { Write-Output '  4720 account created: none' }
try {
    $ev = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4728; StartTime=$Since} -ErrorAction Stop)
    if ($ev.Count -gt 0) { Bad ([string]$ev.Count + ' global group membership changes (4728), check for Domain Admins') } else { Ok 'no group membership changes (4728)' }
} catch { Write-Output '  4728 group membership change: none' }
try {
    $ev = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4662; StartTime=$Since} -ErrorAction Stop)
    if ($ev.Count -gt 0) { Note ([string]$ev.Count + ' directory service access events (4662). DS-Replication-Get-Changes means DCSync.') } else { Ok 'no directory service access (4662)' }
} catch { Write-Output '  4662 directory service access: none' }
try {
    $ev = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$Since} -ErrorAction Stop)
    $red = @($ev | Where-Object { $_.Message -match '10\.42\.' })
    if ($red.Count -gt 0) { Bad ([string]$red.Count + ' logons from the 10.42 attacker network') } else { Ok 'no logons from 10.42.x' }
} catch { Write-Output '  4624 logons: none' }

Write-Output ''
Write-Output ('=== SUMMARY: ' + [string]$script:Findings + ' finding(s). This script modified nothing. ===')
Write-Output '  Screenshot the finding lines. Each one is an incident you can write up.'
Write-Output '  Fix the AD ones by hand, then run this again to prove the fix.'
