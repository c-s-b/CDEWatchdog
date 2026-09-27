<#
.SYNOPSIS
    Minute-0 Active Directory Emergency Remediation Playbook
.DESCRIPTION
    Purges rogue Domain Admins, locks down security registry policies,
    disables unauthorized backdoor accounts, and flushes Kerberos ticket caches.
    Designed for air-gapped Cyber Defense Exercise (CDE) Domain Controllers.
#>

[CmdletBinding()]
param (
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "  AIR-GAPPED DOMAIN CONTROLLER MINUTE-0 EMERGENCY REMEDIATION PLAYBOOK" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan

# 1. Baseline Whitelist Definitions
$PristineDomainAdmins = @("Administrator", "BlueTeamLead")
$PristineUsers = @("Administrator", "Guest", "krbtgt", "BlueTeamLead", "BlueTeamAdmin1", "BlueTeamAdmin2", "ScoreUser_AD")

# 2. Audit & Purge Rogue Domain Admins
Write-Host "`n[*] Auditing 'Domain Admins' Group Membership..." -ForegroundColor Yellow
try {
    $CurrentAdmins = Get-ADGroupMember -Identity "Domain Admins" | Select-Object -ExpandProperty SamAccountName
    foreach ($Admin in $CurrentAdmins) {
        if ($PristineDomainAdmins -notcontains $Admin) {
            Write-Host "  [!] ALERT: Rogue Domain Admin Detected: $Admin" -ForegroundColor Red
            if (-not $WhatIf) {
                Write-Host "      [-] Stripping from Domain Admins..." -ForegroundColor Magenta
                Remove-ADGroupMember -Identity "Domain Admins" -Members $Admin -Confirm:$false
                Write-Host "      [-] Disabling account..." -ForegroundColor Magenta
                Disable-ADAccount -Identity $Admin
                Write-Host "      [✔] Remediated $Admin" -ForegroundColor Green
            } else {
                Write-Host "      [WHATIF] Would remove $Admin from Domain Admins and disable account." -ForegroundColor Gray
            }
        } else {
            Write-Host "  [+] Authorized Admin: $Admin" -ForegroundColor Green
        }
    }
} catch {
    Write-Warning "Failed to query or modify Domain Admins: $_"
}

# 3. Audit & Disable Pre-installed Backdoor Users
Write-Host "`n[*] Auditing Active Directory Accounts for Pre-Installed Backdoors..." -ForegroundColor Yellow
try {
    $AllUsers = Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName
    foreach ($User in $AllUsers) {
        if ($PristineUsers -notcontains $User) {
            Write-Host "  [!] ALERT: Rogue User Account Detected: $User" -ForegroundColor Red
            if (-not $WhatIf) {
                Write-Host "      [-] Disabling account $User..." -ForegroundColor Magenta
                Disable-ADAccount -Identity $User
                Write-Host "      [✔] Locked account $User" -ForegroundColor Green
            } else {
                Write-Host "      [WHATIF] Would disable account $User." -ForegroundColor Gray
            }
        }
    }
} catch {
    Write-Warning "Failed to query AD users: $_"
}

# 4. Enforce Hardened Security Registry Policies
Write-Host "`n[*] Enforcing Security Registry Hardening Policies..." -ForegroundColor Yellow

# Policy A: Enforce Firewall
$FwPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"
try {
    if (-not (Test-Path $FwPath)) { New-Item -Path $FwPath -Force | Out-Null }
    Set-ItemProperty -Path $FwPath -Name "EnableFirewall" -Value 1 -Type DWord
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Write-Host "  [✔] Enforced EnableFirewall = 1 (All Profiles Enabled)" -ForegroundColor Green
} catch {
    Write-Warning "Failed to enforce Firewall: $_"
}

# Policy B: Enforce RDP Network Level Authentication (NLA)
$RdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
try {
    if (-not (Test-Path $RdpPath)) { New-Item -Path $RdpPath -Force | Out-Null }
    Set-ItemProperty -Path $RdpPath -Name "UserAuthentication" -Value 1 -Type DWord
    Write-Host "  [✔] Enforced RDP UserAuthentication = 1 (NLA Enabled)" -ForegroundColor Green
} catch {
    Write-Warning "Failed to enforce RDP NLA: $_"
}

# Policy C: Enforce LSA RunAsPPL (Protection against Mimikatz credential dumping)
$LsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
try {
    if (-not (Test-Path $LsaPath)) { New-Item -Path $LsaPath -Force | Out-Null }
    Set-ItemProperty -Path $LsaPath -Name "RunAsPPL" -Value 1 -Type DWord
    Write-Host "  [✔] Enforced LSA RunAsPPL = 1 (Credential Guard Active)" -ForegroundColor Green
} catch {
    Write-Warning "Failed to enforce RunAsPPL: $_"
}

# 5. Flush Kerberos Ticket Caches
Write-Host "`n[*] Purging System Kerberos Ticket Cache..." -ForegroundColor Yellow
try {
    klist -li 0x3e7 purge | Out-Null
    Write-Host "  [✔] System Kerberos TGT/TGS cache flushed" -ForegroundColor Green
} catch {
    Write-Warning "Failed to purge ticket cache: $_"
}

Write-Host "`n==========================================================================" -ForegroundColor Cyan
Write-Host "  [✔] REMEDIATION COMPLETE! DOMAIN CONTROLLER SECURED TO GOLDEN BASELINE" -ForegroundColor Green
Write-Host "==========================================================================" -ForegroundColor Cyan
