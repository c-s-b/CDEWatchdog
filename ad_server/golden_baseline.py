"""
Golden State Baseline & Diff Engine Specifications
Air-Gapped Cyber Defense Exercise (CDE) Active Directory Integrity Model
"""

from typing import Dict, List, Set, Any
from dataclasses import dataclass, field

# ============================================================================
# 1. GOLDEN STATE BASELINE DEFINITIONS
# ============================================================================

# Pristine Built-in Active Directory System Accounts
BASE_SYSTEM_USERS: Set[str] = {
    "Administrator",
    "Guest",
    "krbtgt"
}

# Assigned Blue Team Roster Accounts
BASE_BLUE_TEAM_ROSTER: Set[str] = {
    "BlueTeamLead",
    "BlueTeamAdmin1",
    "BlueTeamAdmin2",
    "ScoreUser_AD"
}

# The Absolute Baseline User Pool (Golden State)
GOLDEN_STATE_USERS: Set[str] = BASE_SYSTEM_USERS | BASE_BLUE_TEAM_ROSTER

# Pristine Privileged Domain Groups Whitelist
GOLDEN_DOMAIN_ADMINS: Set[str] = {
    "Administrator",
    "BlueTeamLead"
}

GOLDEN_ENTERPRISE_ADMINS: Set[str] = {
    "Administrator"
}

# Hardened Security Registry Requirements (Enforced = 1)
GOLDEN_REGISTRY_POLICIES: Dict[str, int] = {
    "EnableFirewall": 1,        # StandardProfile / DomainProfile Firewall
    "UserAuthentication": 1,    # RDP Network Level Authentication (NLA)
    "RunAsPPL": 1               # LSA Protection against LSASS Dumping / Mimikatz
}


# ============================================================================
# 2. DIFF & COMPLIANCE DATA STRUCTURES
# ============================================================================

@dataclass
class AnomalyRecord:
    timestamp: str
    severity: str        # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    category: str        # "Privileged Access", "Backdoor Account", "Defense Impairment", "Credential Guard"
    finding: str         # Concrete discrepancy detected
    details: str         # Technical description
    mitre_attack: str    # MITRE ATT&CK technique reference
    remediation_cmd: str # Ready-to-execute PowerShell / cmd command


@dataclass
class DiffResult:
    health_score: int
    rogue_users: Set[str] = field(default_factory=set)
    rogue_domain_admins: Set[str] = field(default_factory=set)
    missing_baseline_users: Set[str] = field(default_factory=set)
    registry_discrepancies: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    anomalies: List[AnomalyRecord] = field(default_factory=list)
    is_compliant: bool = False


# ============================================================================
# 3. SET-DIFFERENCE EVALUATION ENGINE
# ============================================================================

def evaluate_ad_telemetry(
    telemetry: Dict[str, Any],
    extra_user_whitelist: Set[str] = None
) -> DiffResult:
    """
    Evaluates live Active Directory telemetry against the Golden State Baseline.
    Applies set-difference logic to identify rogue accounts, privilege escalations,
    and weakened registry policies.
    """
    if extra_user_whitelist is None:
        extra_user_whitelist = set()

    # Normalize case-insensitively for comparison
    live_users_raw = telemetry.get("users", [])
    live_admins_raw = telemetry.get("domain_admins", [])
    live_registry = telemetry.get("registry", {})

    live_users: Set[str] = set(live_users_raw)
    live_admins: Set[str] = set(live_admins_raw)

    # Combined active user whitelist
    active_whitelist: Set[str] = GOLDEN_STATE_USERS | extra_user_whitelist

    # Case-insensitive mapping for AD matching
    whitelist_lookup = {u.lower(): u for u in active_whitelist}
    golden_admins_lookup = {u.lower(): u for u in GOLDEN_DOMAIN_ADMINS}

    # 1. Identify Rogue Domain Admins
    rogue_admins: Set[str] = set()
    for admin in live_admins:
        if admin.lower() not in golden_admins_lookup:
            rogue_admins.add(admin)

    # 2. Identify Rogue AD Users (Backdoors)
    rogue_users: Set[str] = set()
    for user in live_users:
        if user.lower() not in whitelist_lookup:
            rogue_users.add(user)

    # 3. Check for Missing Baseline Accounts
    live_users_lower = {u.lower() for u in live_users}
    missing_baseline: Set[str] = set()
    for expected in (BASE_BLUE_TEAM_ROSTER | {"Administrator", "krbtgt"}):
        if expected.lower() not in live_users_lower:
            missing_baseline.add(expected)

    # 4. Check Registry Hardening
    reg_discrepancies: Dict[str, Dict[str, Any]] = {}
    for key, expected_val in GOLDEN_REGISTRY_POLICIES.items():
        actual_val = live_registry.get(key, 0)
        if actual_val != expected_val:
            reg_discrepancies[key] = {
                "expected": expected_val,
                "actual": actual_val
            }

    # 5. Compute AD Security Health Score
    # Starting score = 100%
    # Deductions:
    # - 40% for any rogue Domain Admin
    # - 30% for disabled firewall
    # - 20% for weakened RDP/LSA configs
    score = 100
    deductions = []

    # Rogue Domain Admin deduction: -40%
    if rogue_admins:
        score -= 40
        deductions.append(f"-40% Rogue Domain Admins ({', '.join(rogue_admins)})")

    # Disabled Firewall deduction: -30%
    if "EnableFirewall" in reg_discrepancies:
        score -= 30
        deductions.append("-30% Disabled Firewall (EnableFirewall != 1)")

    # Weakened RDP/LSA configs deduction: -20%
    weakened_rdp = "UserAuthentication" in reg_discrepancies
    weakened_lsa = "RunAsPPL" in reg_discrepancies
    if weakened_rdp or weakened_lsa:
        score -= 20
        reasons = []
        if weakened_rdp: reasons.append("RDP NLA Disabled")
        if weakened_lsa: reasons.append("LSA RunAsPPL Disabled")
        deductions.append(f"-20% Weakened System Hardening ({', '.join(reasons)})")

    # 5. Check Run and RunOnce Registry Persistence Keys (MITRE T1547.001)
    BENIGN_RUN_NAMES = {
        "vmware user process", "vmware tools", "vboxtray", "vboxclient", "securityhealth", "securityhealthsystray"
    }
    raw_run_keys = telemetry.get("run_keys", [])
    suspicious_run_keys = []
    for r in raw_run_keys:
        r_name = str(r.get("name", "")).strip().lower()
        r_cmd = str(r.get("command", "")).strip().lower()
        if r_name in BENIGN_RUN_NAMES or "vmtoolsd.exe" in r_cmd or "vboxtray.exe" in r_cmd:
            continue
        suspicious_run_keys.append(r)

    if suspicious_run_keys:
        penalty = min(25, len(suspicious_run_keys) * 15)
        score -= penalty
        deductions.append(f"-{penalty}% Autostart Run/RunOnce Keys ({len(suspicious_run_keys)} detected)")

    # 6. Check Winlogon & Logon/Logoff Scripts (MITRE T1547.004 / T1037)
    winlogon = telemetry.get("winlogon", {})
    userinit_val = winlogon.get("Userinit", "C:\\Windows\\system32\\userinit.exe,").strip()
    is_userinit_clean = (userinit_val.lower() in ["c:\\windows\\system32\\userinit.exe,", "c:\\windows\\system32\\userinit.exe"])
    if not is_userinit_clean:
        score -= 30
        deductions.append(f"-30% Hijacked Winlogon Userinit ({userinit_val})")

    shell_val = winlogon.get("Shell", "explorer.exe").strip()
    if shell_val.lower() != "explorer.exe" and shell_val != "":
        score -= 25
        deductions.append(f"-25% Hijacked Winlogon Shell ({shell_val})")

    logon_script = winlogon.get("LogonScript", "").strip()
    if logon_script:
        score -= 20
        deductions.append(f"-20% Rogue Logon Script ({logon_script})")

    gp_scripts = winlogon.get("LogonLogoffScripts", [])
    if gp_scripts:
        penalty = min(25, len(gp_scripts) * 15)
        score -= penalty
        deductions.append(f"-{penalty}% Rogue Logon/Logoff GPO Scripts ({len(gp_scripts)} detected)")

    # Additional penalty for general rogue backdoor users (if not already domain admin)
    standard_rogue = rogue_users - rogue_admins
    if standard_rogue and score > 0:
        penalty = min(20, len(standard_rogue) * 10)
        score -= penalty
        deductions.append(f"-{penalty}% Rogue Backdoor Users ({', '.join(standard_rogue)})")

    # Clamp health score between 0 and 100
    score = max(0, min(100, score))

    # 7. Build Anomaly Records
    import datetime
    timestamp_str = datetime.datetime.now().strftime("%H:%M:%S")
    anomalies: List[AnomalyRecord] = []

    # Anomaly: Run / RunOnce Autostart Persistence
    for r in suspicious_run_keys:
        loc = r.get("location", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
        name = r.get("name", "Unknown")
        cmd = r.get("command", "")
        anomalies.append(AnomalyRecord(
            timestamp=timestamp_str,
            severity="CRITICAL",
            category="Autostart Persistence (Run Key)",
            finding=f"Unauthorized Run/RunOnce Key: '{name}' in {loc}",
            details=f"Autostart execution payload configured: {name} -> \"{cmd}\". Executes on user logon.",
            mitre_attack="T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder)",
            remediation_cmd=f'Remove-ItemProperty -Path "Registry::{loc}" -Name "{name}" -Force'
        ))

    # Anomaly: Winlogon Userinit Hijacking
    if not is_userinit_clean:
        anomalies.append(AnomalyRecord(
            timestamp=timestamp_str,
            severity="CRITICAL",
            category="Logon Persistence (Winlogon Hijack)",
            finding=f"Winlogon Userinit Hijacked: '{userinit_val}'",
            details="Winlogon Userinit value modified from default 'C:\\Windows\\system32\\userinit.exe,'. Executes arbitrary code during winlogon sequence.",
            mitre_attack="T1547.004 (Boot or Logon Autostart Execution: Winlogon Helper DLL / Userinit)",
            remediation_cmd='Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" -Name "Userinit" -Value "C:\\Windows\\system32\\userinit.exe,"'
        ))

    # Anomaly: Winlogon Shell Hijacking
    if shell_val.lower() != "explorer.exe" and shell_val != "":
        anomalies.append(AnomalyRecord(
            timestamp=timestamp_str,
            severity="CRITICAL",
            category="Logon Persistence (Shell Hijack)",
            finding=f"Winlogon Shell Hijacked: '{shell_val}'",
            details=f"Winlogon Shell changed to '{shell_val}' instead of 'explorer.exe'.",
            mitre_attack="T1547.004 (Winlogon Shell Replacement)",
            remediation_cmd='Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" -Name "Shell" -Value "explorer.exe"'
        ))

    # Anomaly: UserInitMprLogonScript
    if logon_script:
        anomalies.append(AnomalyRecord(
            timestamp=timestamp_str,
            severity="HIGH",
            category="Logon Persistence (Logon Script)",
            finding=f"Rogue Logon Script: UserInitMprLogonScript = '{logon_script}'",
            details=f"Environment UserInitMprLogonScript configured to execute '{logon_script}' at user logon.",
            mitre_attack="T1037.001 (Boot or Logon Initialization Scripts: Logon Script (Windows))",
            remediation_cmd='Remove-ItemProperty -Path "HKCU:\\Environment" -Name "UserInitMprLogonScript" -Force; Remove-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment" -Name "UserInitMprLogonScript" -Force -ErrorAction SilentlyContinue'
        ))

    # Anomaly: Group Policy Logon/Logoff Scripts
    for s in gp_scripts:
        anomalies.append(AnomalyRecord(
            timestamp=timestamp_str,
            severity="HIGH",
            category="Logon/Logoff Script Policy",
            finding=f"Rogue Logon/Logoff Script Detected: '{s}'",
            details=f"Group Policy script configured to execute on user logon/logoff: {s}",
            mitre_attack="T1037.001 (Boot or Logon Initialization Scripts: Logon Script (Windows))",
            remediation_cmd='# Inspect and delete script policy from Group Policy editor or registry'
        ))

    # Anomaly: Rogue Domain Admins
    for admin in sorted(rogue_admins):
        anomalies.append(AnomalyRecord(
            timestamp=timestamp_str,
            severity="CRITICAL",
            category="Privileged Access (Domain Admin)",
            finding=f"Rogue Domain Admin Detected: '{admin}'",
            details=f"Account '{admin}' is in Domain Admins but is NOT in pristine whitelist {GOLDEN_DOMAIN_ADMINS}.",
            mitre_attack="T1078.002 (Valid Accounts: Domain Accounts), T1098 (Account Manipulation)",
            remediation_cmd=f'Remove-ADGroupMember -Identity "Domain Admins" -Members "{admin}" -Confirm:$false; Disable-ADAccount -Identity "{admin}"'
        ))

    # Anomaly: Rogue AD Backdoor Users
    for user in sorted(standard_rogue):
        anomalies.append(AnomalyRecord(
            timestamp=timestamp_str,
            severity="HIGH",
            category="Pre-Installed Backdoor Account",
            finding=f"Unauthorized AD User: '{user}'",
            details=f"User account '{user}' exists on the Domain Controller without baseline authorization.",
            mitre_attack="T1136.002 (Create Account: Domain Account), T1078 (Valid Accounts)",
            remediation_cmd=f'Disable-ADAccount -Identity "{user}"; Revoke-ADUserTokens -Identity "{user}"'
        ))

    # Anomaly: Firewall Impairment
    if "EnableFirewall" in reg_discrepancies:
        anomalies.append(AnomalyRecord(
            timestamp=timestamp_str,
            severity="HIGH",
            category="Defense Impairment",
            finding="Windows Firewall is Disabled (EnableFirewall = 0)",
            details="StandardProfile/DomainProfile firewall is shut down, exposing DC RPC/SMB/LDAP ports to lateral traversal.",
            mitre_attack="T1562.001 (Impair Defenses: Disable or Modify System Firewall)",
            remediation_cmd='Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile" -Name "EnableFirewall" -Value 1; Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True'
        ))

    # Anomaly: RDP NLA Disabled
    if "UserAuthentication" in reg_discrepancies:
        anomalies.append(AnomalyRecord(
            timestamp=timestamp_str,
            severity="MEDIUM",
            category="Policy Hardening",
            finding="RDP Network Level Authentication (NLA) Disabled (UserAuthentication = 0)",
            details="Remote Desktop accepts connections prior to authentication, exposing DC to BlueKeep/RDP exploits.",
            mitre_attack="T1021.001 (Remote Services: Remote Desktop Protocol)",
            remediation_cmd='Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name "UserAuthentication" -Value 1'
        ))

    # Anomaly: LSA RunAsPPL Disabled
    if "RunAsPPL" in reg_discrepancies:
        anomalies.append(AnomalyRecord(
            timestamp=timestamp_str,
            severity="HIGH",
            category="Credential Guard Impairment",
            finding="LSA Protection Disabled (RunAsPPL = 0)",
            details="Local Security Authority process (lsass.exe) is unprotected against arbitrary memory reads (Mimikatz / Sekurlsa).",
            mitre_attack="T1003.001 (OS Credential Dumping: LSASS Memory)",
            remediation_cmd='Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "RunAsPPL" -Value 1'
        ))

    # Anomaly: Missing Baseline Accounts
    for missing in sorted(missing_baseline):
        anomalies.append(AnomalyRecord(
            timestamp=timestamp_str,
            severity="MEDIUM",
            category="Account Tampering",
            finding=f"Missing Whitelisted Account: '{missing}'",
            details=f"Core account '{missing}' is absent or deleted from the Domain Controller.",
            mitre_attack="T1531 (Account Access Removal)",
            remediation_cmd=f'# Verify account status via Get-ADUser -Identity "{missing}"'
        ))

    is_compliant = (score == 100 and len(anomalies) == 0)

    return DiffResult(
        health_score=score,
        rogue_users=rogue_users,
        rogue_domain_admins=rogue_admins,
        missing_baseline_users=missing_baseline,
        registry_discrepancies=reg_discrepancies,
        anomalies=anomalies,
        is_compliant=is_compliant
    )
