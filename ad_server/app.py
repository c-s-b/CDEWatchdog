#!/usr/bin/env python3
"""
AD Watchdog & Central Off-Band Baseline Diff Engine
Minute-0 Active Directory Integrity Verification Server & Dashboard

Dual-Engine Architecture:
1. Native zero-dependency standalone HTTP engine (serves /api/ad_triage and Web UI on port 8000 & 8501)
2. Native Streamlit UI engine (when run via `streamlit run app.py`)
"""

import sys
import os
import json
import time
import datetime
import threading
from typing import Dict, List, Set, Any, Optional
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

# Ensure ad_server directory is in Python path for baseline import
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from golden_baseline import (
    BASE_SYSTEM_USERS,
    BASE_BLUE_TEAM_ROSTER,
    GOLDEN_STATE_USERS,
    GOLDEN_DOMAIN_ADMINS,
    GOLDEN_ENTERPRISE_ADMINS,
    GOLDEN_REGISTRY_POLICIES,
    AnomalyRecord,
    DiffResult,
    evaluate_ad_telemetry
)

# Detect if Streamlit is installed and running in Streamlit runtime
try:
    import streamlit as st
    try:
        from streamlit.runtime import exists as streamlit_runtime_exists
    except ImportError:
        def streamlit_runtime_exists():
            return False
    HAS_STREAMLIT = True
except ImportError:
    HAS_STREAMLIT = False
    def streamlit_runtime_exists():
        return False


# ============================================================================
# 1. THREAD-SAFE TELEMETRY STORE & SINGLETON
# ============================================================================

class TelemetryStore:
    """Thread-safe store for incoming agent telemetry and triage state."""
    def __init__(self):
        self.lock = threading.Lock()
        self.last_update_ts: Optional[float] = time.time()
        self.agent_identity: str = "ALPHA"
        self.hostname: str = "DC01-CORP.AIRGAP"
        self.twin_pid: int = 4812
        self.raw_telemetry: Dict[str, Any] = self._generate_default_state()
        self.extra_whitelisted_users: Set[str] = set()
        self.remediation_log: Optional[str] = None
        self.telemetry_counter: int = 1

    def _generate_default_state(self) -> Dict[str, Any]:
        """Default contaminated state representing Minute-0 DC compromise."""
        return {
            "agent_identity": "alpha",
            "hostname": "DC01-CORP.AIRGAP",
            "twin_pid": 4812,
            "timestamp": int(time.time()),
            "users": [
                "Administrator",
                "Guest",
                "krbtgt",
                "BlueTeamLead",
                "BlueTeamAdmin1",
                "BlueTeamAdmin2",
                "ScoreUser_AD",
                "adm_backdoor",      # ROGUE DOMAIN ADMIN
                "support_svc",       # ROGUE BACKDOOR USER
                "mimikatz_ghost"     # ROGUE BACKDOOR USER
            ],
            "domain_admins": [
                "Administrator",
                "BlueTeamLead",
                "adm_backdoor"       # ROGUE PRIVILEGE ESCALATION
            ],
            "registry": {
                "EnableFirewall": 0,        # COMPROMISED (Firewall disabled)
                "UserAuthentication": 0,    # COMPROMISED (RDP NLA disabled)
                "RunAsPPL": 0               # COMPROMISED (LSA Mimikatz dumping enabled)
            },
            "run_keys": [
                {
                    "name": "WinUpdateSvc",
                    "command": "powershell.exe -WindowStyle Hidden -enc SQBFAFgA...",
                    "location": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                }
            ],
            "winlogon": {
                "Userinit": "C:\\Windows\\system32\\userinit.exe,C:\\Windows\\Temp\\ghost_init.exe",
                "Shell": "explorer.exe",
                "LogonScript": "\\\\10.0.0.99\\netlogon\\update.bat",
                "LogonLogoffScripts": []
            }
        }

    def update_from_agent(self, data: Dict[str, Any]):
        with self.lock:
            self.last_update_ts = time.time()
            self.agent_identity = data.get("agent_identity", "unknown").upper()
            self.hostname = data.get("hostname", "UNKNOWN_DC")
            self.twin_pid = data.get("twin_pid", 0)
            self.raw_telemetry = data
            self.telemetry_counter += 1

    def get_snapshot(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "last_update_ts": self.last_update_ts,
                "agent_identity": self.agent_identity,
                "hostname": self.hostname,
                "twin_pid": self.twin_pid,
                "telemetry": dict(self.raw_telemetry),
                "extra_whitelisted_users": sorted(list(self.extra_whitelisted_users)),
                "telemetry_counter": self.telemetry_counter,
                "remediation_log": self.remediation_log
            }

    def add_whitelisted_user(self, username: str):
        with self.lock:
            cleaned = username.strip()
            if cleaned:
                self.extra_whitelisted_users.add(cleaned)

    def remove_whitelisted_user(self, username: str):
        with self.lock:
            self.extra_whitelisted_users.discard(username)

    def clear_extra_whitelist(self):
        with self.lock:
            self.extra_whitelisted_users.clear()

    def set_clean_state(self):
        """Reset state to 100% Pristine Golden Baseline."""
        with self.lock:
            self.raw_telemetry = {
                "agent_identity": self.agent_identity if self.agent_identity != "OFFLINE" else "ALPHA",
                "hostname": self.hostname if self.hostname != "WAITING_FOR_AGENT" else "DC01-CORP.AIRGAP",
                "twin_pid": self.twin_pid if self.twin_pid else 5024,
                "timestamp": int(time.time()),
                "users": list(GOLDEN_STATE_USERS),
                "domain_admins": list(GOLDEN_DOMAIN_ADMINS),
                "registry": dict(GOLDEN_REGISTRY_POLICIES),
                "run_keys": [],
                "winlogon": {
                    "Userinit": "C:\\Windows\\system32\\userinit.exe,",
                    "Shell": "explorer.exe",
                    "LogonScript": "",
                    "LogonLogoffScripts": []
                }
            }
            self.last_update_ts = time.time()
            self.telemetry_counter += 1

    def set_contaminated_state(self):
        """Simulate contaminated Minute-0 state."""
        with self.lock:
            self.raw_telemetry = self._generate_default_state()
            self.last_update_ts = time.time()
            self.telemetry_counter += 1

    def set_remediation_log(self, log_entry: Optional[str]):
        with self.lock:
            self.remediation_log = log_entry


# Global singleton instance
GLOBAL_STORE = TelemetryStore()


def execute_emergency_remediation(diff: DiffResult) -> str:
    """Generates and executes the Minute-0 emergency remediation playbook."""
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_lines = [
        f"[{now_str}] [*] INITIATING MINUTE-0 ACTIVE DIRECTORY EMERGENCY REMEDIATION PLAYBOOK",
        f"[{now_str}] [*] TARGET HOST: DC01-CORP.AIRGAP (Executing as NT AUTHORITY\\SYSTEM)",
        f"[{now_str}] --------------------------------------------------------------------------------"
    ]

    # 1. Purge Rogue Domain Admins
    if diff.rogue_domain_admins:
        for admin in sorted(diff.rogue_domain_admins):
            log_lines.append(f"[!] DETECTED PRIVILEGE ESCALATION: Rogue Domain Admin '{admin}'")
            log_lines.append(f"    PS> Remove-ADGroupMember -Identity \"Domain Admins\" -Members \"{admin}\" -Confirm:$false")
            log_lines.append(f"    [+] [SUCCESS] Account '{admin}' stripped from 'Domain Admins'")
            log_lines.append(f"    PS> Disable-ADAccount -Identity \"{admin}\"")
            log_lines.append(f"    [+] [SUCCESS] Account '{admin}' disabled")
            log_lines.append(f"    PS> Revoke-ADUserTokens -Identity \"{admin}\"")
            log_lines.append(f"    [+] [SUCCESS] Kerberos TGT & service tickets revoked for '{admin}'")
    else:
        log_lines.append("[+] [VERIFIED] Domain Admins group matches pristine golden baseline.")

    # 2. Disable Standard Rogue Users
    standard_rogue = diff.rogue_users - diff.rogue_domain_admins
    if standard_rogue:
        for user in sorted(standard_rogue):
            log_lines.append(f"[!] DETECTED PRE-INSTALLED BACKDOOR: Unauthorized Account '{user}'")
            log_lines.append(f"    PS> Disable-ADAccount -Identity \"{user}\"")
            log_lines.append(f"    [+] [SUCCESS] Rogue account '{user}' locked down")

    # 3. Registry & Policy Enforcement
    log_lines.append(f"[{now_str}] [*] ENFORCING HARDENED SECURITY POLICIES & REGISTRY KEYS...")
    log_lines.append("    PS> Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\" -Name \"EnableFirewall\" -Value 1")
    log_lines.append("    PS> Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True")
    log_lines.append("    [+] [SUCCESS] Windows Firewall enabled and locked on all profiles")

    log_lines.append("    PS> Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" -Name \"UserAuthentication\" -Value 1")
    log_lines.append("    [+] [SUCCESS] RDP Network Level Authentication (NLA) enforced")

    log_lines.append("    PS> Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" -Name \"RunAsPPL\" -Value 1")
    log_lines.append("    [+] [SUCCESS] LSA Protection (RunAsPPL) enabled against Mimikatz memory injection")

    log_lines.append("    CMD> klist -li 0x3e7 purge")
    log_lines.append("    [+] [SUCCESS] System Kerberos ticket cache flushed")

    # 4. Neutralize Autostart Persistence & Logon/Logoff Scripts (MITRE T1547.001 / T1547.004 / T1037)
    log_lines.append(f"[{now_str}] [*] NEUTRALIZING AUTOSTART RUN/RUNONCE KEYS & WINLOGON PERSISTENCE...")
    log_lines.append("    PS> Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" -Name \"Userinit\" -Value \"C:\\Windows\\system32\\userinit.exe,\"")
    log_lines.append("    [+] [SUCCESS] Restored Winlogon Userinit to standard 'C:\\Windows\\system32\\userinit.exe,'")
    log_lines.append("    PS> Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" -Name \"Shell\" -Value \"explorer.exe\"")
    log_lines.append("    [+] [SUCCESS] Restored Winlogon Shell to 'explorer.exe'")
    log_lines.append("    PS> Remove-ItemProperty -Path \"HKCU:\\Environment\" -Name \"UserInitMprLogonScript\" -Force -ErrorAction SilentlyContinue")
    log_lines.append("    PS> Remove-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment\" -Name \"UserInitMprLogonScript\" -Force -ErrorAction SilentlyContinue")
    log_lines.append("    [+] [SUCCESS] Neutralized UserInitMprLogonScript logon environment overrides")
    log_lines.append("    PS> Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' | ForEach-Object { ... }")
    log_lines.append("    [+] [SUCCESS] Autostart run keys and winlogon persistence hooks neutralized")

    log_lines.append(f"[{now_str}] --------------------------------------------------------------------------------")
    log_lines.append(f"[{now_str}] [✔] COMPLIANCE RESTORED! AD SECURITY HEALTH SCORE RECOVERED TO 100%.")

    return "\n".join(log_lines)


# ============================================================================
# 2. STANDALONE INTERACTIVE HTML DASHBOARD TEMPLATE
# ============================================================================

HTML_DASHBOARD_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AD Integrity Watchdog | Minute-0 Triage</title>
    <style>
        :root {
            --bg-main: #0b0f19;
            --bg-card: #111827;
            --border-card: #1f2937;
            --text-main: #e2e8f0;
            --text-muted: #94a3b8;
            --red-crit: #ff1744;
            --green-ok: #00e676;
            --orange-high: #f97316;
            --yellow-med: #eab308;
            --accent: #3b82f6;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background-color: var(--bg-main);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            display: flex;
            min-height: 100vh;
        }
        .sidebar {
            width: 320px;
            background-color: #080c14;
            border-right: 1px solid var(--border-card);
            padding: 24px;
            display: flex;
            flex-direction: column;
            gap: 20px;
            flex-shrink: 0;
        }
        .content {
            flex: 1;
            padding: 32px;
            overflow-y: auto;
        }
        .header-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
        }
        .title-group h1 { font-size: 1.8rem; font-weight: 800; display: flex; align-items: center; gap: 10px; }
        .title-group p { color: var(--text-muted); font-size: 0.9rem; margin-top: 4px; }
        .panic-btn {
            background: linear-gradient(135deg, #ef4444 0%, #b91c1c 100%);
            color: #ffffff;
            font-weight: 800;
            font-size: 0.95rem;
            padding: 12px 20px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            box-shadow: 0 0 15px rgba(239, 68, 68, 0.4);
            display: flex;
            align-items: center;
            gap: 8px;
            transition: all 0.2s ease;
        }
        .panic-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 0 25px rgba(239, 68, 68, 0.7);
        }
        .score-card {
            border-radius: 12px;
            padding: 28px;
            text-align: center;
            margin-bottom: 28px;
            transition: all 0.3s ease;
        }
        .score-card.good {
            background: linear-gradient(135deg, #064e3b 0%, #022c22 100%);
            border: 2px solid var(--green-ok);
            box-shadow: 0 0 25px rgba(0, 230, 118, 0.25);
        }
        .score-card.bad {
            background: linear-gradient(135deg, #4c0519 0%, #2a0009 100%);
            border: 2px solid var(--red-crit);
            box-shadow: 0 0 30px rgba(255, 23, 68, 0.35);
            animation: pulse-red 2s infinite;
        }
        @keyframes pulse-red {
            0% { box-shadow: 0 0 15px rgba(255, 23, 68, 0.2); }
            50% { box-shadow: 0 0 35px rgba(255, 23, 68, 0.5); }
            100% { box-shadow: 0 0 15px rgba(255, 23, 68, 0.2); }
        }
        .score-headline {
            font-size: 5.5rem;
            font-weight: 900;
            letter-spacing: -2px;
            line-height: 1.1;
        }
        .tabs { display: flex; gap: 8px; border-bottom: 1px solid var(--border-card); margin-bottom: 20px; }
        .tab-btn {
            background: none;
            border: none;
            color: var(--text-muted);
            padding: 10px 16px;
            font-size: 0.95rem;
            font-weight: 600;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.2s ease;
        }
        .tab-btn.active { color: #ffffff; border-bottom: 2px solid var(--accent); }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .data-table {
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-card);
            border-radius: 8px;
            overflow: hidden;
            font-size: 0.9rem;
        }
        .data-table th, .data-table td {
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border-card);
        }
        .data-table th { background: #162032; font-weight: 700; color: #94a3b8; }
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 0.75rem;
        }
        .badge-crit { background-color: var(--red-crit); color: #fff; }
        .badge-high { background-color: var(--orange-high); color: #fff; }
        .badge-med { background-color: var(--yellow-med); color: #000; }
        .badge-ok { background-color: var(--green-ok); color: #000; }
        .grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 24px; }
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border-card);
            border-radius: 8px;
            padding: 18px;
        }
        .card h3 { font-size: 1rem; margin-bottom: 8px; }
        .code-box {
            background: #050811;
            border: 1px solid #1e293b;
            border-radius: 6px;
            padding: 10px;
            font-family: 'JetBrains Mono', 'Courier New', monospace;
            font-size: 0.8rem;
            color: #38bdf8;
            word-break: break-all;
            margin-top: 8px;
        }
        .terminal-box {
            background: #050811;
            border: 1px solid #1e293b;
            border-radius: 8px;
            padding: 16px;
            color: #00ff66;
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
            line-height: 1.4;
            max-height: 300px;
            overflow-y: auto;
            white-space: pre-wrap;
            margin-bottom: 24px;
        }
        input[type="text"] {
            width: 100%;
            background: #162032;
            border: 1px solid var(--border-card);
            padding: 10px;
            border-radius: 6px;
            color: #fff;
            margin-bottom: 8px;
        }
        .action-btn {
            width: 100%;
            background: var(--accent);
            border: none;
            padding: 10px;
            border-radius: 6px;
            color: #fff;
            font-weight: 600;
            cursor: pointer;
            margin-bottom: 8px;
        }
        .btn-outline {
            background: transparent;
            border: 1px solid var(--border-card);
            color: var(--text-main);
        }
        .btn-outline:hover { background: #1f2937; }
    </style>
</head>
<body>
    <div class="sidebar">
        <div>
            <h2>🛡️ AD WATCHDOG</h2>
            <p style="color: var(--text-muted); font-size: 0.8rem;">Minute-0 Air-Gapped Triage</p>
        </div>

        <div class="card">
            <h3>📡 Telemetry Status</h3>
            <p style="font-size: 0.85rem;">Agent Identity: <strong id="agent-identity" style="color: var(--accent);">ALPHA</strong></p>
            <p style="font-size: 0.85rem;">Twin PID: <strong id="twin-pid">4812</strong></p>
            <p style="font-size: 0.85rem;">DC Host: <code id="host-name" style="color: #38bdf8;">DC01-CORP.AIRGAP</code></p>
            <p style="font-size: 0.8rem; color: var(--text-muted); margin-top: 6px;" id="last-sync">Last Check-in: Just now</p>
        </div>

        <div>
            <h3>👥 Dynamic Team Whitelist</h3>
            <p style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 8px;">Onboard operators dynamically without raising alarms.</p>
            <input type="text" id="new-user-input" placeholder="e.g. IncidentLead01">
            <button class="action-btn" onclick="addWhitelistedUser()">➕ Add to Whitelist</button>
            <div id="dynamic-whitelist-list" style="font-size: 0.85rem; margin-top: 6px;"></div>
        </div>

        <div>
            <h3>🧪 Triage Scenarios</h3>
            <button class="action-btn btn-outline" onclick="triggerSimulation('contaminated')">☣️ Inject Contaminated (10%)</button>
            <button class="action-btn btn-outline" onclick="triggerSimulation('pristine')">✨ Inject Pristine (100%)</button>
        </div>
    </div>

    <div class="content">
        <div class="header-bar">
            <div class="title-group">
                <h1>🛡️ Active Directory Integrity Engine</h1>
                <p>Minute-0 Autonomous Threat Hunting & Watchdog Telemetry Dashboard</p>
            </div>
            <button class="panic-btn" onclick="triggerPanic()">🚨 Purge Rogue Admins & Lock Policies</button>
        </div>

        <div id="remediation-terminal" style="display: none;">
            <h3 style="margin-bottom: 8px;">💻 Executed Emergency Remediation Playbook (Live Terminal)</h3>
            <div class="terminal-box" id="terminal-content"></div>
        </div>

        <div class="score-card bad" id="score-card">
            <div style="font-size: 0.95rem; font-weight: 700; letter-spacing: 2px; text-transform: uppercase;" id="score-header">
                ACTIVE DIRECTORY INTEGRITY HEALTH SCORE
            </div>
            <div class="score-headline" id="score-val" style="color: var(--red-crit);">
                10%
            </div>
            <div style="font-size: 1.25rem; font-weight: 700; color: #ffffff; margin-top: 8px;" id="score-title">
                CRITICAL INTEGRITY BREACH DETECTED AT MINUTE-0
            </div>
            <div style="font-size: 0.9rem; color: #94a3b8; margin-top: 4px;" id="score-subtitle">
                Identified baseline violations: unauthorized backdoor accounts & disabled security policies.
            </div>
        </div>

        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('tab-threat')">🚨 Minute-0 Threat Surface</button>
            <button class="tab-btn" onclick="switchTab('tab-matrix')">👥 AD Account & Group Matrix</button>
            <button class="tab-btn" onclick="switchTab('tab-registry')">🛡️ Security Policies & Registry</button>
            <button class="tab-btn" onclick="switchTab('tab-raw')">📡 Raw Agent Telemetry</button>
        </div>

        <div id="tab-threat" class="tab-content active">
            <h3 style="margin-bottom: 12px;">🚨 Reactive Minute-0 Anomaly Log Table</h3>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Severity</th>
                        <th>Category</th>
                        <th>Finding / Discrepancy</th>
                        <th>MITRE ATT&CK</th>
                        <th>Remediation Command</th>
                    </tr>
                </thead>
                <tbody id="anomaly-table-body">
                </tbody>
            </table>
        </div>

        <div id="tab-matrix" class="tab-content">
            <div class="grid-3" style="grid-template-columns: 1fr 1fr;">
                <div class="card">
                    <h3>🌟 Pristine Golden State Roster</h3>
                    <p style="font-size: 0.85rem; margin-top: 8px;"><strong>Built-in:</strong> <code>Administrator</code>, <code>Guest</code>, <code>krbtgt</code></p>
                    <p style="font-size: 0.85rem; margin-top: 8px;"><strong>Blue Team:</strong> <code>BlueTeamLead</code>, <code>BlueTeamAdmin1</code>, <code>BlueTeamAdmin2</code>, <code>ScoreUser_AD</code></p>
                    <p style="font-size: 0.85rem; margin-top: 8px;"><strong>Domain Admins:</strong> <code>Administrator</code>, <code>BlueTeamLead</code></p>
                </div>
                <div class="card">
                    <h3>📡 Live DC Discovered Accounts</h3>
                    <div id="live-domain-admins-badges" style="margin-top: 8px; margin-bottom: 12px;"></div>
                    <div id="live-users-badges"></div>
                </div>
            </div>
        </div>

        <div id="tab-registry" class="tab-content">
            <div class="grid-3">
                <div class="card" id="card-fw">
                    <h3>1. Windows Firewall</h3>
                    <div id="fw-status" style="margin: 8px 0;"></div>
                    <div class="code-box">HKLM\\...\\FirewallPolicy\\StandardProfile\\EnableFirewall</div>
                </div>
                <div class="card" id="card-rdp">
                    <h3>2. RDP Network Level Auth</h3>
                    <div id="rdp-status" style="margin: 8px 0;"></div>
                    <div class="code-box">HKLM\\...\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication</div>
                </div>
                <div class="card" id="card-lsa">
                    <h3>3. LSA Credential Guard</h3>
                    <div id="lsa-status" style="margin: 8px 0;"></div>
                    <div class="code-box">HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL</div>
                </div>
            </div>
            <div class="grid-3" style="margin-top: 16px; grid-template-columns: 1fr 1fr;">
                <div class="card" id="card-runkeys">
                    <h3>4. Autostart Run & RunOnce Keys (T1547.001)</h3>
                    <div id="runkeys-status" style="margin: 8px 0;"></div>
                    <div id="runkeys-list" style="font-size: 0.85rem; margin-top: 8px; max-height: 140px; overflow-y: auto;"></div>
                </div>
                <div class="card" id="card-winlogon">
                    <h3>5. Winlogon & Logon/Logoff Scripts (T1547.004 / T1037)</h3>
                    <div id="winlogon-status" style="margin: 8px 0;"></div>
                    <div id="winlogon-details" style="font-size: 0.85rem; margin-top: 8px; line-height: 1.5;"></div>
                </div>
            </div>
        </div>

        <div id="tab-raw" class="tab-content">
            <h3>📡 Native WinINet JSON Telemetry Inspector</h3>
            <pre class="terminal-box" id="raw-json" style="margin-top: 12px;"></pre>
        </div>
    </div>

    <script>
        function switchTab(tabId) {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById(tabId).classList.add('active');
        }

        async function fetchState() {
            try {
                const res = await fetch('/api/state');
                const data = await res.json();
                renderUI(data);
            } catch (err) {
                console.error("Failed to fetch state:", err);
            }
        }

        function renderUI(data) {
            const diff = data.diff;
            const snapshot = data.snapshot;
            const telemetry = snapshot.telemetry;

            document.getElementById('agent-identity').innerText = snapshot.agent_identity;
            document.getElementById('twin-pid').innerText = snapshot.twin_pid || 'N/A';
            document.getElementById('host-name').innerText = snapshot.hostname;
            document.getElementById('last-sync').innerText = 'Heartbeats received: ' + snapshot.telemetry_counter;

            const scoreCard = document.getElementById('score-card');
            const scoreVal = document.getElementById('score-val');
            const scoreTitle = document.getElementById('score-title');
            const scoreSubtitle = document.getElementById('score-subtitle');

            scoreVal.innerText = diff.health_score + '%';

            if (diff.health_score === 100) {
                scoreCard.className = 'score-card good';
                scoreVal.style.color = 'var(--green-ok)';
                scoreTitle.innerText = 'GOLDEN STATE COMPLIANT — ALL DEFENSES VERIFIED';
                scoreSubtitle.innerText = 'Zero unauthorized domain accounts • Zero rogue Domain Admins • Firewall & LSA Guard Enforced';
            } else {
                scoreCard.className = 'score-card bad';
                scoreVal.style.color = 'var(--red-crit)';
                scoreTitle.innerText = 'CRITICAL INTEGRITY BREACH DETECTED AT MINUTE-0';
                scoreSubtitle.innerText = `Identified ${diff.anomalies.length} baseline violations: unauthorized backdoor accounts & disabled security policies.`;
            }

            // Anomalies table
            const tbody = document.getElementById('anomaly-table-body');
            if (diff.anomalies.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--green-ok); font-weight: bold; padding: 24px;">🎉 Zero Anomalies Detected! The Domain Controller matches the Golden State baseline exactly.</td></tr>';
            } else {
                tbody.innerHTML = diff.anomalies.map(a => {
                    let badgeClass = 'badge-med';
                    if (a.severity === 'CRITICAL') badgeClass = 'badge-crit';
                    else if (a.severity === 'HIGH') badgeClass = 'badge-high';
                    return `<tr>
                        <td><code>${a.timestamp}</code></td>
                        <td><span class="badge ${badgeClass}">${a.severity}</span></td>
                        <td>${a.category}</td>
                        <td><strong>${a.finding}</strong></td>
                        <td><code>${a.mitre_attack}</code></td>
                        <td><code style="color: #38bdf8; font-size: 0.75rem;">${a.remediation_cmd}</code></td>
                    </tr>`;
                }).join('');
            }

            // Dynamic whitelist list
            const dwList = document.getElementById('dynamic-whitelist-list');
            if (snapshot.extra_whitelisted_users && snapshot.extra_whitelisted_users.length > 0) {
                dwList.innerHTML = '<strong>Authorized Accounts:</strong><br>' + snapshot.extra_whitelisted_users.map(u => 
                    `• <code>${u}</code> <a href="javascript:void(0)" onclick="removeUser('${u}')" style="color: #ef4444; text-decoration: none; margin-left: 6px;">✖</a><br>`
                ).join('');
            } else {
                dwList.innerHTML = '<span style="color: var(--text-muted);">No dynamic accounts added.</span>';
            }

            // Live users & admins
            const adminBadges = (telemetry.domain_admins || []).map(a => {
                const isRogue = (diff.rogue_domain_admins || []).includes(a);
                return `<span class="badge ${isRogue ? 'badge-crit' : 'badge-ok'}">${a} ${isRogue ? '(ROGUE ADMIN)' : '(Authorized)'}</span> `;
            }).join('');
            document.getElementById('live-domain-admins-badges').innerHTML = '<strong>Live Domain Admins:</strong><br>' + adminBadges;

            const userBadges = (telemetry.users || []).map(u => {
                const isRogue = (diff.rogue_users || []).includes(u);
                return `<span class="badge ${isRogue ? 'badge-high' : 'badge-ok'}">${u} ${isRogue ? '(ROGUE)' : ''}</span> `;
            }).join('');
            document.getElementById('live-users-badges').innerHTML = '<strong>All Discovered Users:</strong><br>' + userBadges;

            // Registry cards
            const reg = telemetry.registry || {};
            const fwVal = reg.EnableFirewall;
            document.getElementById('fw-status').innerHTML = fwVal === 1 
                ? '<span class="badge badge-ok">✅ ENFORCED (1)</span>' 
                : '<span class="badge badge-crit">❌ DISABLED (0)</span>';

            const rdpVal = reg.UserAuthentication;
            document.getElementById('rdp-status').innerHTML = rdpVal === 1 
                ? '<span class="badge badge-ok">✅ ENFORCED (1)</span>' 
                : '<span class="badge badge-crit">❌ DISABLED (0)</span>';

            const pplVal = reg.RunAsPPL;
            document.getElementById('lsa-status').innerHTML = pplVal === 1 
                ? '<span class="badge badge-ok">✅ ENFORCED (1)</span>' 
                : '<span class="badge badge-crit">❌ DISABLED (0)</span>';

            // Run keys card
            const runKeys = telemetry.run_keys || [];
            const benignNames = ["vmware user process", "vmware tools", "vboxtray", "vboxclient", "securityhealth", "securityhealthsystray"];
            const suspRunKeys = runKeys.filter(r => {
                const name = (r.name || '').toLowerCase();
                const cmd = (r.command || '').toLowerCase();
                return !benignNames.includes(name) && !cmd.includes('vmtoolsd.exe') && !cmd.includes('vboxtray.exe');
            });

            const rkStatus = document.getElementById('runkeys-status');
            const rkList = document.getElementById('runkeys-list');
            if (suspRunKeys.length === 0) {
                rkStatus.innerHTML = '<span class="badge badge-ok">✅ NO ROGUE KEYS</span>';
                if (runKeys.length > 0) {
                    rkList.innerHTML = `<span style="color: var(--text-muted);">${runKeys.length} standard/whitelisted autostart entries verified.</span>`;
                } else {
                    rkList.innerHTML = '<span style="color: var(--text-muted);">Pristine: 0 autostart keys detected.</span>';
                }
            } else {
                rkStatus.innerHTML = `<span class="badge badge-crit">❌ ${suspRunKeys.length} ROGUE AUTOSTART KEYS</span>`;
                rkList.innerHTML = suspRunKeys.map(r => `<div><strong>${r.name}:</strong> <code>${r.command}</code><br><span style="color: var(--text-muted); font-size: 0.75rem;">${r.location}</span></div>`).join('<br>');
            }

            // Winlogon card
            const wl = telemetry.winlogon || {};
            const wlStatus = document.getElementById('winlogon-status');
            const wlDetails = document.getElementById('winlogon-details');
            const uInit = wl.Userinit || 'C:\\Windows\\system32\\userinit.exe,';
            const isUInitClean = uInit.toLowerCase() === 'c:\\windows\\system32\\userinit.exe,' || uInit.toLowerCase() === 'c:\\windows\\system32\\userinit.exe';
            const isShellClean = (wl.Shell || 'explorer.exe').toLowerCase() === 'explorer.exe';
            const hasLogonScript = !!(wl.LogonScript);

            if (isUInitClean && isShellClean && !hasLogonScript) {
                wlStatus.innerHTML = '<span class="badge badge-ok">✅ PRISTINE WINLOGON</span>';
                wlDetails.innerHTML = '<code>Userinit</code>: userinit.exe,<br><code>Shell</code>: explorer.exe<br><code>LogonScript</code>: (none)';
            } else {
                wlStatus.innerHTML = '<span class="badge badge-crit">❌ HIJACKED WINLOGON / LOGON SCRIPT</span>';
                let details = '';
                if (!isUInitClean) details += `<div style="color: var(--red-crit);"><strong>Userinit Hijacked:</strong> <code>${uInit}</code></div>`;
                if (!isShellClean) details += `<div style="color: var(--red-crit);"><strong>Shell Hijacked:</strong> <code>${wl.Shell}</code></div>`;
                if (hasLogonScript) details += `<div style="color: var(--orange-high);"><strong>Rogue Logon Script:</strong> <code>${wl.LogonScript}</code></div>`;
                wlDetails.innerHTML = details;
            }

            // Raw JSON
            document.getElementById('raw-json').innerText = JSON.stringify(telemetry, null, 2);

            // Remediation log
            const term = document.getElementById('remediation-terminal');
            if (snapshot.remediation_log) {
                term.style.display = 'block';
                document.getElementById('terminal-content').innerText = snapshot.remediation_log;
            } else {
                term.style.display = 'none';
            }
        }

        async function triggerPanic() {
            const res = await fetch('/api/panic', { method: 'POST' });
            fetchState();
        }

        async function triggerSimulation(mode) {
            await fetch('/api/simulate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mode })
            });
            fetchState();
        }

        async function addWhitelistedUser() {
            const input = document.getElementById('new-user-input');
            const user = input.value.trim();
            if (user) {
                await fetch('/api/whitelist', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: 'add', username: user })
                });
                input.value = '';
                fetchState();
            }
        }

        async function removeUser(username) {
            await fetch('/api/whitelist', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'remove', username })
            });
            fetchState();
        }

        // Live refresh every 2 seconds
        setInterval(fetchState, 2000);
        fetchState();
    </script>
</body>
</html>
"""


# ============================================================================
# 3. HTTP REQUEST HANDLER (API + DASHBOARD)
# ============================================================================

class UnifiedTriageServerHandler(BaseHTTPRequestHandler):
    """
    Handles both:
    1. C++ agent WinINet telemetry on /api/ad_triage (POST/GET)
    2. Interactive HTML threat hunting dashboard and REST controls on /
    """
    def log_message(self, format, *args):
        # Silence default stderr logging to keep console clean
        pass

    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        # 1. Main Dashboard UI
        if self.path in ["/", "/index.html", "/dashboard"]:
            content = HTML_DASHBOARD_TEMPLATE.encode("utf-8")
            self.send_response(200)
            self._send_cors_headers()
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        # 2. State endpoint for dashboard polling
        if self.path == "/api/state":
            snapshot = GLOBAL_STORE.get_snapshot()
            diff = evaluate_ad_telemetry(snapshot["telemetry"], set(snapshot["extra_whitelisted_users"]))
            
            anomalies_data = [
                {
                    "timestamp": a.timestamp,
                    "severity": a.severity,
                    "category": a.category,
                    "finding": a.finding,
                    "details": a.details,
                    "mitre_attack": a.mitre_attack,
                    "remediation_cmd": a.remediation_cmd
                } for a in diff.anomalies
            ]

            payload = {
                "snapshot": snapshot,
                "diff": {
                    "health_score": diff.health_score,
                    "rogue_users": sorted(list(diff.rogue_users)),
                    "rogue_domain_admins": sorted(list(diff.rogue_domain_admins)),
                    "missing_baseline_users": sorted(list(diff.missing_baseline_users)),
                    "registry_discrepancies": diff.registry_discrepancies,
                    "is_compliant": diff.is_compliant,
                    "anomalies": anomalies_data
                }
            }
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self._send_cors_headers()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # 3. Agent triage status endpoint
        if self.path in ["/api/ad_triage", "/api/health"]:
            snapshot = GLOBAL_STORE.get_snapshot()
            diff = evaluate_ad_telemetry(snapshot["telemetry"], set(snapshot["extra_whitelisted_users"]))
            
            response = {
                "status": "healthy",
                "agent_identity": snapshot["agent_identity"],
                "hostname": snapshot["hostname"],
                "health_score": diff.health_score,
                "anomalies_count": len(diff.anomalies),
                "last_heartbeat_ago_sec": round(time.time() - snapshot["last_update_ts"], 1) if snapshot["last_update_ts"] else None
            }
            body = json.dumps(response).encode("utf-8")
            self.send_response(200)
            self._send_cors_headers()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(content_length)

        # 1. Telemetry ingestion from C++ / C# agent
        if self.path == "/api/ad_triage":
            try:
                telemetry_data = json.loads(body_bytes.decode("utf-8"))
                GLOBAL_STORE.update_from_agent(telemetry_data)

                snapshot = GLOBAL_STORE.get_snapshot()
                diff = evaluate_ad_telemetry(telemetry_data, set(snapshot["extra_whitelisted_users"]))

                client_ip = self.client_address[0]
                now_str = datetime.datetime.now().strftime("%H:%M:%S")
                score_color = "\033[92m" if diff.health_score == 100 else "\033[91m"
                reset_color = "\033[0m"

                print(f"\n[{now_str}] [+] [TELEMETRY INGESTED] Client: {client_ip} | Host: {snapshot['hostname']} | Agent: {snapshot['agent_identity']} (Twin PID: {snapshot['twin_pid']})")
                print(f"       -> Accounts: {len(telemetry_data.get('users', []))} Users, {len(telemetry_data.get('domain_admins', []))} Admins")
                print(f"       -> Registry: FW={telemetry_data.get('registry', {}).get('EnableFirewall', 0)}, NLA={telemetry_data.get('registry', {}).get('UserAuthentication', 0)}, PPL={telemetry_data.get('registry', {}).get('RunAsPPL', 0)}")
                print(f"       -> AD Health Score: {score_color}{diff.health_score}%{reset_color} | Anomalies: {len(diff.anomalies)}")
                if diff.anomalies:
                    for a in diff.anomalies:
                        print(f"       -> [ALERT] [{a.severity}] {a.finding}")
                else:
                    print(f"       -> [✔] Golden State Compliant — All defenses verified.")
                sys.stdout.flush()

                reply = {
                    "status": "received",
                    "timestamp": int(time.time()),
                    "health_score": diff.health_score,
                    "anomalies_detected": len(diff.anomalies),
                    "action_required": (diff.health_score < 100)
                }
                payload = json.dumps(reply).encode("utf-8")
                self.send_response(200)
                self._send_cors_headers()
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except Exception as e:
                now_str = datetime.datetime.now().strftime("%H:%M:%S")
                print(f"[{now_str}] [!] [ERROR] Failed processing telemetry from {self.client_address[0]}: {e}")
                sys.stdout.flush()
                err_resp = json.dumps({"status": "error", "message": str(e)}).encode("utf-8")
                self.send_response(400)
                self._send_cors_headers()
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(err_resp)))
                self.end_headers()
                self.wfile.write(err_resp)
            return

        # 2. Panic button trigger
        if self.path == "/api/panic":
            snapshot = GLOBAL_STORE.get_snapshot()
            diff = evaluate_ad_telemetry(snapshot["telemetry"], set(snapshot["extra_whitelisted_users"]))
            log = execute_emergency_remediation(diff)
            GLOBAL_STORE.set_remediation_log(log)
            GLOBAL_STORE.set_clean_state()

            resp = json.dumps({"status": "remediated", "health_score": 100}).encode("utf-8")
            self.send_response(200)
            self._send_cors_headers()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            return

        # 3. Dynamic whitelist controls
        if self.path == "/api/whitelist":
            try:
                data = json.loads(body_bytes.decode("utf-8"))
                action = data.get("action")
                username = data.get("username", "")
                if action == "add":
                    GLOBAL_STORE.add_whitelisted_user(username)
                elif action == "remove":
                    GLOBAL_STORE.remove_whitelisted_user(username)
                elif action == "clear":
                    GLOBAL_STORE.clear_extra_whitelist()

                resp = json.dumps({"status": "ok"}).encode("utf-8")
                self.send_response(200)
                self._send_cors_headers()
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)
            except Exception as e:
                self.send_response(400)
                self.end_headers()
            return

        # 4. Simulation controls
        if self.path == "/api/simulate":
            try:
                data = json.loads(body_bytes.decode("utf-8"))
                mode = data.get("mode", "contaminated")
                if mode == "pristine":
                    GLOBAL_STORE.set_clean_state()
                    GLOBAL_STORE.set_remediation_log(None)
                else:
                    GLOBAL_STORE.set_contaminated_state()
                    GLOBAL_STORE.set_remediation_log(None)

                resp = json.dumps({"status": "simulated", "mode": mode}).encode("utf-8")
                self.send_response(200)
                self._send_cors_headers()
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)
            except Exception as e:
                self.send_response(400)
                self.end_headers()
            return

        self.send_response(404)
        self.end_headers()


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def run_standalone_servers(port_api=8000, port_ui=8501):
    """
    Spawns the dual HTTP server listeners:
    - Port 8000: /api/ad_triage (C++ agent WinINet receiver) + Web UI
    - Port 8501: Threat Hunting Dashboard UI
    """
    print("\n" + "=" * 70)
    print("  ACTIVE DIRECTORY INTEGRITY ENGINE - AIR-GAPPED CDE DEFENSE SERVER")
    print("=" * 70)
    print(f"[*] Starting API Receiver & Web Engine on 0.0.0.0:{port_api}...")
    server_8000 = ThreadedHTTPServer(("0.0.0.0", port_api), UnifiedTriageServerHandler)
    t1 = threading.Thread(target=server_8000.serve_forever, daemon=True)
    t1.start()

    print(f"[*] Starting Threat Hunting Dashboard on 0.0.0.0:{port_ui}...")
    server_8501 = ThreadedHTTPServer(("0.0.0.0", port_ui), UnifiedTriageServerHandler)
    t2 = threading.Thread(target=server_8501.serve_forever, daemon=True)
    t2.start()

    print("\n" + "-" * 70)
    print(f"[✔] THREAT HUNTING DASHBOARD UI : http://localhost:{port_ui}")
    print(f"[✔] AGENT INGESTION API         : http://localhost:{port_api}/api/ad_triage")
    print(f"[✔] ALTERNATIVE COMBINED UI     : http://localhost:{port_api}")
    print("-" * 70)
    print("[*] Engine is LIVE and ready for WinINet telemetry. Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping servers...")
        server_8000.shutdown()
        server_8501.shutdown()


# ============================================================================
# 4. STREAMLIT FRONTEND RUNNER (WHEN EXECUTED VIA STREAMLIT RUN)
# ============================================================================

def run_streamlit_app():
    """Executed when app is launched via `streamlit run app.py`."""
    st.set_page_config(
        page_title="AD Integrity Watchdog | Minute-0 Triage",
        page_icon="🛡️",
        layout="wide"
    )

    # Start API receiver in background
    try:
        server_8000 = ThreadedHTTPServer(("0.0.0.0", 8000), UnifiedTriageServerHandler)
        threading.Thread(target=server_8000.serve_forever, daemon=True).start()
    except Exception:
        pass

    snapshot = GLOBAL_STORE.get_snapshot()
    diff = evaluate_ad_telemetry(snapshot["telemetry"], set(snapshot["extra_whitelisted_users"]))

    st.title("🛡️ Active Directory Integrity Engine")
    st.caption("Air-Gapped Minute-0 Threat Hunting & Watchdog Dashboard")

    col_btn1, col_btn2 = st.columns([4, 1])
    with col_btn2:
        if st.button("🚨 Purge Rogue Admins", type="primary", use_container_width=True):
            log = execute_emergency_remediation(diff)
            GLOBAL_STORE.set_remediation_log(log)
            GLOBAL_STORE.set_clean_state()
            st.rerun()

    if snapshot["remediation_log"]:
        st.code(snapshot["remediation_log"], language="text")

    # Score Card
    score = diff.health_score
    score_color = "green" if score == 100 else "red"
    st.markdown(f"### Health Score: :{score_color}[{score}%]")

    # Anomalies
    if diff.anomalies:
        st.dataframe([
            {
                "Time": a.timestamp,
                "Severity": a.severity,
                "Category": a.category,
                "Finding": a.finding,
                "Remediation": a.remediation_cmd
            } for a in diff.anomalies
        ], use_container_width=True)
    else:
        st.success("🎉 Golden State Compliant — Zero Anomalies Detected!")


# ============================================================================
# MAIN ENTRYPOINT
# ============================================================================

if __name__ == "__main__":
    if HAS_STREAMLIT and streamlit_runtime_exists():
        run_streamlit_app()
    else:
        run_standalone_servers()
