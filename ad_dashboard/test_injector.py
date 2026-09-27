#!/usr/bin/env python3
"""
Telemetry Test Injector for Active Directory Integrity Engine
Emulates C++ agent WinINet HTTP POST payloads to test the triage API and dashboard.
Uses standard library only (zero dependencies).
"""

import sys
import json
import time
import argparse
import urllib.request
import urllib.error

CONTAMINATED_PAYLOAD = {
    "agent_identity": "alpha",
    "hostname": "DC01-PROD.CORP.LOCAL",
    "twin_pid": 3892,
    "timestamp": int(time.time()),
    "users": [
        "Administrator",
        "Guest",
        "krbtgt",
        "BlueTeamLead",
        "BlueTeamAdmin1",
        "BlueTeamAdmin2",
        "ScoreUser_AD",
        "adm_backdoor",      # Rogue Domain Admin
        "support_svc",       # Rogue User
        "mimikatz_ghost"     # Rogue User
    ],
    "domain_admins": [
        "Administrator",
        "BlueTeamLead",
        "adm_backdoor"       # Rogue Privilege Escalation
    ],
    "registry": {
        "EnableFirewall": 0,        # Disabled Firewall
        "UserAuthentication": 0,    # Disabled RDP NLA
        "RunAsPPL": 0               # Disabled LSA Protection
    },
    "run_keys": [
        {
            "name": "WinUpdateCheck",
            "command": "powershell.exe -w hidden -enc SQBFAFgA...",
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

PRISTINE_PAYLOAD = {
    "agent_identity": "bravo",
    "hostname": "DC01-PROD.CORP.LOCAL",
    "twin_pid": 4120,
    "timestamp": int(time.time()),
    "users": [
        "Administrator",
        "Guest",
        "krbtgt",
        "BlueTeamLead",
        "BlueTeamAdmin1",
        "BlueTeamAdmin2",
        "ScoreUser_AD"
    ],
    "domain_admins": [
        "Administrator",
        "BlueTeamLead"
    ],
    "registry": {
        "EnableFirewall": 1,
        "UserAuthentication": 1,
        "RunAsPPL": 1
    },
    "run_keys": [],
    "winlogon": {
        "Userinit": "C:\\Windows\\system32\\userinit.exe,",
        "Shell": "explorer.exe",
        "LogonScript": "",
        "LogonLogoffScripts": []
    }
}


def send_telemetry(url: str, payload: dict) -> bool:
    payload["timestamp"] = int(time.time())
    data = json.dumps(payload, indent=2).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"}
    )
    print(f"[*] Dispatching Telemetry to {url}...")
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            status = response.status
            body = response.read().decode("utf-8")
            print(f"[✔] Server Response ({status}):")
            print(body)
            return True
    except urllib.error.URLError as e:
        print(f"[!] Failed to connect to {url}: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Simulate C++ Agent WinINet Telemetry")
    parser.add_argument("--url", default="http://localhost:8000/api/ad_triage", help="API triage endpoint")
    parser.add_argument("--mode", choices=["contaminated", "pristine", "loop"], default="contaminated",
                        help="Telemetry mode to send")
    parser.add_argument("--interval", type=int, default=5, help="Loop interval in seconds")
    args = parser.parse_args()

    if args.mode == "contaminated":
        send_telemetry(args.url, CONTAMINATED_PAYLOAD)
    elif args.mode == "pristine":
        send_telemetry(args.url, PRISTINE_PAYLOAD)
    elif args.mode == "loop":
        print(f"[*] Starting continuous telemetry simulation loop ({args.interval}s interval)...")
        while True:
            send_telemetry(args.url, CONTAMINATED_PAYLOAD)
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
