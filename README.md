# 🛡️ CDEWatchdog: Minute-0 Active Directory Integrity & Autostart Persistence Engine

An autonomous, air-gapped Active Directory defense and threat hunting system built for high-stakes Cyber Defense Exercises (CDE / CCDC / LockShields). Engineered to detect pre-installed backdoors, rogue Domain Admins, weakened security registry policies, and hidden autostart/logon persistence hooks within seconds of competition kickoff.

---

## 🌟 Key Highlights & Innovations

1. **Zero-Dependency Native Windows Agent (C# / C++):**
   - Compiles directly on any air-gapped Windows Server (2012 R2 through 2022) using the pre-installed native .NET compiler (`csc.exe`). No Visual Studio, Python, SDK, or external package downloads required.
   - Dual-language support: native C# (.NET BCL) and native Win32 C++ (`Netapi32.dll`, `Advapi32.dll`, `WinINet.dll`).
2. **Built-in Local Web Dashboard (Loopback Interface - 127.0.0.1:8000):**
   - Hosts the full, interactive SOC threat-hunting dashboard directly on the Active Directory machine itself using native `System.Net.HttpListener`.
   - **Zero Network Transmission Risk:** 100% air-gapped loopback telemetry prevents packet sniffing (**T1040**), remote telemetry tampering, and analyst IP exposure over contest networks.
   - Features 1-click `[🚨 Purge Rogue Admins & Lock Policies]` panic button, dynamic team whitelist manager, and real-time ATT&CK anomaly tables.
3. **Simultaneous Live Terminal Triage Output (Always Retained):**
   - In addition to the local web GUI, the agent outputs a rich, color-coded terminal triage report to PowerShell / Command Prompt on every audit round (5-minute / 300s interval).
   - Displays the AD Health Score, discovered accounts, rogue domain admins, registry defense posture, autostart persistence keys, and ready-to-paste emergency remediation scripts.
4. **Comprehensive Autostart & Logon Persistence Audit (MITRE ATT&CK):**
   - Scans system and user `Run` / `RunOnce` keys in 32-bit and 64-bit registry views (**T1547.001**).
   - Audits Winlogon `Userinit` and `Shell` hijacking (**T1547.004**).
   - Detects `UserInitMprLogonScript` and Group Policy logon/logoff script backdoors (**T1037.001**).
   - Built-in virtualization whitelist (`vmtoolsd.exe`, `vboxtray.exe`) prevents false alarms on lab VMs.
5. **Mutual Dual-Process Watchdog:**
   - Sibling processes (`agent_alpha` & `agent_bravo`) monitor each other. If a red-team operator kills one via `taskkill`, the surviving companion instantly resurrects it from memory.

---

## 🏗️ Architecture & Project Structure

```
CDEWatchdog/
├── ad_agent/                    # [Native Windows DC Agent & Watchdog]
│   ├── agent.cs                 # Primary zero-dependency C# native watchdog & triage agent
│   ├── agent.cpp                # Native C++ Win32 watchdog engine
│   ├── build_executable.bat     # 1-Click compiler using built-in Windows csc.exe
│   ├── build_executable.ps1     # 1-Click PowerShell compiler script
│   ├── test_standalone_vm.bat   # Interactive test bench: contaminate & clean on local VM
│   ├── build_mingw.sh           # Linux/MSYS2 cross-compilation script
│   ├── build_msvc.bat           # MSVC cl.exe native compilation script
│   ├── Makefile                 # MinGW build automation
│   └── README.md                # Agent deployment & architecture documentation
│
├── ad_server/                   # [Central Analytical Engine & SOC Dashboard]
│   ├── app.py                   # Multi-threaded API receiver (:8000) & SOC Dashboard (:8501)
│   ├── golden_baseline.py       # Golden State set-difference engine & scoring model
│   ├── requirements.txt         # Server runtime dependencies
│   └── README.md                # Scoring formulas & analytical engine documentation
│
├── ad_dashboard/                # [Simulation, Testing & Playbooks]
│   ├── test_injector.py         # Mock telemetry injector for zero-dependency testing
│   ├── remediation_playbook.ps1 # Emergency PowerShell remediation playbook
│   ├── run_dashboard.sh         # Convenience launcher for dashboard
│   └── README.md                # Operator triage documentation
│
└── README.md                    # Master documentation & CDE competition runbook
```

---

## 🎯 The "Golden State" Security Baseline

The engine continuously validates live telemetry against the pristine baseline defined in `golden_baseline.py`:

### A. Pristine User & Group Whitelist
* **Built-in System Accounts:** `Administrator`, `Guest`, `krbtgt`
* **Blue Team Roster:** `BlueTeamLead`, `BlueTeamAdmin1`, `BlueTeamAdmin2`, `ScoreUser_AD`
* **Domain Admins:** Only `Administrator` and `BlueTeamLead`
* **Rule:** Any unwhitelisted account is flagged as a pre-installed backdoor (**T1136.002**) or unauthorized privilege escalation (**T1078.002**).

### B. Hardened Registry Policies
* `EnableFirewall == 1`: StandardProfile and DomainProfile firewall enabled (**T1562.001**).
* `UserAuthentication == 1`: RDP Network Level Authentication (NLA) enforced (**T1021.001**).
* `RunAsPPL == 1`: LSA Protection enabled against LSASS memory scraping / Mimikatz (**T1003.001**).

### C. Persistence & Autostart Policies
* `Run` / `RunOnce`: Must contain zero unauthorized autostart binaries (**T1547.001**).
* `Winlogon Userinit`: Must be `C:\Windows\system32\userinit.exe,` (**T1547.004**).
* `Winlogon Shell`: Must be `explorer.exe` (**T1547.004**).
* `UserInitMprLogonScript`: Must be absent (**T1037.001**).

---

## 📊 AD Security Health Score Formula

$$\text{Health Score} = 100 - \sum \text{Penalties (Clamped } 0\% - 100\%)$$

| Severity | Baseline Discrepancy | Score Penalty | MITRE Technique |
| :---: | :--- | :---: | :--- |
| **CRITICAL** | Rogue Domain Admin detected | **-40%** | T1078.002, T1098 |
| **CRITICAL** | Hijacked Winlogon `Userinit` | **-30%** | T1547.004 |
| **CRITICAL** | Windows Firewall disabled | **-30%** | T1562.001 |
| **CRITICAL** | Hijacked Winlogon `Shell` | **-25%** | T1547.004 |
| **CRITICAL** | Unauthorized `Run` / `RunOnce` Keys | **-15%** per key (up to -25%) | T1547.001 |
| **HIGH** | Weakened RDP NLA or LSA RunAsPPL | **-20%** | T1021.001, T1003.001 |
| **HIGH** | Rogue `UserInitMprLogonScript` | **-20%** | T1037.001 |
| **HIGH** | Rogue Backdoor User account | **-10%** per user (up to -20%) | T1136.002 |

---

## 🚀 Quick Start Guide

### 1. Compile Agent on Windows (Zero Downloads)
On the target Windows Server or VM, run:
```cmd
build_executable.bat
```
This uses Windows built-in `csc.exe` to generate `agent.exe`, `agent_alpha.exe`, and `agent_bravo.exe` in seconds.

### 2. Standalone VM Testing (No AD Server Required)
If testing on a local workstation or VM:
```cmd
test_standalone_vm.bat
```
- Press **`1`** to inject mock red-team contamination (rogue admin, backdoor user, disabled firewall, rogue Run key, logon script).
- Run `agent.exe -debug` to observe real-time detection, score penalty (drops to 0%), and instant PowerShell remediation.
- Press **`2`** to cleanse the system back to 100% pristine.

### 3. Launch Central SOC Server & Dashboard
```bash
# Install dependencies
pip install -r ad_server/requirements.txt

# Start the unified engine
python3 ad_server/app.py
```
- **SOC Threat Hunting Dashboard:** `http://localhost:8501`
- **Agent Telemetry Receiver API:** `http://localhost:8000/api/ad_triage`
- **Interactive Single-Page UI:** `http://localhost:8000`

### 4. Deploy to Domain Controller
Launch with interactive terminal triage and built-in local web dashboard:
```cmd
agent_alpha.exe -alpha -debug
```
- **Local Web Dashboard:** Navigate to `http://127.0.0.1:8000/` in Edge/Chrome on the DC to inspect live threat cards and execute 1-click remediation.
- **Simultaneous Terminal Triage:** Live color-coded report prints to the console on every 5-minute (300s) audit round.
- **Optional Central SOC Exfiltration:** If connecting to a remote central monitoring server:
  ```cmd
  agent_alpha.exe -alpha -server <CENTRAL_SERVER_IP> -port 8000 -interval 300 -debug
  ```

---

## 🛡️ Hackathon Submission Details

- **Author:** Casey Brock (`c-s-b`)
- **Contact:** casey.brock613@gmail.com
- **Track:** Cyber Defense / Incident Response & Infrastructure Integrity
- **License:** MIT License
