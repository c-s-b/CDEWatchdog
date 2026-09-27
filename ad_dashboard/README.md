# Visual Threat Hunting Surface & Incident Response Dashboard (`/ad_dashboard`)

Interactive incident response console designed for rapid triage, rogue admin purging, dynamic team roster onboarding, and automated baseline diff visualization.

## Key Features

1. **Massive Color-Coded Health Score Metric**
   - High-contrast visual health status banner.
   - **Green (100%)**: Pristine Golden State compliance. All defenses verified.
   - **Red (< 100%)**: Critical integrity breach detected. Immediate operator action required.

2. **Reactive Minute-0 Anomaly Log Table**
   - Discrepancy breakdown sorted by severity:
     - 🔴 **CRITICAL**: Rogue Domain Admins (`-40%`)
     - 🟠 **HIGH**: Disabled Firewall (`-30%`), LSA Protection Disabled (`-20%`), Pre-installed Backdoors (`-10%`)
     - 🟡 **MEDIUM**: RDP NLA Disabled, Missing Baseline Accounts
   - MITRE ATT&CK mapping (T1078, T1098, T1562.001, T1003.001).

3. **Dynamic Sidebar Team Whitelist Buffer**
   - Onboard newly assigned Blue Team operators or incident responders on the fly.
   - Dynamically extends the baseline whitelist buffer without restarting the service or altering Golden State rules.

4. **Panic Button: "Purge Rogue Admins & Lock Policies"**
   - Triggers an instant emergency remediation playbook.
   - Outputs simulated live terminal execution log showing PowerShell commands executed against the DC.
   - Automatically cleanses the memory state and restores health score to 100%.

5. **Integrated Utilities**
   - `run_dashboard.sh`: One-click runner for Streamlit.
   - `test_injector.py`: Zero-dependency test script to simulate C++ agent telemetry payloads.
   - `remediation_playbook.ps1`: Production-ready PowerShell script to execute on the real DC.

## Quick Launch
```bash
# Start Dashboard & API Receiver
./run_dashboard.sh

# Inject Test Contaminated Telemetry
python3 test_injector.py --mode contaminated

# Inject Test Pristine Telemetry
python3 test_injector.py --mode pristine
```
