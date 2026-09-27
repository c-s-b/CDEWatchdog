# Central Off-Band Baseline Diff Engine & Server (`/ad_server`)

Hosts the central telemetry receiver and the Streamlit-powered Threat Hunting Dashboard in a unified, multi-threaded analytical process.

## Architectural Architecture

```
[ Domain Controller ]                          [ Central Analytical Server ]
  agent.exe (Alpha/Bravo)                         app.py (Streamlit + HTTP Daemon)
       │                                                      │
       │─── WinINet HTTP POST /api/ad_triage ────────────────▶│ (Port 8000 API Receiver)
       │    (AD Users, Domain Admins, Registry Keys)          │
       │                                                      │
       │                                                      ▼
       │                                            [ Set-Difference Engine ]
       │                                            - Golden State Roster Diff
       │                                            - Privileged Group Audit
       │                                            - Registry Policy Check
       │                                            - Health Score Scoring
       │                                                      │
       │                                                      ▼
       │                                            [ Streamlit Dashboard ]
       │                                            - Health Score Banner
       │                                            - Anomaly Log Table
       │                                            - Onboarding Buffer
       │                                            - Panic Button Remediation
```

## Golden State Baseline Whitelists (Hardcoded)

1. **Active Directory Pristine Users**:
   - System: `["Administrator", "Guest", "krbtgt"]`
   - Blue Team Roster: `["BlueTeamLead", "BlueTeamAdmin1", "BlueTeamAdmin2", "ScoreUser_AD"]`
   - *Rule*: Any user discovered outside this pool is flagged as a pre-installed backdoor.

2. **Privileged Domain Groups**:
   - `Domain Admins`: Only `["Administrator", "BlueTeamLead"]`
   - `Enterprise Admins`: Only `["Administrator"]`

3. **Hardened Security Registry Keys**:
   - `EnableFirewall` == `1`
   - `UserAuthentication` (RDP NLA) == `1`
   - `RunAsPPL` (LSA Credential Protection against Mimikatz) == `1`

## Health Score Calculation Formula
- Baseline: **100%**
- **-40%** for any rogue Domain Admin account
- **-30%** for a disabled firewall (`EnableFirewall != 1`)
- **-20%** for weakened RDP/LSA configs (`UserAuthentication != 1` or `RunAsPPL != 1`)
- **-10%** per standard rogue backdoor user

## Running the Server & Dashboard
```bash
pip install -r requirements.txt
streamlit run app.py --server.port 8501 --server.address 0.0.0.0
```
- Streamlit Web UI: `http://localhost:8501`
- WinINet Agent API Receiver: `http://localhost:8000/api/ad_triage`
