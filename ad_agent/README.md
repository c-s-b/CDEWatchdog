# Active Directory Integrity Verification & Watchdog Agent (`/ad_agent`)

Ultra-lightweight, native C++ agent designed for Minute-0 deployment on contaminated Windows Domain Controllers in air-gapped Cyber Defense Exercises (CDE).

## Key Capabilities

1. **Native AD User & Group Auditing**
   - Directly calls `NetUserEnum` (level 0) with `FILTER_NORMAL_ACCOUNT` to extract all accounts on the Domain Controller.
   - Queries privileged groups using `NetGroupGetUsers` (target: `Domain Admins`) without invoking PowerShell, WMI, or cmd.exe.
   - Zero command-line execution prevents detection by Red Team audit logs and EDR rules.

2. **Native Win32 Registry Auditing**
   - Direct registry querying via `RegOpenKeyExW` and `RegQueryValueExW` for critical defense policies:
     - `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\EnableFirewall` (and `DomainProfile`)
     - `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication` (RDP NLA)
     - `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` (LSA Credential Guard against Mimikatz)

3. **Dual-Process Mutual Watchdog Persistence**
   - Accepts identity flag `-alpha` or `-bravo`.
   - Takes periodic process snapshots via `CreateToolhelp32Snapshot` (`TH32CS_SNAPPROCESS`).
   - If its twin process (`agent_bravo.exe` or `agent_alpha.exe`) is terminated or killed by red team actors, it immediately copies and re-spawns it with `CREATE_NO_WINDOW | DETACHED_PROCESS`.
   - Mutual self-healing guarantees continuous telemetry exfiltration.

4. **WinINet JSON Exfiltration**
   - Serializes audit results into clean JSON with zero third-party library dependencies.
   - Dispatches telemetry via asynchronous HTTP `POST` requests directly over the Windows WinINet API stack (`InternetOpenA`, `InternetConnectA`, `HttpOpenRequestA`, `HttpSendRequestA`) to the triage receiver (`/api/ad_triage`).

---

## Compilation Instructions

### MinGW-w64 Cross-Compilation (Linux / Windows MSYS2)
```bash
x86_64-w64-mingw32-g++ -O2 -std=c++11 -Wall \
    -static -static-libgcc -static-libstdc++ \
    agent.cpp -o agent.exe \
    -mwindows \
    -lnetapi32 -ladvapi32 -lwininet -lshlwapi
```
Or execute:
```bash
make -C ad_agent
```

### MSVC (Visual Studio Developer Command Prompt)
```cmd
cl.exe /O2 /EHsc /MT /std:c++14 agent.cpp ^
    /link /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup ^
    netapi32.lib advapi32.lib wininet.lib shlwapi.lib user32.lib ^
    /OUT:agent.exe
```
Or run:
```cmd
build_msvc.bat
```

---

## Deployment & Usage on Windows Domain Controller

### Minute-0 Quick Deployment
Deploy both binaries side-by-side on the Domain Controller (e.g. `C:\Windows\System32\` or `C:\ProgramData\ADEngine\`):
```cmd
copy agent.exe agent_alpha.exe
copy agent.exe agent_bravo.exe

:: Launch the Alpha watchdog targeting the central analytics server
start "" agent_alpha.exe -alpha -server 10.0.0.50 -port 8000
```
Alpha will immediately detect that Bravo is missing, spawn `agent_bravo.exe -bravo` in a hidden detached process, and both will monitor each other while dispatching live AD telemetry every 5 seconds.

### Available Command-Line Arguments
| Flag | Description | Default |
|------|-------------|---------|
| `-alpha` | Run as primary watchdog Alpha | `alpha` |
| `-bravo` | Run as twin companion watchdog Bravo | `bravo` |
| `-server <ip>` | Central Server API address | `127.0.0.1` |
| `-port <port>` | Central Server API port | `8000` |
| `-interval <sec>` | Polling & exfiltration interval | `5` |
| `-debug` | Keep console window open for live terminal debugging | `false` (hidden) |
