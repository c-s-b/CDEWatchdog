@echo off
REM ==============================================================================
REM MSVC Build Script: AD Integrity Watchdog Agent
REM Produces zero-dependency, statically-linked, hidden background binaries
REM ==============================================================================

echo [*] Compiling AD Integrity Watchdog Agent with MSVC (Static /MT Runtime)...

cl.exe /O2 /EHsc /MT /std:c++14 agent.cpp ^
    /link /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup ^
    netapi32.lib advapi32.lib wininet.lib shlwapi.lib user32.lib ^
    /OUT:agent.exe

if %ERRORLEVEL% NEQ 0 (
    echo [!] Build Failed!
    exit /b %ERRORLEVEL%
)

copy /Y agent.exe agent_alpha.exe >nul
copy /Y agent.exe agent_bravo.exe >nul

echo [✔] Build Succeeded!
echo     - agent.exe
echo     - agent_alpha.exe
echo     - agent_bravo.exe
