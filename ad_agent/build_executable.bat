@echo off
REM ==============================================================================
REM Active Directory Watchdog: Instant 1-Click Windows Executable Generator
REM Uses Windows native built-in compiler (Zero external downloads required)
REM Works on 100% of air-gapped Windows Servers (2012/2016/2019/2022)
REM ==============================================================================

setlocal enabledelayedexpansion
title AD Watchdog Executable Builder

echo.
echo ==============================================================================
echo   AD WATCHDOG: INSTANT NATIVE WINDOWS EXECUTABLE GENERATOR
echo ==============================================================================
echo.

:: 1. Check for MSVC cl.exe first (if running in Visual Studio Command Prompt)
where cl.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [*] Detected MSVC compiler (cl.exe). Compiling native C++ engine...
    cl.exe /O2 /EHsc /MT /std:c++14 agent.cpp ^
        /link /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup ^
        netapi32.lib advapi32.lib wininet.lib shlwapi.lib user32.lib ^
        /OUT:agent.exe
    if %ERRORLEVEL% EQU 0 goto SUCCESS
)

:: 2. Check for MinGW g++ next
where g++ >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [*] Detected MinGW (g++). Compiling native C++ engine...
    g++ -O2 -std=c++11 -Wall -static agent.cpp -o agent.exe -mwindows -lnetapi32 -ladvapi32 -lwininet -lshlwapi
    if %ERRORLEVEL% EQU 0 goto SUCCESS
)

:: 3. Use Windows Pre-Installed Native .NET C# Compiler (csc.exe)
echo [*] Compiling zero-dependency native Windows executable using built-in csc.exe...

set CSC_PATH=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "!CSC_PATH!" (
    set CSC_PATH=C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe
)

if not exist "!CSC_PATH!" (
    echo [!] ERROR: Could not locate built-in csc.exe on this Windows system.
    pause
    exit /b 1
)

echo [+] Using native compiler: !CSC_PATH!
"!CSC_PATH!" /target:winexe /optimize+ /platform:anycpu /out:agent.exe agent.cs

if %ERRORLEVEL% NEQ 0 (
    echo [!] Compilation failed!
    pause
    exit /b %ERRORLEVEL%
)

:SUCCESS
echo.
echo [+] Creating twin watchdog persistence binaries...
copy /Y agent.exe agent_alpha.exe >nul
copy /Y agent.exe agent_bravo.exe >nul

echo.
echo ==============================================================================
echo [✔] BUILD COMPLETE! Generated Windows Native Executables:
echo     - agent.exe       (Base Binary - GUI Subsystem / Hidden Background)
echo     - agent_alpha.exe (Primary Watchdog)
echo     - agent_bravo.exe (Companion Watchdog)
echo ==============================================================================
echo To run with Local Web Dashboard and Terminal Triage:
echo     agent_alpha.exe -alpha -debug
echo     Then open your browser to: http://127.0.0.1:8000
echo.
echo Or run the interactive standalone test bench:
echo     test_standalone_vm.bat
echo.
pause
