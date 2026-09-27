#!/usr/bin/env bash
# ==============================================================================
# MinGW-w64 Cross-Compilation Script
# Produces standalone, statically linked Windows binaries with zero DLL dependencies
# ==============================================================================
set -e

echo "[*] Building Windows Native AD Watchdog binaries with MinGW-w64..."

x86_64-w64-mingw32-g++ -O2 -std=c++11 -Wall \
    -static -static-libgcc -static-libstdc++ \
    agent.cpp -o agent.exe \
    -mwindows \
    -lnetapi32 -ladvapi32 -lwininet -lshlwapi

cp agent.exe agent_alpha.exe
cp agent.exe agent_bravo.exe

echo "[✔] Successfully built:"
echo "    - agent.exe"
echo "    - agent_alpha.exe"
echo "    - agent_bravo.exe"
