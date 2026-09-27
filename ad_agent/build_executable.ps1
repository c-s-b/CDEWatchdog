<#
.SYNOPSIS
    1-Click PowerShell Executable Compiler for AD Server
.DESCRIPTION
    Compiles agent.cs into agent.exe, agent_alpha.exe, and agent_bravo.exe
    using native .NET APIs with zero external compiler dependencies.
#>

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "  AD WATCHDOG: POWERSHELL NATIVE EXECUTABLE COMPILER (NO DOWNLOADS)" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan

# 1. Locate C# compiler
$CscPath = "$env:SystemRoot\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $CscPath)) {
    $CscPath = "$env:SystemRoot\Microsoft.NET\Framework\v4.0.30319\csc.exe"
}

if (-not (Test-Path $CscPath)) {
    Write-Error "Could not find built-in csc.exe compiler."
    exit 1
}

Write-Host "[*] Compiler: $CscPath" -ForegroundColor Yellow
Write-Host "[*] Compiling agent.cs -> agent.exe (WindowsApplication / Hidden)..." -ForegroundColor Yellow

$SourceFile = Join-Path $ScriptDir "agent.cs"
$OutFile = Join-Path $ScriptDir "agent.exe"

& $CscPath /target:winexe /optimize+ /platform:anycpu /out:$OutFile $SourceFile

if ($LASTEXITCODE -eq 0 -and (Test-Path $OutFile)) {
    Copy-Item -Path $OutFile -Destination (Join-Path $ScriptDir "agent_alpha.exe") -Force
    Copy-Item -Path $OutFile -Destination (Join-Path $ScriptDir "agent_bravo.exe") -Force

    Write-Host "`n[✔] SUCCESS: Created native executables:" -ForegroundColor Green
    Write-Host "    - agent.exe" -ForegroundColor Green
    Write-Host "    - agent_alpha.exe" -ForegroundColor Green
    Write-Host "    - agent_bravo.exe" -ForegroundColor Green
    Write-Host "`nLaunch Alpha with:" -ForegroundColor Cyan
    Write-Host "    .\agent_alpha.exe -alpha -server 127.0.0.1 -port 8000" -ForegroundColor White
} else {
    Write-Error "Compilation failed."
}
