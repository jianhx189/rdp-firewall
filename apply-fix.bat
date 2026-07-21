@echo off
setlocal
set "FIX=%~dp0wry-elevated-fix.ps1"

net session >nul 2>&1
if %errorlevel% NEQ 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @('-ExecutionPolicy','Bypass','-File','%FIX%')"
    goto :done
)

echo Running fix as administrator...
powershell -ExecutionPolicy Bypass -File "%FIX%"

:done
endlocal
pause
