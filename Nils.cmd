echo off

cls
color 0A

@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Win10.ps1" -include "%~dp0Win10.psm1" -include "%~dp0Additional.psm1" -preset "%~dp0Default.preset" -preset "%~dpn0.preset"


:: @powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Win10.ps1" -include "%~dp0Additional.psm1" ShowSecondsInTaskbar

::pause