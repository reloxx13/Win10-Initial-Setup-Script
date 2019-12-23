echo off

cls
color 0A


::Apply Nils Configs
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Win10.ps1" -include "%~dp0Win10.psm1" -include "%~dp0Additional.psm1" -include "%~dp0UninstallCustom.psm1" -include "%~dp0InstallApps.psm1" -preset "%~dp0Default.preset" -preset "%~dpn0.preset"

::MAP Drives
::@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0MapDrives.ps1"

::RESTART
::@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Win10.ps1" -include "%~dp0Win10.psm1" Restart



::example one function only
:: @powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Win10.ps1" -include "%~dp0Additional.psm1" ShowSecondsInTaskbar

::pause