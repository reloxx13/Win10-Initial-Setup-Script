##########
#region UI Tweaks
##########


# Wait 5 seconds
Function WaitASec {
    Write-Output "Waiting 5 seconds..."
	Start-Sleep 5
}

# Show seconds in taskbar
Function ShowSecondsInTaskbar {
	Write-Output "Showing seconds in taskbar..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSecondsInSystemClock" -Type DWord -Value 1
}

# Hide seconds in taskbar
Function HideSecondsInTaskbar {
	Write-Output "Hiding seconds in taskbar..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSecondsInSystemClock" -ErrorAction SilentlyContinue
}

# Show Windows build number and Windows edition (Home/Pro/Enterprise) from bottom right of desktop
Function ShowBuildNumberOnDesktop {
	Write-Output "Showing build number on desktop..."
	If (!(Test-Path "HKCU:\Control Panel\Desktop")) {
		New-Item -Path "HKCU:\Control Panel\Desktop" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "PaintDesktopVersion" -Type DWord -Value 1
}

# Hide Windows build number and Windows edition (Home/Pro/Enterprise) from bottom right of desktop
Function HideBuildNumberOnDesktop {
	Write-Output "Hiding build number on desktop..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "PaintDesktopVersion" -Type DWord -Value 0
}


##########
#App Tweaks
##########

# Download Firefox
Function DownloadFirefox {
	Write-Output "Download firefox..."
	$firefoxUrl = "https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=de"
	$firefoxOutput = "$PSScriptRoot\firefox_latest_ssl_win64_de.exe"

	Invoke-WebRequest -Uri $firefoxUrl -OutFile $firefoxOutput
}

# Install Firefox
Function InstallFirefox {
    Write-Output "Installing previously downloaded Firefox..."
	$firefoxOutput = "$PSScriptRoot\firefox_latest_ssl_win64_de.exe"
	
	& $firefoxOutput /DesktopShortcut=false /MaintenanceService=false; Wait-Process firefox_latest_ssl_win64_de
}

# Download CCleaner
Function DownloadCCleaner {
    Write-Output "Downloading CCleaner Portable..."
	$ccleanerUrl = "https://download.ccleaner.com/portable/ccsetup558.zip" # https://www.ccleaner.com/de-de/ccleaner/builds
	$ccleanerOutput = "$PSScriptRoot\ccsetup.zip"

	Invoke-WebRequest -Uri $ccleanerUrl -OutFile $ccleanerOutput
}

# Install CCleaner
Function InstallCCleaner {
    Write-Output "Installing previously downloaded CCleaner..."
	$ccleanerOutput = "$PSScriptRoot\ccsetup.zip"
	
	Add-Type -AssemblyName System.IO.Compression.FileSystem
	[System.IO.Compression.ZipFile]::ExtractToDirectory($ccleanerOutput, "$HOME\Documents\CCleaner")
}

# Export functions
Export-ModuleMember -Function *