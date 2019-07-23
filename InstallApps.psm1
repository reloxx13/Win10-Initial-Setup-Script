

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