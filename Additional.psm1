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


Function SetConsoleColor {
	Write-Host "Running concfg to set console windows to vs-code color scheme..."
	. "$psscriptroot\..\concfg\bin\concfg.ps1" clean -n
	. "$psscriptroot\..\concfg\bin\concfg.ps1" import vs-code-dark-plus "$psscriptroot\consoleSettings.json" -n
}

Function ResetDefaultConsoleColor {
	Write-Host "Running concfg to set console windows to Default color scheme..."
	. "$psscriptroot\..\concfg\bin\concfg.ps1" clean -n
	. "$psscriptroot\..\concfg\bin\concfg.ps1" import defaults -n
}


# Remove right click menu shortcut to open an elevated PS prompt here
Function RemovePowerShellHereShortcut {
	Write-Host "Removing `"Open PowerShell Here`" shell extension..."
	'directory', 'directory\background', 'drive' | ForEach-Object {
		Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\$_\shell\runas" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
	}
}

# Add a right click menu shortcut to open an elevated PS prompt here
Function AddPowerShellHereShortcut {
	$menu = 'Open Admin PowerShell Here'
	$command = "$PSHOME\powershell.exe -NoExit -Command ""Set-Location '%V'"""

	Write-Host "Adding `"Open PowerShell Here`" shell extension..."
	'directory', 'directory\background', 'drive' | ForEach-Object {
		New-Item -Path "Registry::HKEY_CLASSES_ROOT\$_\shell" -Name runas\command -Force |
		Set-ItemProperty -Name '(default)' -Value $command -PassThru |
		Set-ItemProperty -Path {$_.PSParentPath} -Name '(default)' -Value $menu -PassThru |
		Set-ItemProperty -Name HasLUAShield -Value ''
	}
}


#Disable various services
Function DisableServices {
	
	$services = @(
	    "diagnosticshub.standardcollector.service" # Microsoft (R) Diagnostics Hub Standard Collector Service
	    "DiagTrack"                                # Diagnostics Tracking Service
	    #"dmwappushservice"                        # WAP Push Message Routing Service (see known issues)
	    "HomeGroupListener"                        # HomeGroup Listener
	    "HomeGroupProvider"                        # HomeGroup Provider
	    "lfsvc"                                    # Geolocation Service
	    "MapsBroker"                               # Downloaded Maps Manager
	    "NetTcpPortSharing"                        # Net.Tcp Port Sharing Service
	    "RemoteAccess"                             # Routing and Remote Access
	    "RemoteRegistry"                           # Remote Registry
	    "SharedAccess"                             # Internet Connection Sharing (ICS)
	    "TrkWks"                                   # Distributed Link Tracking Client
	    "WbioSrvc"                                 # Windows Biometric Service
	    "WlanSvc"                                  # WLAN AutoConfig
		"WMPNetworkSvc"                            # Windows Media Player Network Sharing Service
		"XboxGipSvc"
		"xbgm"
	    "XblAuthManager"                           # Xbox Live Auth Manager
	    "XblGameSave"                              # Xbox Live Game Save Service
		"XboxNetApiSvc"                            # Xbox Live Networking Service
		"WinHttpAutoProxySvc"					   # Web Proxy Auto Discovery
	)

	foreach ($service in $services) {
	    Write-Output "Trying to disable $service"
	    Get-Service -Name $service | Set-Service -StartupType Disabled
	}
}

#Check if reg value exists
# Source: https://gallery.technet.microsoft.com/scriptcenter/deactivate-Nagle-Algorithm-66ca7608
Function Exists-RegistryValue($pspath, $propertyname) {
    $exists = Get-ItemProperty -Path "$pspath" -Name "$propertyname" -ea SilentlyContinue
    If (($exists -ne $null) -and ($exists.Length -ne 0)) {
        Return $true
    }
    Return $false
}

# Disable Nagle Algorithm
# Modified from: https://gallery.technet.microsoft.com/scriptcenter/deactivate-Nagle-Algorithm-66ca7608
Function DisableNagle{
	$strTargetNICAddress = Test-Connection -ComputerName (hostname) -Count 1  | Select -ExpandProperty IPV4Address 
	$strTargetNICAddress = $strTargetNICAddress.IPAddressToString

	foreach($item in Get-Childitem -LiteralPath HKLM:\system\currentcontrolset\services\tcpip\parameters\interfaces)
	{
	    
	    $key = Get-ItemProperty $item.PSPath
	    
	    if(([string]$key.IPAddress -match $strTargetNICAddress) -OR ([string]$key.DHCPIPAddress -match $strTargetNICAddress))
	    {
	        Write-Host "Interface: " $item.PSPath
	        # only one is supposed to have a value, so both vars printed quick and dirty
	        Write-Host "IP: " $key.IPAddress $key.DHCPIPAddress

			Set-ItemProperty -LiteralPath $item.PSPath -Name TcpAckFrequency -Value 1 -ea "Stop"
			Set-ItemProperty -LiteralPath $item.PSPath -Name TCPNoDelay -Value 1 -ea "Stop"

	        if(-not [Boolean](Exists-RegistryValue $item.PSPath "TcpAckFrequency"))
	        {
	        	Write-Host "Successfully disabled Nagle's algorithm."
	        }
	    }
	}
}

# Nvidia Driver Check, cleans and installs new drivers
# Source: https://github.com/lord-carlos/nvidia-update
Function UpdateNvidiaDrivers{
	# Checking currently installed driver version
	Write-Host "Updating Nvidia drivers..."
	try {  
		$ins_version = (Get-WmiObject Win32_PnPSignedDriver | Where-Object {$_.devicename -like "*nvidia*" -and $_.devicename -notlike "*audio*"}).DriverVersion.SubString(7).Remove(1,1).Insert(3,".")
	} catch {
		Write-Host "Unable to detect a compatible Nvidia device."
		return;
	}
	Write-Host "Installed version: `t$ins_version"

	# Set locations
	$location = "US"
	$extractDir = [Environment]::GetFolderPath("Desktop")

	# Checking if 7zip is installed
	if (Test-Path $env:programfiles\7-zip\7z.exe) {
		$archiverProgram = "$env:programfiles\7-zip\7z.exe"
	} else {
		Write-Host "7zip not installed. Cannot extract driver package. Cancelling."
		return;
	}

	# Checking latest driver version from Nvidia website
	$link = Invoke-WebRequest -Uri 'https://www.nvidia.com/Download/processFind.aspx?psid=101&pfid=816&osid=57&lid=1&whql=1&lang=en-us&ctk=0' -Method GET -UseBasicParsing
	$link -match '<td class="gridItem">([^<]+?)</td>' | Out-Null
	$version = $matches[1]
	Write-Host "Latest version `t`t$version"

	# Comparing installed driver version to latest driver version from Nvidia
	if($version -eq $ins_version) {
		Write-Host "Latest Nvidia Drivers installed."
		return;
	}

	# Confirm install
	Write-Host -nonewline "New Nvidia Driver $version found. Continue with install? (Y/N) "
	$response = read-host
	if ( $response -ne "Y" ) { return; }

	# Checking Windows version
	if ([Environment]::OSVersion.Version -ge (new-object 'Version' 9,1)) {
		$windowsVersion = "win10"
	} else {
		$windowsVersion = "win8-win7"
	}

	# Checking Windows version
	if ((Get-WmiObject win32_operatingsystem | Select-Object osarchitecture).osarchitecture -eq "64-bit")
	{
		$windowsArchitecture = "64bit"
	} else {
		$windowsArchitecture = "32bit"
	}

	# Generating the download link
	$url = "http://$location.download.nvidia.com/Windows/$version/$version-desktop-$windowsVersion-$windowsArchitecture-international-whql.exe"
	Write-Host $url

	# Create a new temp folder NVIDIA
	$nvidiaTempFolder = "$extractDir\nvidia_$version"
	New-Item -Path $nvidiaTempFolder -ItemType Directory 2>&1 | Out-Null

	# Download installer
	$dlFile = "$nvidiaTempFolder\$version.exe"
	Write-Host "Downloading $version to $dlFile"
	Start-BitsTransfer -Source $url -Destination $dlFile

	# Extracting setup files
	$extractFolder = "$nvidiaTempFolder\$version"
	$filesToExtract = "Display.Driver NVI2 EULA.txt ListDevices.txt setup.cfg setup.exe"
	Write-Host "Download finished, extracting files..."
	if ($archiverProgram -eq "$env:programfiles\7-zip\7z.exe") {
		Start-Process -FilePath $archiverProgram -ArgumentList "x $dlFile $filesToExtract -o""$extractFolder""" -wait
	}
	# Remove unneeded dependencies from setup.cfg
	(Get-Content "$extractFolder\setup.cfg") | Where-Object {$_ -notmatch 'name="\${{(EulaHtmlFile|FunctionalConsentFile|PrivacyPolicyFile)}}'} | Set-Content "$extractFolder\setup.cfg" -Encoding UTF8 -Force

	# Installing drivers
	Write-Host "Installing $version..."
	$install_args = "-s -noreboot -noeula -clean"
	Start-Process -FilePath "$extractFolder\setup.exe" -ArgumentList $install_args -wait
}

# Add telemetry ips to firewall
Function DisableTeleIps{
	Write-Output "Adding telemetry ips to firewall"
    $ips = [string[]](Get-Content $psscriptroot\telemetryIPs.txt | Select-Object -Skip 3)
	Remove-NetFirewallRule -DisplayName "Block Telemetry IPs" -ErrorAction SilentlyContinue
	New-NetFirewallRule -DisplayName "Block Telemetry IPs" -Direction Outbound `
	-Action Block -RemoteAddress ($ips)
}

# Change volume control to classic style
Function ChangeVolumeClassic {
	Write-Output "Changing volume control to classic style..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC" -Name "EnableMtcUvc" -Type Dword -Value 0
}

Function DisableTransparency {
    Write-Host "Disabling Transparency"
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Type Dword -Value 0
}


## Set Gaming Performance to high priority
Function GamingRegSet{
	if ((Test-Path ${env:ProgramFiles(x86)}\Steam\)) # Assumption: If steam is not installed then there's no point adjusting PC performance for gaming
	{
		Write-Output "Set gaming performance to high priority..."
		Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Type String -Value "High"
		Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Type String -Value "High"
		Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Background Only" -Type String -Value "False"
		Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Type DWord -Value 6
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 0
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 0xFFFFFFFF
	}
	else {
		Write-Host "Steam is not installed. Assuming gaming performance registry tweaks are not needed."
	}
}

## Disable wpad service
Function Disablewpad{
	Write-Output "Disabling wpad DNS queries..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "UseDomainNameDevolution" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" -Name "Start" -Type DWord -Value 4
}

# Disable wpad DNS queries and appends all entries in hosts.txt that are not in the hosts file
Function AppendHosts{
	Write-Output "Appending to Hosts file..."
    $file = "$psscriptroot\hosts.txt"
    $HostsToWrite = [string[]](Get-Content $file | Select-Object -Skip 0)
    if (!($HostsToWrite.count -eq 0)){
        $hostspath="$($env:windir)\System32\drivers\etc\hosts"
        If ((Test-Path $hostspath) -eq "True") {
            $InHosts = @()
            $hostsFile = Get-Content $hostspath
            foreach ($line in $hostsFile) {
                $ln = [regex]::Split($line, "^127.0.0.1 +")
                if ($ln.count -eq 2) {
                    $InHosts += $ln[1]
                }
            }
        }
        $notInstalled = $HostsToWrite | Where {$InHosts -NotContains $_}
        if (!($notInstalled.count -eq 0)){
            foreach ($domain in $notInstalled){
                "`n127.0.0.1 " + $domain | Out-File -encoding ASCII -append $hostspath
                Write-Host "Adding host $domain"
            }
        }
        Write-Host "All hosts in $file set in $hostspath"
    }else {
        Write-Output "$file empty"
    }
}

Function NetworkTweaks {
	Write-Output "Setting network settings..."
	netsh interface teredo set state disabled
	netsh interface 6to4 set state disabled
	netsh winsock reset
	netsh interface isatap set state disable
	netsh int tcp set global timestamps=disabled
	netsh int tcp set heuristics disabled
	netsh int tcp set global autotuninglevel=disable
	netsh int tcp set global congestionprovider=ctcp
	netsh int tcp set supplemental Internet congestionprovider=CTCP
	netsh int tcp set global chimney=disabled
	netsh int tcp set global ecncapability=disabled
	netsh int tcp set global rss=enabled
	netsh int tcp set global rsc=disabled
	netsh int tcp set global dca=enabled
	netsh int tcp set global netdma=enabled
	Disable-NetAdapterChecksumOffload -Name "*"
	Disable-NetAdapterLso -Name "*"
	Disable-NetAdapterRsc -Name "*"
	Disable-NetAdapterIPsecOffload -Name "*"
	Disable-NetAdapterPowerManagement -Name "*"
	Disable-NetAdapterQos -Name "*"
	
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\TCPIP6\Parameters" -Name "EnableICSIPv6" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\TCPIP6\Parameters" -Name "DisabledComponents" -Type DWord -Value 255
}

Function SetDefaultViewDetailed{
	Write-Output "Setting Explorer default view to Detailed"
	Remove-Item -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagsMRU" -Recurse -ErrorAction SilentlyContinue
	If (!(Test-Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell")) {
		New-Item -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" -Force | Out-Null
		Set-ItemProperty -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" -Name "FolderType" -Type String -Value "NotSpecified"
	}

	If (!(Test-Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell\{7fde1a1e-8b31-49a5-93b8-6be14cfa4943}")) {
		New-Item -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell\{7fde1a1e-8b31-49a5-93b8-6be14cfa4943}" -Force | Out-Null
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell\{7fde1a1e-8b31-49a5-93b8-6be14cfa4943}" -Name "LogicalViewMode" -Type DWord -Value 1
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell\{7fde1a1e-8b31-49a5-93b8-6be14cfa4943}" -Name "Mode" -Type DWord -Value 4
	}
}





# Export functions
Export-ModuleMember -Function *