##########
#region UI Tweaks
##########


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