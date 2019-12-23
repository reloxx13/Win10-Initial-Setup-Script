Write-Host "Map Backup as B: ..."
New-PSDrive -Name "B" -Root "\\192.168.178.101\Backup" -Persist -PSProvider "FileSystem"

Write-Host "Map Media as M: ..."
New-PSDrive -Name "M" -Root "\\192.168.178.101\Media" -Persist -PSProvider "FileSystem"

