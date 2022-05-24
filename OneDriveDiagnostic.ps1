#
#	OneDrive and Sharepoint Diagnostics Tool
#
#	TESTED ON:      Windows 10 domain-joined and non-domain-joined devices.
#	LAST UPDATED:   25 MAY 2022
#	AUTHOR:         Michael Russo
#
#	Import this ps1 module, then run the "Start-ODSPDiagnostics" function, which will call all other functions.
#

function Generate-ODSPReport {
# The following code was drawn from:
# https://social.technet.microsoft.com/Forums/windows/en-US/375f3933-fcab-450c-bb9c-da54155549e2/how-do-i-getset-onedrive-quotfiles-on-demandquot-status-from-powershell
$code = @'
using System;

[FlagsAttribute]
public enum FileAttributesEx : uint {
	Readonly = 0x00000001,
	Hidden = 0x00000002,
	System = 0x00000004,
	Directory = 0x00000010,
	Archive = 0x00000020,
	Device = 0x00000040,
	Normal = 0x00000080,
	Temporary = 0x00000100,
	SparseFile = 0x00000200,
	ReparsePoint = 0x00000400,
	Compressed = 0x00000800,
	Offline = 0x00001000,
	NotContentIndexed = 0x00002000,
	Encrypted = 0x00004000,
	IntegrityStream = 0x00008000,
	Virtual = 0x00010000,
	NoScrubData = 0x00020000,
	EA = 0x00040000,
	Pinned = 0x00080000,
	Unpinned = 0x00100000,
	U200000 = 0x00200000,
	RecallOnDataAccess = 0x00400000,
	U800000 = 0x00800000,
	U1000000 = 0x01000000,
	U2000000 = 0x02000000,
	U4000000 = 0x04000000,
	U8000000 = 0x08000000,
	U10000000 = 0x10000000,
	U20000000 = 0x20000000,
	U40000000 = 0x40000000,
	U80000000 = 0x80000000
}
'@
Add-Type $code

#Set Arrays
$OneDriveFoldersConfiguredForSync=@()
$OneDriveRegistry=@()
$OneDriveShortcuts=@()
$LocalSyncedFolders=@()
$Analysis=@()
$Analysis2=@()
$OriginalFiles=@()
$FilesWithPCNameInThem=@()
$DuplicateFiles=@()
$OneDriveOrgFolders=@()

# Check the PowerShell window width.
$width = (Get-Host).UI.RawUI.MaxWindowSize.Width
If ( $width -lt 120 ) {
	Write-Host "For best results, you need to set this Powershell window's width to minimum 120."
	pause
}

#Get the Current (Local) User's personal SID and other environment information.
$CurrentUserSID=((get-localuser -Name $env:username | select SID).SID).Value
$OneDriveUserEmail = (Get-ItemProperty -Path Registry::"HKEY_CURRENT_USER\SOFTWARE\Microsoft\OneDrive\Accounts\Business1" -Name UserEmail).UserEmail
$OneDriveUserID = (Get-ItemProperty -Path Registry::"HKEY_CURRENT_USER\SOFTWARE\Microsoft\OneDrive\Accounts\Business1" -Name cid).cid
$OneDriveConfig = "$env:localappdata\Microsoft\Onedrive\Settings\Business1\$OneDriveUserID.ini"

#Scan the OneDrive registry in HKLM for the SID, and enumerate the folders currently configured to sync.
#This path is HKLM level, and could be useful if Kaseya or a machine management tool was running this application.
#$CurrentUserRegistry=(Get-ChildItem -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager" | where Name -like "*$CurrentUserSID*").Name
$CurrentUserRegistry = (Get-ChildItem -Path Registry::"HKEY_CURRENT_USER\SOFTWARE\SyncEngines\Providers\OneDrive" | Get-ItemProperty | Select MountPoint, LibraryType | Sort-Object "MountPoint")

#Remove some duplicate entries for personal/mysites.
$CurrentUserRegistry = $CurrentUserRegistry | Where LibraryType -ne "Personal"
$CurrentUserRegistry | ForEach-Object {
$OneDriveRegistry += @(
       [pscustomobject]@{"Path_from_OD_Registry"=$_.MountPoint;"Exists?"=$(Test-Path $_.MountPoint)}
)
}

#Get OneDrive Base Folder.  Important to know even if the base folder ends up an equivalent of $env:userprofile, because sometimes the base folder can be moved.
$OneDriveBaseFolder=(Get-ItemProperty Registry::"HKEY_CURRENT_USER\SOFTWARE\Microsoft\OneDrive\Accounts\Business1" | Get-ItemProperty -Name UserFolder).UserFolder
$OneDriveBaseFolder=$OneDriveBaseFolder.Substring(0, $OneDriveBaseFolder.LastIndexOf('\'))

$tenantroots=(Get-ChildItem -Path Registry::"HKEY_CURRENT_USER\SOFTWARE\Microsoft\OneDrive\Accounts\Business1\Tenants").Name.Replace('HKEY_CURRENT_USER\SOFTWARE\Microsoft\OneDrive\Accounts\Business1\Tenants\','')
$tenantroots | ForEach-Object {
$OneDriveOrgFolders += @(
       [pscustomobject]@{"Organization"="$_";"LocalPath"="$OneDriveBaseFolder\$_";"Exists?"=$(Test-Path "$OneDriveBaseFolder\$_")}
)
}

#This result should correspond with the OneDrive App / Settings / Account tab / Locations that are syncing.
$OneDriveFoldersConfigurationREG=(Get-ChildItem -Path Registry::"HKEY_CURRENT_USER\SOFTWARE\Microsoft\OneDrive\Accounts\Business1\Tenants")
$OneDriveFoldersConfigurationREG | ForEach-Object { (Get-Item Registry::$_).Property } | ForEach-Object {
$OneDriveFoldersConfiguredForSync += @(
       [pscustomobject]@{"LocalPath"="$_";"Exists?"=$(Test-Path "$_")}
)
}
	
#Identify OneDrive Shortcut folders from the OneDrive ini configuration file... because it cannot be bloody found anywhere else.
#Note that the FullPath might not be the correct one in all cases!
#TODO: test FullPath in Brian's case where the base OneDrive has been moved to C:\OD.
foreach ($line in Select-String -Path $OneDriveConfig -Encoding unicode -Pattern "^AddedScope") {
    $fields = [regex]::matches($line.line, '(\".*?\"|(\w|[-+=])+)');
    $name = $fields[11].value.Replace('"','').Replace('/','\');
    $url = $fields[5].value.Replace('"','');
	$ODRegID = $fields[3].value
	$OneDriveShortcuts += @(
		[pscustomobject]@{
		"Location" = $name ;
		"URL" = $url ;
		"RelativeODPath" = "$env:OneDrive\$name" ;
		"FullPath" = (Get-ItemProperty -Path Registry::"HKEY_CURRENT_USER\SOFTWARE\SyncEngines\Providers\OneDrive\$ODRegID" -Name MountPoint).MountPoint
		}
		)
}

$LocalSyncedFolders=foreach ( $item in $OneDriveOrgFolders.LocalPath ) {
If ( $item -like "*OneDrive - *" ) {
Get-Item $item | Select FullName, @{n='Synced';e={[fileAttributesex]$_.Attributes.Value__ -match "ReparsePoint"}}
} else{
Get-ChildItem $item | Select FullName, @{n='Synced';e={[fileAttributesex]$_.Attributes.Value__ -match "ReparsePoint"}}
}
}

foreach ($item in $LocalSyncedFolders) {
	$Analysis += @( [pscustomobject]@{"FullPath"=$item.FullName}
	)
}
foreach ($item in $CurrentUserRegistry) {
	$Analysis += @( [pscustomobject]@{"FullPath"=$item.MountPoint}
	)
foreach ($item in $OneDriveShortcuts) {
	$Analysis += @( [pscustomobject]@{
		"FullPath"=$item.FullPath ;
		"IsOneDriveShortcut"=$true
		}
	)
}
}
$Analysis = $Analysis | Select FullPath -Unique

#Perform Analysis, and output to Analysis2 array for final report.
$Analysis | ForEach-Object {
	$Analysis2 += @(
	[pscustomobject]@{
		"Path"=$_.FullPath;"Folder Exists?"=(Test-Path $_.FullPath) ;
		"Is a Local Root Folder?"=($LocalSyncedFolders.FullName -contains $_.FullPath) ;
		"Is It Set to Sync?"=($CurrentUserRegistry.MountPoint -contains $_.FullPath) ;
		"Is a OneDrive Shortcut?"=($OneDriveShortcuts.FullPath -contains $_.FullPath)}
		)
}

#Identify Duplicate Files based on current Computer Name.  You may need to run this on each computer to get a full picture!
$FilesWithPCNameInThem=($OneDriveFoldersConfiguredForSync | ForEach-Object {	Get-ChildItem $_.LocalPath | Where Name -like "*$env:COMPUTERNAME*" | Select FullName} ).FullName
$FilesWithPCNameInThem | ForEach-Object { $OriginalFiles += $_.Replace("-$env:COMPUTERNAME","") }
$FilesWithPCNameInThem | ForEach-Object { $DuplicateFiles += $_ }
$OriginalFiles | ForEach-Object { $DuplicateFiles += $_ }
$DuplicateFileReport= ($DuplicateFiles | Get-Item | Select FullName, LastWriteTime)

clear

$HTMLBody = @"
<p>Dear Bielby Data Services Team,</p>
<p>Please see&nbsp;<strong>OneDrive and SharePoint Diagnostics</strong> result below.</p>
"@
$HTMLBody += "<p><b>Computer Name:</b> $env:COMPUTERNAME<br>"
$HTMLBody += "<b>Local UserName:</b> $env:USERNAME<br>"
$HTMLBody += "<b>OneDrive UserName:</b> $OneDriveUserEmail</p>"
$HTMLBody += "<p></p>"
$HTMLBody += "<p></p><p><strong>These are the top-level Organization folders:</strong></p>"
$HTMLBody += $($OneDriveOrgFolders | ConvertTo-HTML -Fragment).Replace('<table>','<table border="1">').Replace('False','<span style="color: #ff0000;">False</span>')
$HTMLBody += "<p></p><p><strong>Local OneDrive and SharePoint folders:</strong></p>"
$HTMLBody += $($LocalSyncedFolders | ConvertTo-HTML -Fragment).Replace('<table>','<table border="1">').Replace('False','<span style="color: #ff0000;">False</span>')
$HTMLBody += "<p></p><p><strong>Analysis:</strong></p>"
$HTMLBody += $($Analysis2 | ConvertTo-HTML -Fragment).Replace('<table>','<table border="1">').Replace('False','<span style="color: #ff0000;">False</span>')
$HTMLBody += "<p></p><p><strong>Duplicate File Report:</strong></p>"
$HTMLBody += $($DuplicateFileReport | ConvertTo-HTML -Fragment).Replace('<table>','<table border="1">')

$HTMLBody > $global:filenamesaved

If ( $SendToOutlook -like "Y" ) {

	$Outlook = New-Object -ComObject Outlook.Application
	$Mail = $Outlook.CreateItem(0)
	$Mail.To = "support@productiv.com.au"
	$Mail.Subject = "OneDrive/Sharepoint Diagnostics"
	$Mail.HTMLBody = $HTMLBody
	$Mail.Display()
}else{
$HTMLBody += "<p></p><p><strong>You should copy the contents of this report to an email, and send to <a href=""mailto:support@productiv.com.au"">support@productiv.com.au</a></strong></p>"

$HTMLBody > $global:filenamesaved

}
	
}
Function Set-NotificationIcon {
param(
    [Parameter(Mandatory=$true,HelpMessage='The name of the program')][string]$ProgramName,
    [Parameter(Mandatory=$true,HelpMessage='The setting (2 = show icon and notifications 1 = hide icon and notifications, 0 = only show notifications')]
        [ValidateScript({if ($_ -lt 0 -or $_ -gt 2) { throw 'Invalid setting' } return $true})]
        [Int16]$Setting
    )

$encText = New-Object System.Text.UTF8Encoding
[byte[]] $bytRegKey = @()
$strRegKey = ""
$bytRegKey = $(Get-ItemProperty $(Get-Item 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify').PSPath).IconStreams
for($x=0; $x -le $bytRegKey.Count; $x++)
{
    $tempString = [Convert]::ToString($bytRegKey[$x], 16)
    switch($tempString.Length)
    {
        0 {$strRegKey += "00"}
        1 {$strRegKey += "0" + $tempString}
        2 {$strRegKey += $tempString}
    }
}
[byte[]] $bytTempAppPath = @()
$bytTempAppPath = $encText.GetBytes($ProgramName)
[byte[]] $bytAppPath = @()
$strAppPath = ""

Function Rot13($byteToRot)
{
    if($byteToRot -gt 64 -and $byteToRot -lt 91)
    {
        $bytRot = $($($byteToRot - 64 + 13) % 26 + 64)
        return $bytRot
    }
    elseif($byteToRot -gt 96 -and $byteToRot -lt 123)
    {
        $bytRot = $($($byteToRot - 96 + 13) % 26 + 96)
        return $bytRot
    }
    else
    {
        return $byteToRot
    }
}

for($x = 0; $x -lt $bytTempAppPath.Count * 2; $x++)
{
    If($x % 2 -eq 0)
    {
        $curbyte = $bytTempAppPath[$([Int]($x / 2))]
            $bytAppPath += Rot13($curbyte)

    }
    Else
    {
        $bytAppPath += 0
    }
}

for($x=0; $x -lt $bytAppPath.Count; $x++)
{
    $tempString = [Convert]::ToString($bytAppPath[$x], 16)
    switch($tempString.Length)
    {
        0 {$strAppPath += "00"}
        1 {$strAppPath += "0" + $tempString}
        2 {$strAppPath += $tempString}
    }
}
if(-not $strRegKey.Contains($strAppPath))
{
    Write-Host Program not found. Programs are case sensitive.
    break
}

[byte[]] $header = @()
$items = @{}
for($x=0; $x -lt 20; $x++)
{
    $header += $bytRegKey[$x]
}

for($x=0; $x -lt $(($bytRegKey.Count-20)/1640); $x++)
{
    [byte[]] $item=@()
    $startingByte = 20 + ($x*1640)
    $item += $bytRegKey[$($startingByte)..$($startingByte+1639)]
    $items.Add($startingByte.ToString(), $item)
}

foreach($key in $items.Keys)
{
$item = $items[$key]
    $strItem = ""
    $tempString = ""

    for($x=0; $x -le $item.Count; $x++)
    {
        $tempString = [Convert]::ToString($item[$x], 16)
        switch($tempString.Length)
        {
            0 {$strItem += "00"}
            1 {$strItem += "0" + $tempString}
            2 {$strItem += $tempString}
        }
    }
    if($strItem.Contains($strAppPath))
    {
        Write-Host Item Found with $ProgramName in item starting with byte $key
            $bytRegKey[$([Convert]::ToInt32($key)+528)] = $setting
            Set-ItemProperty $($(Get-Item 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify').PSPath) -name IconStreams -value $bytRegKey
    }
}
}
function Start-ODSPDiagnostics {

	$dateformat=Get-Date -Format "yyyyMMdd-hhmm"
	$global:filenamesaved="$env:onedrive\OneDriveSharepointDiagnosticReport_$dateformat.html"

	Write-Host ""
	Write-Host ""
	$Visible=(Read-Host "Set OneDrive agent to always be visible in the Notifications bar? This will restart OneDrive. (Y/N)")
	If ( $Visible -like "y" ) {
		Write-Host "  Setting OneDrive notification icon to ALWAYS VISIBLE..."
		Set-NotificationIcon "OneDrive.exe" 2
		Write-Host "  Restarting OneDrive application..."
		taskkill /im OneDrive.exe /f
		start "C:\Program Files\Microsoft OneDrive\OneDrive.exe"
	}
	If ( (Get-Process | Where { $_.ProcessName -eq "Outlook" -and $_.Company -eq "Microsoft Corporation" }).Count -gt 0 ) {
		Write-Host ""
		Write-Host ""
		$global:SendToOutlook=(Read-Host "Generate an email with this report? (Y/N)")
	}

	
	Write-Host "  Collecting information..."
	Generate-ODSPReport

	Write-Host "  Displaying Results..."
	start "$global:filenamesaved"
}

