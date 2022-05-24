# PS_OneDriveDiagnostics
PowerShell-based OneDrive and SharePoint Diagnostics

Import this PS1 file using:
"Import-Module OneDriveDiagnostic.ps1"

Then run the following command: "Start-ODSPDiagnostics"

This tool is designed to query parts of the Windows 10/11 Registry, OneDrive local app data configuration, and traditional file/folder structures to cross-reference OneDrive's configuration with the local user's data.

The tool can be used to identify whether:
1. A user has folders that are no longer sync'ing (e.g. Folder exists on C drive, but no longer connected).
2. A user has folders corresponding to multiple organizations, and their respective locations.
3. A user has folders that should be sync'ing but don't exist (e.g. OneDrive THINKS there should be a folder, but either isn't, or is somewhere else).
4. A user has OneDrive Shortcuts... which are the author's bane of existence-- I mean, which create further complications in tracking down folder locations and sync behaviour conflicts.
