<#
.SYNOPSIS
    Removes the Shift application files from all local user profiles.

.DESCRIPTION
    This script stops any running Shift processes and removes the following
    directories from each user profile on the computer:

        AppData\Local\Shift
        AppData\Local\ShiftInstaller

    Designed for use with RMM tools such as N-able where the script may run
    under the SYSTEM account.

.NOTES
    Script Name : Remove-Shift.ps1
    Purpose     : Remove Shift application files from all user profiles
    Requires    : Administrator or SYSTEM privileges
    Author:     : Chatgpt pro
    Co-Author      : Jswenson@getsystems.net Systems Technology Consultants
    Version     : 1.0
    Date        : September 11, 2026

.WARNING
    This script permanently deletes the Shift application directories
    from each local Windows user profile.

    Verify that Shift should be removed before deploying this script.
#>

# Stop Shift for all users
Stop-Process -Name "shift" -Force -ErrorAction SilentlyContinue

# Remove Shift from all local user profiles
Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {

    $ShiftPath = Join-Path $_.FullName "AppData\Local\Shift"
    $InstallerPath = Join-Path $_.FullName "AppData\Local\ShiftInstaller"

    if (Test-Path $ShiftPath) {
        Remove-Item $ShiftPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Output "Removed: $ShiftPath"
    }

    if (Test-Path $InstallerPath) {
        Remove-Item $InstallerPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Output "Removed: $InstallerPath"
    }
}

Write-Output "Shift cleanup complete."
