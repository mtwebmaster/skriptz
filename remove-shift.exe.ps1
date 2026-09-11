<#
.SYNOPSIS
    Removes Shift application files and scheduled tasks from all local user profiles.

.DESCRIPTION
    This script performs the following actions:

        - Creates a timestamped log file in C:\Temp.
        - Stops any running Shift processes.
        - Searches Windows Task Scheduler for Shift-related tasks.
        - Removes Shift-related scheduled tasks.
        - Removes Shift and ShiftInstaller directories from all user profiles.
        - Performs final verification.
        - Produces a remediation summary showing exactly what was found and removed.

    Designed for use with RMM tools such as N-able where the script may run
    under the SYSTEM account.

.NOTES
    Script Name : Remove-Shift.ps1
    Purpose     : Remove Shift application files and scheduled tasks
    Requires    : Administrator or SYSTEM privileges
    Author      : ChatGPT Pro
    Co-Author   : Jswenson@getsystems.net - Systems Technology Consultants
    Version     : 1.3
    Date        : September 11, 2026

    Log Location:
        C:\Temp\Remove-Shift-YYYYMMDD-HHMMSS.log

.WARNING
    This script permanently deletes Shift application directories and
    scheduled tasks associated with Shift.

    Verify that Shift should be removed before deploying this script.
#>


# ============================================================
# Logging Configuration
# ============================================================

$LogFolder = "C:\Temp"
$TimeStamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogFile   = Join-Path $LogFolder "Remove-Shift-$TimeStamp.log"

if (-not (Test-Path $LogFolder)) {
    New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
}

Start-Transcript -Path $LogFile -Force


# ============================================================
# Remediation Counters
# ============================================================

$ProcessesStopped         = 0
$ScheduledTasksFound      = 0
$ScheduledTasksRemoved    = 0
$ShiftFoldersFound        = 0
$ShiftFoldersRemoved      = 0
$InstallerFoldersFound    = 0
$InstallerFoldersRemoved  = 0


try {

    Write-Output ""
    Write-Output "========================================"
    Write-Output " Shift Cleanup Script"
    Write-Output "========================================"
    Write-Output ""
    Write-Output "Computer Name : $env:COMPUTERNAME"
    Write-Output "Running As    : $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    Write-Output "Date/Time     : $(Get-Date)"
    Write-Output "Log File      : $LogFile"


    # ============================================================
    # Step 1 - Stop Shift Processes
    # ============================================================

    Write-Output ""
    Write-Output "----------------------------------------"
    Write-Output "[1] Checking for running Shift processes"
    Write-Output "----------------------------------------"

    $ShiftProcesses = Get-Process -Name "shift" -ErrorAction SilentlyContinue

    if ($ShiftProcesses) {

        foreach ($Process in $ShiftProcesses) {

            Write-Output "FOUND process:"
            Write-Output "  PID  : $($Process.Id)"
            Write-Output "  Name : $($Process.ProcessName)"

            try {

                Stop-Process -Id $Process.Id -Force -ErrorAction Stop

                $ProcessesStopped++

                Write-Output "REMOVED/STOPPED process:"
                Write-Output "  PID  : $($Process.Id)"

            }
            catch {

                Write-Warning "FAILED to stop process PID $($Process.Id)"
                Write-Warning $_.Exception.Message

            }

        }

    }
    else {

        Write-Output "No running Shift processes found."

    }


    # ============================================================
    # Step 2 - Search Task Scheduler
    # ============================================================

    Write-Output ""
    Write-Output "----------------------------------------"
    Write-Output "[2] Checking Task Scheduler for Shift"
    Write-Output "----------------------------------------"

    $ShiftTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {

        $Task = $_

        $NameMatch = $Task.TaskName -match "(?i)shift"
        $PathMatch = $Task.TaskPath -match "(?i)shift"

        $ActionMatch = $false

        foreach ($Action in $Task.Actions) {

            if (
                $Action.Execute   -match "(?i)shift" -or
                $Action.Arguments -match "(?i)shift"
            ) {

                $ActionMatch = $true

            }

        }

        $NameMatch -or $PathMatch -or $ActionMatch

    }


    if ($ShiftTasks) {

        foreach ($Task in $ShiftTasks) {

            $ScheduledTasksFound++

            Write-Output ""
            Write-Output "FOUND Shift-related scheduled task:"
            Write-Output "  Task Name : $($Task.TaskName)"
            Write-Output "  Task Path : $($Task.TaskPath)"
            Write-Output "  State     : $($Task.State)"

            foreach ($Action in $Task.Actions) {

                Write-Output "  Execute   : $($Action.Execute)"
                Write-Output "  Arguments : $($Action.Arguments)"

            }

            try {

                Unregister-ScheduledTask `
                    -TaskName $Task.TaskName `
                    -TaskPath $Task.TaskPath `
                    -Confirm:$false `
                    -ErrorAction Stop

                $ScheduledTasksRemoved++

                Write-Output "REMOVED scheduled task:"
                Write-Output "  $($Task.TaskPath)$($Task.TaskName)"

            }
            catch {

                Write-Warning "FAILED to remove scheduled task:"
                Write-Warning "  $($Task.TaskPath)$($Task.TaskName)"
                Write-Warning $_.Exception.Message

            }

        }

    }
    else {

        Write-Output "No Shift-related scheduled tasks found."

    }


    # ============================================================
    # Step 3 - Remove Shift From User Profiles
    # ============================================================

    Write-Output ""
    Write-Output "----------------------------------------"
    Write-Output "[3] Checking local user profiles"
    Write-Output "----------------------------------------"

    $UserProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue

    foreach ($Profile in $UserProfiles) {

        $UserProfile   = $Profile.FullName
        $ShiftPath     = Join-Path $UserProfile "AppData\Local\Shift"
        $InstallerPath = Join-Path $UserProfile "AppData\Local\ShiftInstaller"

        Write-Output ""
        Write-Output "Checking profile: $UserProfile"


        # --------------------------------------------------------
        # Remove Shift folder
        # --------------------------------------------------------

        if (Test-Path $ShiftPath) {

            $ShiftFoldersFound++

            Write-Output "FOUND Shift directory:"
            Write-Output "  $ShiftPath"

            try {

                Remove-Item `
                    -Path $ShiftPath `
                    -Recurse `
                    -Force `
                    -ErrorAction Stop

                $ShiftFoldersRemoved++

                Write-Output "REMOVED Shift directory:"
                Write-Output "  $ShiftPath"

            }
            catch {

                Write-Warning "FAILED to remove:"
                Write-Warning "  $ShiftPath"
                Write-Warning $_.Exception.Message

            }

        }
        else {

            Write-Output "Not found: $ShiftPath"

        }


        # --------------------------------------------------------
        # Remove ShiftInstaller folder
        # --------------------------------------------------------

        if (Test-Path $InstallerPath) {

            $InstallerFoldersFound++

            Write-Output "FOUND ShiftInstaller directory:"
            Write-Output "  $InstallerPath"

            try {

                Remove-Item `
                    -Path $InstallerPath `
                    -Recurse `
                    -Force `
                    -ErrorAction Stop

                $InstallerFoldersRemoved++

                Write-Output "REMOVED ShiftInstaller directory:"
                Write-Output "  $InstallerPath"

            }
            catch {

                Write-Warning "FAILED to remove:"
                Write-Warning "  $InstallerPath"
                Write-Warning $_.Exception.Message

            }

        }
        else {

            Write-Output "Not found: $InstallerPath"

        }

    }


    # ============================================================
    # Step 4 - Final Verification
    # ============================================================

    Write-Output ""
    Write-Output "----------------------------------------"
    Write-Output "[4] Final verification"
    Write-Output "----------------------------------------"


    # Verify Processes

    $RemainingProcesses = Get-Process -Name "shift" -ErrorAction SilentlyContinue

    if ($RemainingProcesses) {

        Write-Warning "FAIL: Shift process is still running."

    }
    else {

        Write-Output "PASS: No Shift processes are running."

    }


    # Verify Scheduled Tasks

    $RemainingTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {

        $Task = $_

        $NameMatch = $Task.TaskName -match "(?i)shift"
        $PathMatch = $Task.TaskPath -match "(?i)shift"

        $ActionMatch = $false

        foreach ($Action in $Task.Actions) {

            if (
                $Action.Execute   -match "(?i)shift" -or
                $Action.Arguments -match "(?i)shift"
            ) {

                $ActionMatch = $true

            }

        }

        $NameMatch -or $PathMatch -or $ActionMatch

    }

    if ($RemainingTasks) {

        Write-Warning "FAIL: Shift-related scheduled tasks still exist."

        foreach ($Task in $RemainingTasks) {

            Write-Warning "$($Task.TaskPath)$($Task.TaskName)"

        }

    }
    else {

        Write-Output "PASS: No Shift-related scheduled tasks detected."

    }


    # Verify Folders

    $RemainingPaths = @()

    foreach ($Profile in $UserProfiles) {

        $ShiftPath     = Join-Path $Profile.FullName "AppData\Local\Shift"
        $InstallerPath = Join-Path $Profile.FullName "AppData\Local\ShiftInstaller"

        if (Test-Path $ShiftPath) {
            $RemainingPaths += $ShiftPath
        }

        if (Test-Path $InstallerPath) {
            $RemainingPaths += $InstallerPath
        }

    }

    if ($RemainingPaths.Count -gt 0) {

        Write-Warning "FAIL: Shift application directories still exist."

        foreach ($Path in $RemainingPaths) {
            Write-Warning $Path
        }

    }
    else {

        Write-Output "PASS: No Shift application directories detected."

    }


    # ============================================================
    # Remediation Summary
    # ============================================================

    Write-Output ""
    Write-Output "========================================"
    Write-Output " Shift Cleanup Summary"
    Write-Output "========================================"
    Write-Output ""
    Write-Output "Processes stopped         : $ProcessesStopped"
    Write-Output "Scheduled tasks found     : $ScheduledTasksFound"
    Write-Output "Scheduled tasks removed   : $ScheduledTasksRemoved"
    Write-Output "Shift folders found       : $ShiftFoldersFound"
    Write-Output "Shift folders removed     : $ShiftFoldersRemoved"
    Write-Output "Installer folders found   : $InstallerFoldersFound"
    Write-Output "Installer folders removed : $InstallerFoldersRemoved"
    Write-Output ""


    # ============================================================
    # Determine Overall Result
    # ============================================================

    $TotalFound = `
        $ScheduledTasksFound +
        $ShiftFoldersFound +
        $InstallerFoldersFound +
        $ProcessesStopped

    $TotalRemoved = `
        $ScheduledTasksRemoved +
        $ShiftFoldersRemoved +
        $InstallerFoldersRemoved +
        $ProcessesStopped


    if ($RemainingProcesses -or $RemainingTasks -or $RemainingPaths.Count -gt 0) {

        Write-Output "RESULT: REMEDIATION INCOMPLETE"

    }
    elseif ($TotalFound -gt 0) {

        Write-Output "RESULT: REMEDIATION PERFORMED SUCCESSFULLY"
        Write-Output "Items found   : $TotalFound"
        Write-Output "Items removed : $TotalRemoved"

    }
    else {

        Write-Output "RESULT: NO SHIFT ITEMS FOUND - SYSTEM ALREADY CLEAN"

    }


    Write-Output ""
    Write-Output "Completed : $(Get-Date)"
    Write-Output "Log File  : $LogFile"
    Write-Output ""
    Write-Output "========================================"

}
catch {

    Write-Error "An unexpected error occurred during Shift cleanup."
    Write-Error $_.Exception.Message

}
finally {

    Stop-Transcript -ErrorAction SilentlyContinue

}
