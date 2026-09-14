<#
.SYNOPSIS
    Detects and silently uninstalls legacy Microsoft Visual C++ Redistributables.

.DESCRIPTION
    Searches both 64-bit and 32-bit uninstall registry locations for:

        - Microsoft Visual C++ 2005
        - Microsoft Visual C++ 2008
        - Microsoft Visual C++ 2010
        - Microsoft Visual C++ 2012
        - Microsoft Visual C++ 2013

    MSI installations are uninstalled using msiexec.exe.

    EXE/bootstrapper installations are launched using their
    native uninstall command with silent parameters.

    Detailed logs are written to:

        C:\Temp\VCppCleanup\

    Exit code 0    = Successful uninstall
    Exit code 3010 = Successful uninstall, reboot required
    Exit code 1605 = Product already removed / not installed

.NOTES
    Compatible with Windows PowerShell 5.1.
    Requires Administrator privileges.
#>

# ============================================================
# CONFIGURATION
# ============================================================

$LogDirectory = "C:\Temp\VCppCleanup"

$TargetVersions = @(
    "2005",
    "2008",
    "2010",
    "2012",
    "2013"
)

$RegPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

# ============================================================
# CREATE LOG DIRECTORY
# ============================================================

if (-not (Test-Path -Path $LogDirectory)) {

    New-Item `
        -Path $LogDirectory `
        -ItemType Directory `
        -Force `
        | Out-Null
}

$TimeStamp = Get-Date -Format "yyyyMMdd-HHmmss"

$LogFile = Join-Path `
    $LogDirectory `
    "VCppCleanup-$TimeStamp.log"

# ============================================================
# START TRANSCRIPT
# ============================================================

Start-Transcript `
    -Path $LogFile `
    -Force `
    | Out-Null

# ============================================================
# RESULT TRACKING
# ============================================================

$SuccessfulUninstalls = @()
$SkippedUninstalls    = @()
$FailedUninstalls     = @()

$RebootRequired = $false

# ============================================================
# LOGGING FUNCTION
# ============================================================

function Write-Log {

    param (
        [string]$Message,

        [ValidateSet(
            "INFO",
            "DEBUG",
            "SUCCESS",
            "WARNING",
            "ERROR"
        )]
        [string]$Level = "INFO"
    )

    $Time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    switch ($Level) {

        "INFO" {
            $Color = "White"
        }

        "DEBUG" {
            $Color = "Gray"
        }

        "SUCCESS" {
            $Color = "Green"
        }

        "WARNING" {
            $Color = "Yellow"
        }

        "ERROR" {
            $Color = "Red"
        }
    }

    Write-Host `
        "[$Time] [$Level] $Message" `
        -ForegroundColor $Color
}

# ============================================================
# HEADER
# ============================================================

Write-Host ""
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "           MICROSOFT VISUAL C++ LEGACY RUNTIME CLEANUP" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan

Write-Log "Cleanup session started." "INFO"
Write-Log "Computer : $env:COMPUTERNAME" "DEBUG"
Write-Log "User     : $env:USERNAME" "DEBUG"
Write-Log "PowerShell: $($PSVersionTable.PSVersion)" "DEBUG"
Write-Log "Log file : $LogFile" "INFO"

# ============================================================
# ADMINISTRATOR PRIVILEGE CHECK
# ============================================================

Write-Host ""
Write-Host "--- Administrator Privilege Check ---" -ForegroundColor Cyan

$CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()

$CurrentPrincipal = New-Object `
    Security.Principal.WindowsPrincipal($CurrentIdentity)

$IsAdmin = $CurrentPrincipal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $IsAdmin) {

    Write-Log `
        "Critical: This script must be executed with Administrator privileges." `
        "ERROR"

    Stop-Transcript | Out-Null

    Exit 1
}

Write-Log `
    "Administrator privileges confirmed." `
    "SUCCESS"

# ============================================================
# CLEANUP CONFIGURATION
# ============================================================

Write-Host ""
Write-Host "--- Cleanup Configuration ---" -ForegroundColor Cyan

Write-Log `
    "Target versions: $($TargetVersions -join ', ')" `
    "INFO"

foreach ($Path in $RegPaths) {

    Write-Log `
        "Registry path: $Path" `
        "DEBUG"
}

# ============================================================
# REGISTRY SCAN
# ============================================================

Write-Host ""
Write-Host "--- Registry Scan ---" -ForegroundColor Cyan

Write-Log `
    "Scanning installed applications..." `
    "INFO"

$InstalledApps = @()

foreach ($Path in $RegPaths) {

    Write-Log `
        "Scanning: $Path" `
        "DEBUG"

    try {

        $Apps = Get-ItemProperty `
            -Path $Path `
            -ErrorAction SilentlyContinue

        if ($null -ne $Apps) {

            $InstalledApps += $Apps
        }
    }
    catch {

        Write-Log `
            "Unable to scan registry path: $Path" `
            "WARNING"
    }
}

Write-Log `
    "Registry scan complete." `
    "SUCCESS"

# ============================================================
# DETECT LEGACY VISUAL C++ INSTALLATIONS
# ============================================================

Write-Host ""
Write-Host "--- Legacy Visual C++ Detection ---" -ForegroundColor Cyan

$TargetApps = @(
    $InstalledApps | Where-Object {

        $DisplayName = $_.DisplayName

        if ([string]::IsNullOrWhiteSpace($DisplayName)) {
            return $false
        }

        if ([string]::IsNullOrWhiteSpace($_.UninstallString)) {
            return $false
        }

        # Must be Microsoft Visual C++
        if ($DisplayName -notlike "Microsoft Visual C++*") {
            return $false
        }

        # Match target year
        foreach ($Version in $TargetVersions) {

            if ($DisplayName -match "Visual C\+\+ $Version") {
                return $true
            }
        }

        return $false
    }
)

# ============================================================
# NOTHING FOUND
# ============================================================

if ($TargetApps.Count -eq 0) {

    Write-Log `
        "No targeted legacy Visual C++ installations were found." `
        "SUCCESS"

    Write-Host ""
    Write-Host "=============================================================================="
    Write-Host "                         NOTHING TO REMOVE"
    Write-Host "=============================================================================="

    Write-Host ""
    Write-Host "No Visual C++ 2005/2008/2010/2012/2013 installations were detected." `
        -ForegroundColor Green

    Write-Host ""
    Write-Host "Log File: $LogFile" `
        -ForegroundColor Gray

    Stop-Transcript | Out-Null

    Exit 0
}

# ============================================================
# DETECTION SUMMARY
# ============================================================

Write-Log `
    "Found $($TargetApps.Count) targeted installation(s)." `
    "WARNING"

Write-Host ""
Write-Host "--- Detected Legacy Installations ---" -ForegroundColor Cyan

foreach ($App in $TargetApps) {

    Write-Log `
        "Detected: $($App.DisplayName)" `
        "INFO"
}

# ============================================================
# START UNINSTALL OPERATIONS
# ============================================================

Write-Host ""
Write-Log `
    "Starting silent uninstall operations." `
    "WARNING"

foreach ($App in $TargetApps) {

    Write-Host ""
    Write-Host "------------------------------------------------------------------------------" `
        -ForegroundColor DarkGray

    Write-Log `
        "Processing: $($App.DisplayName)" `
        "INFO"

    $UnString = $App.UninstallString

    Write-Log `
        "Uninstall string: $UnString" `
        "DEBUG"

    # ========================================================
    # MSI INSTALLATION
    # ========================================================

    if ($UnString -match "(?i)msiexec") {

        Write-Log `
            "Installer type: MSI" `
            "DEBUG"

        # ----------------------------------------------------
        # Extract MSI GUID
        # ----------------------------------------------------

        if ($UnString -match "\{[A-Fa-f0-9-]{36}\}") {

            $Guid = $Matches[0]

            Write-Log `
                "MSI Product Code: $Guid" `
                "DEBUG"

            Write-Log `
                "Launching silent MSI uninstall..." `
                "INFO"

            try {

                $Proc = Start-Process `
                    -FilePath "msiexec.exe" `
                    -ArgumentList "/X $Guid /qn /norestart" `
                    -Wait `
                    -PassThru `
                    -ErrorAction Stop

                $ExitCode = $Proc.ExitCode

                Write-Log `
                    "MSI exit code: $ExitCode" `
                    "DEBUG"

                # ------------------------------------------------
                # SUCCESS
                # ------------------------------------------------

                if ($ExitCode -eq 0) {

                    $SuccessfulUninstalls += $App.DisplayName

                    Write-Log `
                        "SUCCESS: $($App.DisplayName)" `
                        "SUCCESS"
                }

                # ------------------------------------------------
                # SUCCESS + REBOOT
                # ------------------------------------------------

                elseif ($ExitCode -eq 3010) {

                    $SuccessfulUninstalls += $App.DisplayName

                    $RebootRequired = $true

                    Write-Log `
                        "SUCCESS - REBOOT REQUIRED: $($App.DisplayName)" `
                        "SUCCESS"
                }

                # ------------------------------------------------
                # ALREADY REMOVED
                # ------------------------------------------------

                elseif ($ExitCode -eq 1605) {

                    $SkippedUninstalls += $App.DisplayName

                    Write-Log `
                        "SKIPPED - Product is not currently installed: $($App.DisplayName)" `
                        "WARNING"
                }

                # ------------------------------------------------
                # FAILURE
                # ------------------------------------------------

                else {

                    $FailedUninstalls += `
                        "$($App.DisplayName) [Exit Code: $ExitCode]"

                    Write-Log `
                        "FAILED: $($App.DisplayName) - Exit Code: $ExitCode" `
                        "ERROR"
                }
            }
            catch {

                $FailedUninstalls += `
                    "$($App.DisplayName) [Exception]"

                Write-Log `
                    "FAILED to launch MSI uninstall: $($_.Exception.Message)" `
                    "ERROR"
            }
        }
        else {

            $FailedUninstalls += `
                "$($App.DisplayName) [No MSI GUID]"

            Write-Log `
                "Could not extract MSI Product Code from uninstall string." `
                "ERROR"
        }
    }

    # ========================================================
    # EXE / BOOTSTRAPPER INSTALLATION
    # ========================================================

    else {

        Write-Log `
            "Installer type: Executable / Bootstrapper" `
            "DEBUG"

        try {

            $Executable = $null
            $ExistingArguments = $null

            # ------------------------------------------------
            # Parse quoted executable
            # ------------------------------------------------

            if ($UnString -match '^\s*"([^"]+)"\s*(.*)$') {

                $Executable = $Matches[1]
                $ExistingArguments = $Matches[2]
            }

            # ------------------------------------------------
            # Parse unquoted executable
            # ------------------------------------------------

            elseif ($UnString -match '^\s*(\S+)\s*(.*)$') {

                $Executable = $Matches[1]
                $ExistingArguments = $Matches[2]
            }

            if ([string]::IsNullOrWhiteSpace($Executable)) {

                $FailedUninstalls += `
                    "$($App.DisplayName) [Unable to parse executable]"

                Write-Log `
                    "Could not determine executable from uninstall string." `
                    "ERROR"

                continue
            }

            Write-Log `
                "Executable: $Executable" `
                "DEBUG"

            # ------------------------------------------------
            # Build argument list
            # ------------------------------------------------

            $ArgumentList = @()

            if (-not [string]::IsNullOrWhiteSpace($ExistingArguments)) {

                $ArgumentList += $ExistingArguments
            }

            # Add /quiet only when necessary
            if ($ExistingArguments -notmatch "(?i)(/quiet|/silent)") {

                $ArgumentList += "/quiet"
            }

            # Add /norestart only when necessary
            if ($ExistingArguments -notmatch "(?i)(/norestart|/forcerestart|/promptrestart)") {

                $ArgumentList += "/norestart"
            }

            $FinalArguments = $ArgumentList -join " "

            Write-Log `
                "Arguments: $FinalArguments" `
                "DEBUG"

            Write-Log `
                "Launching native uninstaller..." `
                "INFO"

            # ------------------------------------------------
            # Verify executable exists
            # ------------------------------------------------

            if (-not (Test-Path -LiteralPath $Executable)) {

                $FailedUninstalls += `
                    "$($App.DisplayName) [Executable not found]"

                Write-Log `
                    "Executable not found: $Executable" `
                    "ERROR"

                continue
            }

            # ------------------------------------------------
            # Launch native uninstaller
            # ------------------------------------------------

            $Proc = Start-Process `
                -FilePath $Executable `
                -ArgumentList $FinalArguments `
                -Wait `
                -PassThru `
                -ErrorAction Stop

            $ExitCode = $Proc.ExitCode

            Write-Log `
                "Bootstrapper exit code: $ExitCode" `
                "DEBUG"

            # ------------------------------------------------
            # SUCCESS
            # ------------------------------------------------

            if ($ExitCode -eq 0) {

                $SuccessfulUninstalls += $App.DisplayName

                Write-Log `
                    "SUCCESS: $($App.DisplayName)" `
                    "SUCCESS"
            }

            # ------------------------------------------------
            # SUCCESS + REBOOT
            # ------------------------------------------------

            elseif ($ExitCode -eq 3010) {

                $SuccessfulUninstalls += $App.DisplayName

                $RebootRequired = $true

                Write-Log `
                    "SUCCESS - REBOOT REQUIRED: $($App.DisplayName)" `
                    "SUCCESS"
            }

            # ------------------------------------------------
            # ALREADY REMOVED
            # ------------------------------------------------

            elseif ($ExitCode -eq 1605) {

                $SkippedUninstalls += $App.DisplayName

                Write-Log `
                    "SKIPPED - Product is not currently installed: $($App.DisplayName)" `
                    "WARNING"
            }

            # ------------------------------------------------
            # FAILURE
            # ------------------------------------------------

            else {

                $FailedUninstalls += `
                    "$($App.DisplayName) [Exit Code: $ExitCode]"

                Write-Log `
                    "FAILED: $($App.DisplayName) - Exit Code: $ExitCode" `
                    "ERROR"
            }
        }
        catch {

            $FailedUninstalls += `
                "$($App.DisplayName) [Exception]"

            Write-Log `
                "FAILED to launch native uninstaller: $($_.Exception.Message)" `
                "ERROR"
        }
    }
}

# ============================================================
# FINAL COUNTS
# ============================================================

$DetectedCount = $TargetApps.Count

$SuccessCount = $SuccessfulUninstalls.Count

$SkippedCount = $SkippedUninstalls.Count

$FailedCount = $FailedUninstalls.Count

# ============================================================
# FINAL CLEANUP SUMMARY
# ============================================================

Write-Host ""
Write-Host ""
Write-Host "=============================================================================="
Write-Host "                         CLEANUP SUMMARY"
Write-Host "=============================================================================="

Write-Host ""

Write-Host `
    ("Detected             : {0}" -f $DetectedCount)

Write-Host `
    ("Successfully removed : {0}" -f $SuccessCount) `
    -ForegroundColor Green

if ($FailedCount -gt 0) {

    Write-Host `
        ("Failed               : {0}" -f $FailedCount) `
        -ForegroundColor Red
}
else {

    Write-Host `
        ("Failed               : {0}" -f $FailedCount) `
        -ForegroundColor Green
}

if ($SkippedCount -gt 0) {

    Write-Host `
        ("Skipped              : {0}" -f $SkippedCount) `
        -ForegroundColor Yellow
}
else {

    Write-Host `
        ("Skipped              : {0}" -f $SkippedCount) `
        -ForegroundColor Green
}

if ($RebootRequired) {

    Write-Host `
        "Reboot required      : YES" `
        -ForegroundColor Yellow
}
else {

    Write-Host `
        "Reboot required      : NO" `
        -ForegroundColor Green
}

# ============================================================
# SUCCESSFULLY REMOVED
# ============================================================

Write-Host ""
Write-Host "------------------------------------------------------------------------------" `
    -ForegroundColor Green

Write-Host "                         WE REMOVED SUCCESSFULLY" `
    -ForegroundColor Green

Write-Host "------------------------------------------------------------------------------" `
    -ForegroundColor Green

if ($SuccessfulUninstalls.Count -gt 0) {

    foreach ($Product in $SuccessfulUninstalls) {

        Write-Host ""

        Write-Host "  [REMOVED SUCCESSFULLY]" `
            -ForegroundColor Green

        Write-Host "  $Product" `
            -ForegroundColor White
    }
}
else {

    Write-Host ""
    Write-Host "  None" `
        -ForegroundColor Yellow
}

# ============================================================
# SKIPPED
# ============================================================

if ($SkippedUninstalls.Count -gt 0) {

    Write-Host ""
    Write-Host "------------------------------------------------------------------------------" `
        -ForegroundColor Yellow

    Write-Host "                         SKIPPED / ALREADY REMOVED" `
        -ForegroundColor Yellow

    Write-Host "------------------------------------------------------------------------------" `
        -ForegroundColor Yellow

    foreach ($Product in $SkippedUninstalls) {

        Write-Host ""

        Write-Host "  [SKIPPED]" `
            -ForegroundColor Yellow

        Write-Host "  $Product" `
            -ForegroundColor White
    }
}

# ============================================================
# FAILED
# ============================================================

if ($FailedUninstalls.Count -gt 0) {

    Write-Host ""
    Write-Host "------------------------------------------------------------------------------" `
        -ForegroundColor Red

    Write-Host "                         FAILED UNINSTALLATIONS" `
        -ForegroundColor Red

    Write-Host "------------------------------------------------------------------------------" `
        -ForegroundColor Red

    foreach ($Product in $FailedUninstalls) {

        Write-Host ""

        Write-Host "  [FAILED]" `
            -ForegroundColor Red

        Write-Host "  $Product" `
            -ForegroundColor White
    }
}

# ============================================================
# FINAL STATUS
# ============================================================

Write-Host ""
Write-Host "=============================================================================="

if ($FailedCount -eq 0) {

    Write-Host ""
    Write-Host "                    CLEANUP COMPLETED SUCCESSFULLY" `
        -ForegroundColor Green
    Write-Host ""

}
else {

    Write-Host ""
    Write-Host "                    CLEANUP COMPLETED WITH ERRORS" `
        -ForegroundColor Red
    Write-Host ""
}

Write-Host "=============================================================================="

Write-Host ""

Write-Log `
    "Completed: $(Get-Date)" `
    "INFO"

Write-Log `
    "Successfully removed: $SuccessCount" `
    "INFO"

Write-Log `
    "Skipped: $SkippedCount" `
    "INFO"

Write-Log `
    "Failed: $FailedCount" `
    "INFO"

Write-Log `
    "Log File: $LogFile" `
    "INFO"

# ============================================================
# STOP TRANSCRIPT
# ============================================================

Stop-Transcript | Out-Null

# Return failure exit code only when something actually failed
if ($FailedCount -gt 0) {

    Exit 1
}
else {

    Exit 0
}
