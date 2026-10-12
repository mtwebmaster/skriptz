<#
.SYNOPSIS
    Removes all detected Dragon Medical One versions and reports other Nuance software.
.DESCRIPTION
    Inventories 32-bit and 64-bit uninstall registrations in HKLM and HKCU.
    Dragon Medical One is selected by product name, without a version restriction.
    Runs automatically under SYSTEM. Other Nuance products require individual
    interactive approval; they are skipped under SYSTEM or -NonInteractive.
    Uses MSI product codes or registered EXE QuietUninstallString values. Does
    not guess vendor silent switches, invoke a shell, or use Win32_Product.
    Checks the original registration after uninstall and records every result
    immediately to CSV, the activity log, and the console.
.PARAMETER LogDirectory
    Output directory. Defaults to C:\Temp. Logs are written even with -WhatIf.
.PARAMETER NonInteractive
    Skip all prompts for other Nuance products. Dragon Medical One still runs.
.EXAMPLE
    .\Remove-NuanceSoftware-v1.2.ps1 -WhatIf
.EXAMPLE
    .\Remove-NuanceSoftware-v1.2.ps1 -NonInteractive
.NOTES
    Script Name   : Remove-NuanceSoftware-v1.2.ps1
    Version       : 1.2.0
    Primary Author: Jeff Swenson
    AI Assistance : ChatGPT Pro | OpenAI
    Created       : 2026-10-12
    Last Modified : 2026-10-12
    Requirements  : Windows PowerShell 5.1+, elevated administrator or SYSTEM.
    Logging       : C:\Temp\NuanceRemoval_<run>.log; NuanceUninstalled_<run>.csv;
                    individual verbose NuanceMSI_<run>_<id>.log files.
    Exit Codes    : 0 completed; 1 failure/unresolved removal; 3010 reboot needed.
    Scope         : Machine installs and the executing account's user installs.
                    SYSTEM's HKCU is NOT the signed-in user's HKCU. Other users'
                    profiles and portable/unregistered copies are not scanned.
    Verification  : Registration absence is not proof that every file was deleted.
                    Reboot-pending entries are reported separately for rechecking.
    Security      : MSI requests no reboot. EXE behavior follows its registered
                    quiet command. No forced process termination or data wiping.
    Copyright     : 2026 Jeff Swenson. Intended for internal IT administration.
    Disclaimer    : AI-assisted; validate on a pilot workstation before rollout.
    Changelog     : 1.2.0 - All Dragon Medical One versions; unattended selection;
                    registration verification; CSV and console results retained.
                    1.1 - Added C:\Temp activity and uninstall-result logging.
#>
#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [ValidateNotNullOrEmpty()][string]$LogDirectory = 'C:\Temp',
    [switch]$NonInteractive
)

$ErrorActionPreference = 'Stop'
$run = '{0}_{1}_{2}' -f (Get-Date -Format 'yyyyMMdd_HHmmss'), $PID, ([guid]::NewGuid().ToString('N').Substring(0,8))
# .NET writes intentionally remain active in WhatIf so previews are auditable.
[void][IO.Directory]::CreateDirectory($LogDirectory)
$activity = Join-Path $LogDirectory "NuanceRemoval_$run.log"
$csv = Join-Path $LogDirectory "NuanceUninstalled_$run.csv"
$results = New-Object 'System.Collections.Generic.List[object]'
$restartRequired = $false
$failures = 0
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$canPrompt = -not $NonInteractive -and -not $identity.IsSystem -and [Environment]::UserInteractive
if ([Environment]::GetCommandLineArgs() -match '^-(NonI|NonInteractive)$') { $canPrompt = $false }

function Write-Log([string]$Message) {
    $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    [IO.File]::AppendAllText($activity, $line + [Environment]::NewLine)
    Write-Host $line
}

function Get-Software {
    $views = @([Microsoft.Win32.RegistryView]::Registry32)
    if ([Environment]::Is64BitOperatingSystem) { $views += [Microsoft.Win32.RegistryView]::Registry64 }
    foreach ($hive in @('LocalMachine', 'CurrentUser')) {
        foreach ($view in $views) {
            $base = $null; $root = $null
            try {
                $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]$hive, $view)
                $root = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
                if ($null -eq $root) { continue }
                foreach ($name in $root.GetSubKeyNames()) {
                    $key = $null
                    try {
                        $key = $root.OpenSubKey($name)
                        if ($null -eq $key) { continue }
                        $display = [string]$key.GetValue('DisplayName')
                        if (-not $display) { continue }
                        [pscustomobject]@{
                            Product = $display; Version = [string]$key.GetValue('DisplayVersion')
                            Publisher = [string]$key.GetValue('Publisher'); Hive = $hive
                            View = [string]$view; KeyName = $name
                            Id = "$hive|$view|$name"
                            MSI = ($key.GetValue('WindowsInstaller', 0) -eq 1)
                            Uninstall = [string]$key.GetValue('UninstallString')
                            Quiet = [string]$key.GetValue('QuietUninstallString')
                        }
                    } finally { if ($key) { $key.Dispose() } }
                }
            } finally {
                if ($root) { $root.Dispose() }; if ($base) { $base.Dispose() }
            }
        }
    }
}

function Add-Result($App, [string]$Status, $Code, [string]$Detail) {
    $row = [pscustomobject][ordered]@{
        Timestamp = (Get-Date -Format o); Computer = $env:COMPUTERNAME
        Product = $App.Product; Version = $App.Version; Publisher = $App.Publisher
        Scope = $App.Hive; View = $App.View; Status = $Status; ExitCode = $Code; Detail = $Detail
    }
    $results.Add($row)
    $row | Export-Csv -LiteralPath $csv -Append -NoTypeInformation -Encoding UTF8 -WhatIf:$false -Confirm:$false
    Write-Log "RESULT | $Status | $($App.Product) | Version=$($App.Version) | ExitCode=$Code | $Detail"
}

function Get-UninstallCommand($App) {
    $guidPattern = '\{[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}'
    $msiCommand = $App.Uninstall -match '^\s*(?:"[^"]*\\msiexec(?:\.exe)?"|(?:\S*\\)?msiexec(?:\.exe)?)(?:\s|$)'
    if ($App.MSI -or $msiCommand) {
        $code = $null
        if ($App.KeyName -match "^$guidPattern`$") { $code = $App.KeyName }
        elseif ($App.Uninstall -match "(?i)/[ix]\s*($guidPattern)") { $code = $Matches[1] }
        if (-not $code) { throw 'No reliable MSI product code found.' }
        $exe = Join-Path $env:WINDIR 'System32\msiexec.exe'
        if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
            $exe = Join-Path $env:WINDIR 'Sysnative\msiexec.exe'
        }
        $msiLog = Join-Path $LogDirectory "NuanceMSI_${run}_$([guid]::NewGuid().ToString('N')).log"
        return @{ File = $exe; Args = "/x $code /qn /norestart /L*v `"$msiLog`""; MSI = $true }
    }
    if (-not $App.Quiet) { throw 'No registered silent EXE uninstall command; manual review required.' }
    $command = [Environment]::ExpandEnvironmentVariables($App.Quiet).Trim()
    if ($command -match '^"([^"]+\.exe)"\s*(.*)$') {
        $exe = $Matches[1]; $arguments = $Matches[2]
    } elseif ($command -match '^(\S+\.exe)\s*(.*)$') {
        $exe = $Matches[1]; $arguments = $Matches[2]
    } else { throw 'Ambiguous EXE command; requires a quoted executable path.' }
    if (-not [IO.Path]::IsPathRooted($exe) -or -not [IO.File]::Exists($exe)) {
        throw 'Registered EXE must be an existing absolute path.'
    }
    if ([IO.Path]::GetFileName($exe) -match '^(cmd|powershell|pwsh|wscript|cscript|rundll32|msiexec)\.exe$') {
        throw 'Shell/wrapper uninstall command requires manual review.'
    }
    return @{ File = $exe; Args = $arguments; MSI = $false }
}

try {
    Write-Log "Started v1.2 | Computer=$env:COMPUTERNAME | User=$($identity.Name)"
    Write-Log 'Scope: HKLM both views plus executing user HKCU; other user profiles are excluded.'
    $apps = @(Get-Software | Where-Object {
        $_.Product -match '(?i)^Dragon\s+Medical\s+One(?:\s|$)' -or
        $_.Publisher -match '(?i)Nuance' -or $_.Product -match '(?i)Nuance'
    } | Sort-Object Product, Version, Id -Unique)
    Write-Log "Discovered $($apps.Count) relevant registrations."
    foreach ($app in $apps) {
        $target = $app.Product -match '(?i)^Dragon\s+Medical\s+One(?:\s|$)'
        if (-not $target) {
            if ($WhatIfPreference) {
                Add-Result $app 'ApprovalRequired' $null 'Other Nuance product; no removal authorized.'
                continue
            }
            $answer = 'N'
            if ($canPrompt) {
                try { $answer = Read-Host "Also remove $($app.Product) [$($app.Version)]? Type YES" }
                catch { Write-Log 'Prompt unavailable; skipping optional product.' }
            }
            if ($answer -cne 'YES') {
                Add-Result $app 'Skipped' $null 'Other Nuance product was not approved.'
                continue
            }
        }
        if (-not $PSCmdlet.ShouldProcess("$($app.Product) [$($app.Version)]", 'Uninstall')) {
            $status = 'Skipped'; if ($WhatIfPreference) { $status = 'WhatIf' }
            Add-Result $app $status $null 'No uninstall executed.'
            continue
        }
        $exitCode = $null
        try {
            if (-not @(Get-Software | Where-Object Id -eq $app.Id).Count) {
                Add-Result $app 'AlreadyAbsent' $null 'Registration no longer exists.'
                continue
            }
            $command = Get-UninstallCommand $app
            Write-Log "Starting uninstall: $($app.Product) [$($app.Version)]"
            $start = @{ FilePath = $command.File; Wait = $true; PassThru = $true; ErrorAction = 'Stop' }
            if ($command.Args) { $start.ArgumentList = $command.Args }
            $process = Start-Process @start
            $exitCode = $process.ExitCode
            $process.Dispose()
            $successCodes = @(0)
            if ($command.MSI) { $successCodes = @(0, 1641, 3010, 1605, 1614) }
            if ($command.MSI -and $exitCode -in @(1641,3010)) { $restartRequired = $true }
            if ($exitCode -notin $successCodes) { throw "Uninstaller returned $exitCode." }
            $present = $true
            for ($attempt = 0; $attempt -lt 6; $attempt++) {
                $present = @(Get-Software | Where-Object Id -eq $app.Id).Count -gt 0
                if (-not $present) { break }
                if ($attempt -lt 5) { Start-Sleep -Seconds 2 }
            }
            if (-not $present) {
                Add-Result $app 'RemovedVerified' $exitCode 'Original uninstall registration is absent.'
            } elseif ($command.MSI -and $exitCode -in @(1641,3010)) {
                Add-Result $app 'PendingReboot' $exitCode 'Registration remains; recheck after reboot.'
            } else { throw 'Uninstaller finished but the original registration remains.' }
        } catch {
            $failures++
            Add-Result $app 'Failed' $exitCode $_.Exception.Message
        }
    }
    if ($apps.Count -eq 0) { Write-Log 'No matching software found; no changes made.' }
} catch {
    $failures++
    Write-Log "FATAL | $($_.Exception.Message)"
} finally {
    Write-Host "`n========== NUANCE UNINSTALL RESULTS =========="
    if ($results.Count) { $results | Format-Table Product, Version, Status, ExitCode -AutoSize | Out-Host }
    Write-Log "Finished | Failures=$failures | RestartRequired=$restartRequired"
    Write-Host "Activity log: $activity"
    if ([IO.File]::Exists($csv)) { Write-Host "Results CSV : $csv" }
}
if ($failures -gt 0) { exit 1 }
if ($restartRequired) { exit 3010 }
exit 0
