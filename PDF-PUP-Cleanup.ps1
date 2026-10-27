<#
.SYNOPSIS
    Audits and optionally cleans OneStart/OneBrowser persistence with a PDF-app watchlist.
.DESCRIPTION
    Safe-by-default. Audits registered apps, loaded-user Run/RunOnce registry keys,
    scheduled tasks, services, running processes, known application directories,
    and a small set of installer filenames. Outputs CSV and text reports.
    Remediate mode removes only explicit OneStart/OneBrowser persistence and known
    folders after typed confirmation; it does NOT automatically uninstall or delete
    cataloged PDF/manual products, OneLaunch, or SentinelOne files.
.AUTHOR
    Jeff Swenson | Technical assistance: ChatGPT / OpenAI GPT-6
.VERSION
    2.0.0 - 2026-10-27
.REQUIREMENTS
    Windows 10/11; Windows PowerShell 5.1; elevated 64-bit PowerShell recommended.
.EXAMPLE
    .\PDF-PUP-Cleanup.ps1
.EXAMPLE
    .\PDF-PUP-Cleanup.ps1 -Mode Remediate
.NOTES
    Always confirm app ownership and preserve browser profiles before cleanup.
    Cross-user registry analysis includes only currently loaded user hives.
    Restore points are best effort; exported XML/.reg files do NOT restore deleted data.
.CHANGELOG
    2.0: catalog-backed detection, user-profile coverage, persistence review,
    backups, safe remediation gate, post-cleanup rescan, optional Defender scan.
#>
#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Audit','Remediate')]
    [string]$Mode = 'Audit',
    [string]$CatalogPath = (Join-Path $PSScriptRoot 'PDF_PUP_Watchlist.csv'),
    [switch]$SkipRestorePoint,
    [switch]$SkipDefenderScan
)

$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Run this script on Windows.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($Mode -eq 'Remediate' -and -not $isAdmin) {
    throw 'Remediate mode requires an elevated PowerShell session.'
}
if ($Mode -eq 'Remediate' -and [Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    throw 'Start 64-bit PowerShell for complete registry and filesystem access.'
}

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$reportRoot = if ($isAdmin) { $env:ProgramData } else { $env:LOCALAPPDATA }
$runRoot = Join-Path $reportRoot "PDF-PUP-Cleanup\$stamp"
New-Item -ItemType Directory -Path $runRoot -Force | Out-Null
# Reports can contain user paths and task arguments. Restrict elevated runs.
if ($isAdmin) {
    & icacls.exe $runRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' 2>$null | Out-Null
}
$script:logPath = Join-Path $runRoot 'activity.log'
$script:Findings = New-Object 'System.Collections.Generic.List[object]'
$script:CandidateTasks = @()
$script:CandidateServices = @()
$script:CandidateProcesses = @()
$script:CandidateStartup = @()
$script:CandidatePaths = @()
$script:Catalog = @()
$script:coreName = '(?i)^(?:(?:OneStart(?:\.ai)?|OneBrowser)(?:\.exe| Browser\b| Update\b| Updater\b| Service\b|$)|(?:OneBUpdate|OneBUpdateService|OBUpdateService|OneStartBrowser|OSBrowser)(?:[ ._\-]|$))'
$script:coreInText = '(?i)(?:\\|/)(?:OneStart(?:\.ai)?|OneBrowser|OB)(?:\\|/)|\b(?:OneStart|OneBrowser|OneBUpdate|OneBUpdateService|OBUpdateService|OSBrowser)\.exe\b'
$script:scriptPersist = '(?i)(?:node(?:\.exe)?\b.{0,250}AppData[\\/](?:Local[\\/])?Temp[\\/].{0,180}\.js\b)|(?:mshta(?:\.exe)?\b.{0,250}https?://)'

function Log([string]$Message, [string]$Level = 'INFO') {
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 's'), $Level, $Message
    Write-Host $line
    Add-Content -LiteralPath $script:logPath -Value $line -Encoding UTF8
}
function Add-Finding([string]$Kind,[string]$Name,[string]$Disposition,[string]$Location,[string]$Evidence,[string]$Detail='') {
    $script:Findings.Add([pscustomobject]@{
        Kind=$Kind; Name=$Name; Disposition=$Disposition; Location=$Location
        Evidence=$Evidence; Detail=$Detail
    })
}
function Get-WatchMatch([string]$Text) {
    foreach ($c in $script:Catalog) {
        if ($Text -match $c.MatchRegex) { return $c }
    }
    return $null
}
function Is-Core([string]$Name,[string]$Evidence) {
    return (($Name -match $script:coreName) -or ($Evidence -match $script:coreInText))
}
function Export-Findings([string]$Name) {
    $path = Join-Path $runRoot $Name
    if ($script:Findings.Count -gt 0) {
        $script:Findings | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
    } else {
        'Kind,Name,Disposition,Location,Evidence,Detail' | Set-Content -LiteralPath $path -Encoding UTF8
    }
    Log "Report written: $path ($($script:Findings.Count) findings)"
}

if (Test-Path -LiteralPath $CatalogPath) {
    $script:Catalog = @(Import-Csv -LiteralPath $CatalogPath)
    foreach ($c in $script:Catalog) {
        if (-not $c.Name -or -not $c.MatchRegex -or -not $c.DefaultAction) {
            throw "Watchlist entry missing required fields: $($c | Out-String)"
        }
        try { [void][regex]::new($c.MatchRegex) } catch { throw "Invalid watchlist regex for $($c.Name): $_" }
    }
} else {
    throw "Catalog file missing: $CatalogPath. Keep the CSV next to the script."
}
Log "Mode=$Mode  Host=$env:COMPUTERNAME  Elevated=$isAdmin  Catalog=$($script:Catalog.Count) entries"
if (-not $isAdmin) { Log 'Audit is not elevated; some process, registry and system details may be inaccessible.' 'WARN' }
if (-not [Environment]::Is64BitProcess) { Log '32-bit PowerShell limits registry visibility; use 64-bit PowerShell.' 'WARN' }

function Gather-InstalledApps {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    # Loaded user hives only; unloaded user registry hives are not mounted here.
    $userHives = @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^(?:S-1-5-21|S-1-12-1)-[0-9-]+$' })
    foreach ($u in $userHives) {
        $keys += "Registry::HKEY_USERS\$($u.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
        $keys += "Registry::HKEY_USERS\$($u.PSChildName)\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    }
    foreach ($app in @(Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue)) {
        if (-not $app.DisplayName) { continue }
        $match = Get-WatchMatch ([string]$app.DisplayName)
        if ($null -eq $match) { continue }
        $disposition = 'ReviewOnly'
        if ($match.DefaultAction -eq 'CleanupCandidate') { $disposition = 'UninstallFirst' }
        Add-Finding 'InstalledApp' $match.Name $disposition ([string]$app.PSPath) ([string]$app.DisplayName) ("Publisher={0}; Version={1}; InstallLocation={2}; UninstallString={3}" -f $app.Publisher,$app.DisplayVersion,$app.InstallLocation,$app.UninstallString)
    }
    return $userHives
}

function Gather-Tasks {
    try { $tasks = @(Get-ScheduledTask -ErrorAction Stop) }
    catch { Log "Could not enumerate scheduled tasks: $_" 'WARN'; return }
    foreach ($task in $tasks) {
        $actions = @($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments) $($_.WorkingDirectory)" }) -join ' | '
        $nameAndPath = "$($task.TaskPath)$($task.TaskName)"
        $isCore = Is-Core $nameAndPath $actions
        $suspicious = ($actions -match $script:scriptPersist) -or ($task.TaskName -in @('PDFEditorScheduledTask','PDFEditorUScheduledTask'))
        $watch = Get-WatchMatch $task.TaskName
        if (-not $watch) { $watch = Get-WatchMatch $actions }
        if (-not $isCore -and -not $suspicious -and -not $watch) { continue }
        $disposition = if ($isCore) { 'CleanupCandidate' } else { 'ReviewOnly' }
        Add-Finding 'ScheduledTask' $task.TaskName $disposition $nameAndPath $actions ("State={0}; ScriptHeuristic={1}" -f $task.State,$suspicious)
        if ($isCore) { $script:CandidateTasks += $task }
    }
}

function Gather-Services {
    try { $services = @(Get-CimInstance Win32_Service -ErrorAction Stop) }
    catch { Log "Could not enumerate services: $_" 'WARN'; return }
    foreach ($svc in $services) {
        $isCore = Is-Core $svc.Name $svc.PathName
        $watch = Get-WatchMatch $svc.DisplayName
        if (-not $watch) { $watch = Get-WatchMatch $svc.Name }
        if (-not $isCore -and -not $watch) { continue }
        $disposition = if ($isCore) { 'CleanupCandidate' } else { 'ReviewOnly' }
        Add-Finding 'Service' $svc.Name $disposition $svc.PathName $svc.DisplayName ("State={0}; StartMode={1}" -f $svc.State,$svc.StartMode)
        if ($isCore) { $script:CandidateServices += $svc }
    }
}

function Gather-Processes {
    try { $processes = @(Get-CimInstance Win32_Process -ErrorAction Stop) }
    catch { Log "Could not enumerate processes: $_" 'WARN'; return }
    foreach ($proc in $processes) {
        $isCore = Is-Core $proc.Name $proc.ExecutablePath
        $watch = Get-WatchMatch $proc.Name
        if (-not $isCore -and -not $watch) { continue }
        $disposition = if ($isCore) { 'CleanupCandidate' } else { 'ReviewOnly' }
        Add-Finding 'Process' $proc.Name $disposition ([string]$proc.ExecutablePath) ([string]$proc.CommandLine) ("PID={0}" -f $proc.ProcessId)
        if ($isCore) { $script:CandidateProcesses += $proc }
    }
}

function Gather-Startup([object[]]$UserHives) {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($u in $UserHives) {
        foreach ($part in @('Run','RunOnce')) {
            $keys += "Registry::HKEY_USERS\$($u.PSChildName)\Software\Microsoft\Windows\CurrentVersion\$part"
            $keys += "Registry::HKEY_USERS\$($u.PSChildName)\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\$part"
        }
    }
    foreach ($key in ($keys | Sort-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $key)) { continue }
        try { $entry = Get-ItemProperty -LiteralPath $key -ErrorAction Stop }
        catch { Log "Could not read $key : $_" 'WARN'; continue }
        foreach ($p in $entry.PSObject.Properties) {
            if ($p.Name -match '^PS(?:Path|ParentPath|ChildName|Drive|Provider)$') { continue }
            if ($p.Name -match '^PS') { continue }
            $valueText = [string]$p.Value
            $isCore = Is-Core $p.Name $valueText
            $watch = Get-WatchMatch $p.Name
            if (-not $watch) { $watch = Get-WatchMatch $valueText }
            if (-not $isCore -and -not $watch) { continue }
            $disposition = if ($isCore) { 'CleanupCandidate' } else { 'ReviewOnly' }
            Add-Finding 'StartupRegistry' $p.Name $disposition $key $valueText ''
            if ($isCore) {
                $script:CandidateStartup += [pscustomobject]@{ Key=$key; Name=$p.Name; Value=$valueText }
            }
        }
    }
}

function Gather-Paths {
    $candidates = New-Object 'System.Collections.Generic.List[object]'
    $roots = @($env:ProgramFiles,${env:ProgramFiles(x86)},$env:ProgramData) | Where-Object { $_ }
    foreach ($root in $roots) {
        foreach ($name in @('OneStart','OneStart.ai','OneBrowser')) {
            $candidates.Add([pscustomobject]@{ Path=(Join-Path $root $name); Product=$name; RemoveAllowed=$true })
        }
        $candidates.Add([pscustomobject]@{Path=(Join-Path $root 'OB'); Product='OneBrowser (OB)'; RemoveAllowed=$false})
    }
    try { $profiles = @(Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { -not $_.Special -and $_.LocalPath }) }
    catch { Log "User profile enumeration failed: $_" 'WARN'; $profiles = @() }
    foreach ($profile in $profiles) {
        $root = $profile.LocalPath
        foreach ($part in @('AppData\Local','AppData\Roaming','AppData\Local\Programs')) {
            foreach ($name in @('OneStart','OneStart.ai','OneBrowser')) {
                $candidates.Add([pscustomobject]@{Path=(Join-Path $root "$part\$name"); Product=$name; RemoveAllowed=$true})
            }
        }
        # The generic folder name OB is only removable when verified by OneBrowser files.
        $candidates.Add([pscustomobject]@{Path=(Join-Path $root 'AppData\Local\OB'); Product='OneBrowser (OB)'; RemoveAllowed=$false})
        $candidates.Add([pscustomobject]@{Path=(Join-Path $root 'AppData\Roaming\OB'); Product='OneBrowser (OB)'; RemoveAllowed=$false})
        $candidates.Add([pscustomobject]@{Path=(Join-Path $root 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneBrowser.lnk'); Product='OneBrowser shortcut'; RemoveAllowed=$true})
        $candidates.Add([pscustomobject]@{Path=(Join-Path $root 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneStart.lnk'); Product='OneStart shortcut'; RemoveAllowed=$true})
        $candidates.Add([pscustomobject]@{Path=(Join-Path $root 'AppData\Local\Programs\GooPDF'); Product='GooPDF'; RemoveAllowed=$false})
        $candidates.Add([pscustomobject]@{Path=(Join-Path $root 'Desktop\GooPDF.lnk'); Product='GooPDF shortcut'; RemoveAllowed=$false})
        # Sample PDF executable; detection only, not inferred malicious by filename.
        $candidates.Add([pscustomobject]@{Path=(Join-Path $root 'Downloads\PDF_28880.exe'); Product='PDF_28880 installer'; RemoveAllowed=$false})
    }
    foreach ($candidate in @($candidates | Sort-Object Path -Unique)) {
        if (-not (Test-Path -LiteralPath $candidate.Path)) { continue }
        $allow = [bool]$candidate.RemoveAllowed
        if ($candidate.Product -eq 'OneBrowser (OB)') {
            $dir = $candidate.Path
            $hasBrowser = (Test-Path -LiteralPath (Join-Path $dir 'Application\OneBrowser.exe')) -or
                          (Test-Path -LiteralPath (Join-Path $dir 'OneBUpdate\OneBUpdateService.exe'))
            $allow = [bool]$hasBrowser
        }
        $disposition = if ($allow) {'CleanupCandidate'} else {'ReviewOnly'}
        Add-Finding 'Path' $candidate.Product $disposition $candidate.Path 'Known software path' ("IdentifiedForRemoval={0}" -f $allow)
        if ($allow) { $script:CandidatePaths += $candidate.Path }
    }
}

function Gather-InstallerArtifacts {
    try { $profiles = @(Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { -not $_.Special -and $_.LocalPath }) }
    catch { return }
    $names = @('PDFEditorSetup.exe','ManualFinderApp.exe','PDF_28880.exe')
    foreach ($profile in $profiles) {
        foreach ($folderName in @('Downloads','Desktop')) {
            $folder = Join-Path $profile.LocalPath $folderName
            foreach ($name in $names) {
                $path = Join-Path $folder $name
                if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
                $sha = 'Unavailable'; $sig = 'Unavailable'
                try { $sha = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash } catch {}
                try { $sig = (Get-AuthenticodeSignature -LiteralPath $path).Status } catch {}
                Add-Finding 'InstallerArtifact' $name 'ReviewOnly' $path 'Observed filename; not proof of maliciousness' ("SHA256={0}; SignatureStatus={1}" -f $sha,$sig)
            }
        }
    }
}

Log 'Collecting software and persistence inventory'
$hives = @(Gather-InstalledApps)
Gather-Tasks
Gather-Services
Gather-Processes
Gather-Startup $hives
Gather-Paths
Gather-InstallerArtifacts
Export-Findings 'Findings_Before.csv'
$script:Findings | Group-Object Kind,Disposition | Sort-Object Name | ForEach-Object {
    Log ("{0}: {1}" -f $_.Name,$_.Count)
}

if ($Mode -eq 'Audit') {
    Log 'AUDIT COMPLETE. No applications, tasks, registry values, services or files were removed.'
    Log "Reports: $runRoot"
    return
}

Log 'REMEDIATION PREVIEW: only CleanupCandidate persistence and known OneStart/OneBrowser paths are eligible.' 'WARN'
Log ("Candidates: {0} task(s), {1} service(s), {2} process(es), {3} startup entry/entries, {4} path(s)." -f $script:CandidateTasks.Count,$script:CandidateServices.Count,$script:CandidateProcesses.Count,$script:CandidateStartup.Count,$script:CandidatePaths.Count)
Log 'Registered app uninstallers are NOT run. PDF/manual watchlist applications and OneLaunch are NEVER automatically removed.' 'WARN'
$answer = Read-Host 'Type REMOVE (exact uppercase) to proceed; anything else cancels'
if ($answer -cne 'REMOVE') { Log 'Cancelled. No cleanup actions performed.'; return }

$backup = Join-Path $runRoot 'Backups'
New-Item -ItemType Directory -Path $backup -Force | Out-Null
if (-not $SkipRestorePoint) {
    try {
        Checkpoint-Computer -Description "Before_PDF_PUP_Cleanup_$stamp" -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        Log 'Windows restore point created.'
    } catch { Log "Restore point not available: $_" 'WARN' }
}

# A conservative order: back up first, then disable persistence, stop processes, remove leftovers.
foreach ($task in $script:CandidateTasks) {
    $filename = 'task_' + [Guid]::NewGuid().ToString('N') + '.xml'
    try {
        $taskXml = Export-ScheduledTask -InputObject $task -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($taskXml)) { throw 'Task XML backup was empty.' }
        $taskXml | Set-Content -LiteralPath (Join-Path $backup $filename) -Encoding UTF8 -ErrorAction Stop
        Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction Stop
        Log "Removed task $($task.TaskPath)$($task.TaskName); backup=$filename"
    } catch { Log "Task not removed or backup failed ($($task.TaskName)): $_" 'ERROR' }
}
foreach ($item in $script:CandidateStartup) {
    $nativeKey = $item.Key -replace '^HKLM:\\','HKEY_LOCAL_MACHINE\' -replace '^Registry::',''
    $filename = 'registry_' + [Guid]::NewGuid().ToString('N') + '.reg'
    $target = Join-Path $backup $filename
    try {
        & reg.exe export $nativeKey $target /y *> $null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $target)) {
            throw 'Registry key export failed; entry left intact.'
        }
        Remove-ItemProperty -LiteralPath $item.Key -Name $item.Name -ErrorAction Stop
        Log "Removed startup entry '$($item.Name)' from $($item.Key); backup=$filename"
    } catch { Log "Startup entry not removed ($($item.Name)): $_" 'ERROR' }
}
foreach ($svc in $script:CandidateServices) {
    $filename = 'service_' + [Guid]::NewGuid().ToString('N') + '.reg'
    $key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$($svc.Name)"
    $target = Join-Path $backup $filename
    try {
        & reg.exe export $key $target /y *> $null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $target)) {
            throw 'Service registry export failed; service left intact.'
        }
        & sc.exe stop $svc.Name *> $null
        & sc.exe delete $svc.Name *> $null
        if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed (exit $LASTEXITCODE)" }
        Log "Service deletion requested: $($svc.Name); backup=$filename (may require restart)"
    } catch { Log "Service cleanup failed ($($svc.Name)): $_" 'ERROR' }
}
foreach ($proc in $script:CandidateProcesses) {
    try {
        Stop-Process -Id $proc.ProcessId -Force -ErrorAction Stop
        Log "Stopped process $($proc.Name), PID $($proc.ProcessId)"
    } catch { Log "Could not stop process PID $($proc.ProcessId): $_" 'WARN' }
}
foreach ($path in ($script:CandidatePaths | Sort-Object -Unique)) {
    try {
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Log "Skipping reparse point to prevent unexpected traversal: $path" 'WARN'
            continue
        }
        Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
        if (Test-Path -LiteralPath $path) { throw 'Path still exists after removal attempt.' }
        Log "Removed: $path"
    } catch { Log "Could not remove $path : $_" 'ERROR' }
}

# Optional Microsoft Defender scan only if it's the active AV. SentinelOne is not touched.
if (-not $SkipDefenderScan) {
    try {
        if ((Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) -and
            (Get-MpComputerStatus -ErrorAction Stop).AMRunningMode -eq 'Normal') {
            Start-MpScan -ScanType QuickScan -ErrorAction Stop
            Log 'Microsoft Defender quick scan requested.'
        } else {
            Log 'Defender not active; skipped quick scan. Use the managed EDR console if required.'
        }
    } catch { Log "Defender scan unavailable: $_" 'WARN' }
}

# Capture post-remediation state afresh; don't mistake deletion attempts for proof of success.
$script:Findings.Clear()
$script:CandidateTasks = @(); $script:CandidateServices = @()
$script:CandidateProcesses = @(); $script:CandidateStartup = @(); $script:CandidatePaths = @()
Log 'Collecting post-cleanup inventory'
$hives = @(Gather-InstalledApps)
Gather-Tasks
Gather-Services
Gather-Processes
Gather-Startup $hives
Gather-Paths
Gather-InstallerArtifacts
Export-Findings 'Findings_After.csv'
$remaining = @($script:Findings | Where-Object { $_.Disposition -eq 'CleanupCandidate' })
Log "Remediation finished. Remaining cleanup candidates: $($remaining.Count). Review the After report and log."
Log 'Note: installed app registry entries require vendor-uninstaller review; loaded user hives only.'
Log "Evidence/report directory: $runRoot"
