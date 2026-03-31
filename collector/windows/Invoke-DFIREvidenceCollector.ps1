[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CaseId,

    [Parameter(Mandatory = $true)]
    [string]$OutputRoot,

    [ValidateSet("Lite", "Incident", "Ransomware", "Persistence", "Full")]
    [string]$Profile = "Incident",

    [int]$MaxDays = 14,

    [switch]$NoZip,
    [switch]$IncludeBrowserArtefacts,
    [switch]$IncludeMemory,
    [switch]$IncludeYara,
    [switch]$ZipSharePackage
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-SafeDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Object
    )
    $Object | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $Path -Encoding utf8
}

function Write-TextFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )
    $Text | Out-File -LiteralPath $Path -Encoding utf8
}

function Invoke-CollectorCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [Parameter(Mandatory = $true)][string]$OutDir,
        [switch]$AsJson
    )

    try {
        $result = & $ScriptBlock 2>&1
        if ($AsJson) {
            $jsonPath = Join-Path $OutDir "$Name.json"
            $result | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $jsonPath -Encoding utf8
        }
        $txtPath = Join-Path $OutDir "$Name.txt"
        ($result | Out-String -Width 4096) | Out-File -LiteralPath $txtPath -Encoding utf8
    }
    catch {
        $errPath = Join-Path $OutDir "$Name.error.txt"
        $_ | Out-String | Out-File -LiteralPath $errPath -Encoding utf8
    }
}

function Export-CsvSafe {
    param(
        [Parameter(Mandatory = $true)]$InputObject,
        [Parameter(Mandatory = $true)][string]$Path
    )
    try {
        $InputObject | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding utf8
    }
    catch {
        $_ | Out-String | Out-File -LiteralPath ($Path + ".error.txt") -Encoding utf8
    }
}

function Copy-IfExists {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    try {
        if (Test-Path -LiteralPath $Source) {
            $destDir = Split-Path -Path $Destination -Parent
            New-SafeDirectory -Path $destDir
            Copy-Item -LiteralPath $Source -Destination $Destination -Recurse -Force -ErrorAction Stop
        }
    }
    catch {
        $_ | Out-String | Out-File -LiteralPath ($Destination + ".error.txt") -Encoding utf8
    }
}

function Copy-GlobSafe {
    param(
        [Parameter(Mandatory = $true)][string]$SourceGlob,
        [Parameter(Mandatory = $true)][string]$DestinationDir,
        [int]$Limit = 100
    )
    try {
        New-SafeDirectory -Path $DestinationDir
        Get-ChildItem -Path $SourceGlob -Force -ErrorAction SilentlyContinue | Select-Object -First $Limit | ForEach-Object {
            try {
                Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $DestinationDir $_.Name) -Force -ErrorAction Stop
            } catch {
                $_ | Out-String | Out-File -LiteralPath ((Join-Path $DestinationDir ($_.Exception.GetType().Name + ".error.txt"))) -Encoding utf8
            }
        }
    }
    catch {
        $_ | Out-String | Out-File -LiteralPath (Join-Path $DestinationDir "copy_glob.error.txt") -Encoding utf8
    }
}

function Export-LogIfExists {
    param(
        [Parameter(Mandatory = $true)][string]$LogName,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    try {
        & wevtutil.exe gl "$LogName" | Out-Null
        & wevtutil.exe epl "$LogName" "$Destination" /ow:true | Out-Null
    }
    catch {
        $_ | Out-String | Out-File -LiteralPath ($Destination + ".error.txt") -Encoding utf8
    }
}

function Collect-RunKeys {
    param([Parameter(Mandatory = $true)][string]$DestinationCsv)
    $rows = @()
    $targets = @(
        @{ Hive = "HKLM"; Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" },
        @{ Hive = "HKLM"; Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" },
        @{ Hive = "HKCU"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" },
        @{ Hive = "HKCU"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" }
    )

    foreach ($target in $targets) {
        try {
            if (Test-Path -LiteralPath $target.Path) {
                $props = Get-ItemProperty -LiteralPath $target.Path
                foreach ($property in $props.PSObject.Properties) {
                    if ($property.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
                        $rows += [pscustomobject]@{
                            Hive         = $target.Hive
                            RegistryPath = $target.Path
                            ValueName    = $property.Name
                            ValueData    = [string]$property.Value
                        }
                    }
                }
            }
        } catch {
            $_ | Out-String | Out-File -LiteralPath ($DestinationCsv + ".error.txt") -Encoding utf8 -Append
        }
    }

    Export-CsvSafe -InputObject $rows -Path $DestinationCsv
}

function Get-InstalledSoftware {
    $paths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $rows = foreach ($path in $paths) {
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject]@{
                DisplayName     = $_.DisplayName
                DisplayVersion  = $_.DisplayVersion
                Publisher       = $_.Publisher
                InstallDate     = $_.InstallDate
                InstallLocation = $_.InstallLocation
                UninstallString = $_.UninstallString
            }
        }
    }
    $rows | Where-Object { $_.DisplayName }
}

function Get-ScheduledTasksFlat {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    foreach ($task in $tasks) {
        [pscustomobject]@{
            TaskName = $task.TaskName
            TaskPath = $task.TaskPath
            State = $task.State
            Author = $task.Author
            Description = $task.Description
            Actions = (($task.Actions | ForEach-Object {
                $parts = @($_.Execute, $_.Arguments, $_.WorkingDirectory) | Where-Object { $_ }
                ($parts -join " ")
            }) -join " ; ")
            Triggers = (($task.Triggers | ForEach-Object { $_.ToString() }) -join " ; ")
        }
    }
}

function Get-WmiSubscriptionsFlat {
    $filters = Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
    $consumers = Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
    $bindings = Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue

    [pscustomobject]@{
        Filters   = $filters
        Consumers = $consumers
        Bindings  = $bindings
    }
}

function Get-DriverList {
    Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, State, StartMode, PathName
}

function Get-ProcessList {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object Name, ProcessId, ParentProcessId, ExecutablePath, CommandLine, CreationDate
}

function Get-ServiceList {
    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, State, StartMode, PathName, ProcessId, StartName
}

function Get-TcpListeners {
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, OwningProcess, CreationTime
}

function Get-TcpConnections {
    Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, CreationTime
}

function Get-LocalGroupMembersFlat {
    $groups = Get-LocalGroup -ErrorAction SilentlyContinue
    foreach ($group in $groups) {
        try {
            Get-LocalGroupMember -Group $group.Name -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{
                    GroupName       = $group.Name
                    MemberName      = $_.Name
                    ObjectClass     = $_.ObjectClass
                    PrincipalSource = $_.PrincipalSource
                }
            }
        } catch {
            [pscustomobject]@{
                GroupName       = $group.Name
                MemberName      = "<error>"
                ObjectClass     = ""
                PrincipalSource = ""
            }
        }
    }
}

function Get-DefenderStatusSafe {
    try {
        Get-MpComputerStatus -ErrorAction Stop | Select-Object *
    } catch {
        [pscustomobject]@{
            Error = $_.Exception.Message
        }
    }
}

function Get-DefenderThreatsSafe {
    try {
        Get-MpThreatDetection -ErrorAction Stop | Select-Object *
    } catch {
        @()
    }
}

function Get-DefenderPreferencesSafe {
    try {
        Get-MpPreference -ErrorAction Stop | Select-Object *
    } catch {
        [pscustomobject]@{
            Error = $_.Exception.Message
        }
    }
}

function Get-UserProfileDirectories {
    Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -notin @("All Users", "Default", "Default User", "Public", "defaultuser0")
    }
}

$CaseDir = Join-Path $OutputRoot $CaseId
$DirCase = Join-Path $CaseDir "00_case"
$DirSystem = Join-Path $CaseDir "01_system"
$DirLogs = Join-Path $CaseDir "02_logs"
$DirPersistence = Join-Path $CaseDir "03_persistence"
$DirExecution = Join-Path $CaseDir "04_execution"
$DirNetwork = Join-Path $CaseDir "05_network"
$DirUser = Join-Path $CaseDir "06_user_activity"
$DirSecurity = Join-Path $CaseDir "07_security"
$DirTimeline = Join-Path $CaseDir "08_timeline"
$DirFindings = Join-Path $CaseDir "09_findings"
$DirScreens = Join-Path $CaseDir "10_screenshots"
$DirReports = Join-Path $CaseDir "11_reports"
$DirMemory = Join-Path $CaseDir "12_memory"
$DirShare = Join-Path $CaseDir "99_share_with_internal_or_controlled_ai"

$DirUsb = Join-Path $DirSystem "usb"
$DirPrefetch = Join-Path $DirUser "prefetch"
$DirRecent = Join-Path $DirUser "recent"
$DirLnk = Join-Path $DirUser "lnk"
$DirJumpLists = Join-Path $DirUser "jumplists"
$DirBrowser = Join-Path $DirUser "browser"
$DirAmcache = Join-Path $DirTimeline "amcache"
$DirSrum = Join-Path $DirTimeline "srum"

@(
    $OutputRoot, $CaseDir, $DirCase, $DirSystem, $DirLogs, $DirPersistence,
    $DirExecution, $DirNetwork, $DirUser, $DirSecurity, $DirTimeline,
    $DirFindings, $DirScreens, $DirReports, $DirMemory, $DirShare,
    $DirUsb, $DirPrefetch, $DirRecent, $DirLnk, $DirJumpLists,
    $DirBrowser, $DirAmcache, $DirSrum
) | ForEach-Object { New-SafeDirectory -Path $_ }

$caseMetadata = [ordered]@{
    CaseId = $CaseId
    Profile = $Profile
    MaxDays = $MaxDays
    CollectedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
    CollectedAtLocal = (Get-Date).ToString("o")
    CollectorUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    Hostname = $env:COMPUTERNAME
    Domain = $env:USERDOMAIN
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    IsAdmin = ([bool](([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)))
    IncludeBrowserArtefacts = [bool]$IncludeBrowserArtefacts
    IncludeMemory = [bool]$IncludeMemory
    IncludeYara = [bool]$IncludeYara
    ZipSharePackage = [bool]$ZipSharePackage
}

Write-JsonFile -Path (Join-Path $DirCase "case_metadata.json") -Object $caseMetadata
Write-JsonFile -Path (Join-Path $DirCase "chain_of_custody.json") -Object ([ordered]@{
    CaseId = $CaseId
    CollectedAtUtc = $caseMetadata.CollectedAtUtc
    CollectedBy = $caseMetadata.CollectorUser
    Hostname = $caseMetadata.Hostname
    Notes = "Triage collection produced by Invoke-DFIREvidenceCollector.ps1"
})

# System context
Invoke-CollectorCommand -Name "computer_info" -ScriptBlock {
    Get-ComputerInfo | Select-Object CsName, WindowsProductName, WindowsVersion, WindowsBuildLabEx, CsDomain, CsUserName, OsArchitecture, OsLastBootUpTime, BiosSerialNumber
} -OutDir $DirSystem -AsJson

Export-CsvSafe -InputObject (Get-CimInstance Win32_OperatingSystem | Select-Object *) -Path (Join-Path $DirSystem "os.csv")
Export-CsvSafe -InputObject (Get-CimInstance Win32_ComputerSystem | Select-Object *) -Path (Join-Path $DirSystem "computer_system.csv")
Export-CsvSafe -InputObject (Get-NetIPConfiguration -ErrorAction SilentlyContinue | Select-Object *) -Path (Join-Path $DirSystem "ip_configuration.csv")
Export-CsvSafe -InputObject (Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object *) -Path (Join-Path $DirNetwork "dns_cache.csv")
Export-CsvSafe -InputObject (Get-LocalUser -ErrorAction SilentlyContinue | Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordExpires, UserMayChangePassword, SID) -Path (Join-Path $DirSystem "local_users.csv")
Export-CsvSafe -InputObject (Get-LocalGroupMembersFlat) -Path (Join-Path $DirSystem "local_group_members.csv")
Export-CsvSafe -InputObject (Get-InstalledSoftware) -Path (Join-Path $DirSystem "installed_software.csv")
Invoke-CollectorCommand -Name "arp_table" -ScriptBlock { arp -a } -OutDir $DirNetwork
Invoke-CollectorCommand -Name "route_print" -ScriptBlock { route print } -OutDir $DirNetwork
Invoke-CollectorCommand -Name "net_share" -ScriptBlock { net share } -OutDir $DirSystem
Invoke-CollectorCommand -Name "whoami_all" -ScriptBlock { whoami /all } -OutDir $DirCase

# Execution / services / drivers
Export-CsvSafe -InputObject (Get-ProcessList) -Path (Join-Path $DirExecution "processes.csv")
Export-CsvSafe -InputObject (Get-ServiceList) -Path (Join-Path $DirExecution "services.csv")
Export-CsvSafe -InputObject (Get-DriverList) -Path (Join-Path $DirExecution "drivers.csv")

# Persistence
Export-CsvSafe -InputObject (Get-ScheduledTasksFlat) -Path (Join-Path $DirPersistence "scheduled_tasks.csv")
Collect-RunKeys -DestinationCsv (Join-Path $DirPersistence "run_keys.csv")
Write-JsonFile -Path (Join-Path $DirPersistence "wmi_subscriptions.json") -Object (Get-WmiSubscriptionsFlat)

# Network
Export-CsvSafe -InputObject (Get-TcpListeners) -Path (Join-Path $DirNetwork "tcp_listeners.csv")
Export-CsvSafe -InputObject (Get-TcpConnections) -Path (Join-Path $DirNetwork "tcp_connections.csv")
Export-CsvSafe -InputObject (Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, OwningProcess, CreationTime) -Path (Join-Path $DirNetwork "udp_endpoints.csv")
Export-CsvSafe -InputObject (Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowInboundRules, AllowLocalFirewallRules) -Path (Join-Path $DirNetwork "firewall_profiles.csv")

# Security
Write-JsonFile -Path (Join-Path $DirSecurity "defender_status.json") -Object (Get-DefenderStatusSafe)
Write-JsonFile -Path (Join-Path $DirSecurity "defender_threats.json") -Object (Get-DefenderThreatsSafe)
Write-JsonFile -Path (Join-Path $DirSecurity "defender_preferences.json") -Object (Get-DefenderPreferencesSafe)

# Logs
$logs = @(
    "Application",
    "System",
    "Security",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-TaskScheduler/Operational"
)
foreach ($log in $logs) {
    $safeName = ($log -replace "[\\/:\*?""<>| ]", "_")
    Export-LogIfExists -LogName $log -Destination (Join-Path $DirLogs ($safeName + ".evtx"))
}

# Richer user / forensic artefacts
Copy-GlobSafe -SourceGlob "$env:SystemRoot\Prefetch\*.pf" -DestinationDir $DirPrefetch -Limit 300
Copy-IfExists -Source "$env:SystemRoot\AppCompat\Programs\Amcache.hve" -Destination (Join-Path $DirAmcache "Amcache.hve")
try {
    & esentutl.exe /y "$env:SystemRoot\System32\sru\SRUDB.dat" /d (Join-Path $DirSrum "SRUDB.dat") | Out-Null
} catch {
    $_ | Out-String | Out-File -LiteralPath (Join-Path $DirSrum "SRUDB.dat.error.txt") -Encoding utf8
}

try {
    reg export "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR" (Join-Path $DirUsb "USBSTOR.reg") /y | Out-Null
} catch {
    $_ | Out-String | Out-File -LiteralPath (Join-Path $DirUsb "USBSTOR.reg.error.txt") -Encoding utf8
}

try {
    reg export "HKLM\SYSTEM\CurrentControlSet\Enum\USB" (Join-Path $DirUsb "USB.reg") /y | Out-Null
} catch {
    $_ | Out-String | Out-File -LiteralPath (Join-Path $DirUsb "USB.reg.error.txt") -Encoding utf8
}

try {
    $usbStorObjects = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR" -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{
            DeviceKey = $_.PSChildName
            Path = $_.Name
        }
    }
    Write-JsonFile -Path (Join-Path $DirUsb "usbstor.json") -Object $usbStorObjects
} catch {
    $_ | Out-String | Out-File -LiteralPath (Join-Path $DirUsb "usbstor.json.error.txt") -Encoding utf8
}

foreach ($ProfileDir in Get-UserProfileDirectories) {
    $UserRoot = $ProfileDir.FullName
    $UserName = $ProfileDir.Name

    Copy-GlobSafe -SourceGlob (Join-Path $UserRoot "Desktop\*.lnk") -DestinationDir (Join-Path $DirLnk $UserName) -Limit 200
    Copy-GlobSafe -SourceGlob (Join-Path $UserRoot "AppData\Roaming\Microsoft\Windows\Recent\*") -DestinationDir (Join-Path $DirRecent $UserName) -Limit 300
    Copy-GlobSafe -SourceGlob (Join-Path $UserRoot "AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*") -DestinationDir (Join-Path $DirJumpLists "$UserName\AutomaticDestinations") -Limit 300
    Copy-GlobSafe -SourceGlob (Join-Path $UserRoot "AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\*") -DestinationDir (Join-Path $DirJumpLists "$UserName\CustomDestinations") -Limit 300

    if ($IncludeBrowserArtefacts) {
        Copy-IfExists -Source (Join-Path $UserRoot "AppData\Local\Google\Chrome\User Data\Default\History") -Destination (Join-Path $DirBrowser "$UserName\Chrome\History")
        Copy-IfExists -Source (Join-Path $UserRoot "AppData\Local\Google\Chrome\User Data\Default\Cookies") -Destination (Join-Path $DirBrowser "$UserName\Chrome\Cookies")
        Copy-IfExists -Source (Join-Path $UserRoot "AppData\Local\Microsoft\Edge\User Data\Default\History") -Destination (Join-Path $DirBrowser "$UserName\Edge\History")
        Copy-IfExists -Source (Join-Path $UserRoot "AppData\Local\Microsoft\Edge\User Data\Default\Cookies") -Destination (Join-Path $DirBrowser "$UserName\Edge\Cookies")
        Copy-IfExists -Source (Join-Path $UserRoot "AppData\Roaming\Mozilla\Firefox\Profiles") -Destination (Join-Path $DirBrowser "$UserName\Firefox\Profiles")
    }
}

# Timeline-oriented file listing
try {
    Get-ChildItem -Path "C:\Users" -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { -not $_.PSIsContainer } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 2000 FullName, Length, CreationTime, LastAccessTime, LastWriteTime |
        Export-Csv -LiteralPath (Join-Path $DirTimeline "recent_files.csv") -NoTypeInformation -Encoding utf8
} catch {
    $_ | Out-String | Out-File -LiteralPath (Join-Path $DirTimeline "recent_files.error.txt") -Encoding utf8
}

# Optional placeholders for advanced mode
if ($IncludeMemory) {
    Write-JsonFile -Path (Join-Path $DirMemory "memory_collection_requested.json") -Object ([ordered]@{
        requested = $true
        status = "placeholder"
        tool = "not_configured"
    })
}

if ($IncludeYara) {
    Write-JsonFile -Path (Join-Path $DirFindings "yara_requested.json") -Object ([ordered]@{
        requested = $true
        status = "placeholder"
        rules = "not_configured"
    })
}

# Summary
$summary = [ordered]@{
    CaseId = $CaseId
    Profile = $Profile
    Hostname = $env:COMPUTERNAME
    CollectedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
    Processes = ((Import-Csv -LiteralPath (Join-Path $DirExecution "processes.csv") -ErrorAction SilentlyContinue) | Measure-Object).Count
    Services = ((Import-Csv -LiteralPath (Join-Path $DirExecution "services.csv") -ErrorAction SilentlyContinue) | Measure-Object).Count
    ScheduledTasks = ((Import-Csv -LiteralPath (Join-Path $DirPersistence "scheduled_tasks.csv") -ErrorAction SilentlyContinue) | Measure-Object).Count
    TcpListeners = ((Import-Csv -LiteralPath (Join-Path $DirNetwork "tcp_listeners.csv") -ErrorAction SilentlyContinue) | Measure-Object).Count
    DefenderDetections = @((Get-DefenderThreatsSafe)).Count
    LogsAttempted = $logs.Count
    PrefetchFiles = (Get-ChildItem -LiteralPath $DirPrefetch -File -ErrorAction SilentlyContinue | Measure-Object).Count
    LnkFiles = (Get-ChildItem -Path (Join-Path $DirLnk "*") -File -Recurse -ErrorAction SilentlyContinue | Measure-Object).Count
    JumpListFiles = (Get-ChildItem -Path (Join-Path $DirJumpLists "*") -File -Recurse -ErrorAction SilentlyContinue | Measure-Object).Count
    BrowserArtefacts = (Get-ChildItem -Path (Join-Path $DirBrowser "*") -File -Recurse -ErrorAction SilentlyContinue | Measure-Object).Count
    UsbExports = (Get-ChildItem -LiteralPath $DirUsb -File -ErrorAction SilentlyContinue | Measure-Object).Count
}
Write-JsonFile -Path (Join-Path $DirCase "summary.json") -Object $summary

# File hashes
$hashLines = New-Object System.Collections.Generic.List[string]
Get-ChildItem -LiteralPath $CaseDir -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.Name -ne "hashes.sha256") {
        try {
            $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName
            $relative = $hash.Path.Substring($CaseDir.Length).TrimStart('\')
            $hashLines.Add("{0} *{1}" -f $hash.Hash.ToLower(), $relative)
        } catch {
            # best effort
        }
    }
}
$hashLines | Out-File -LiteralPath (Join-Path $DirCase "hashes.sha256") -Encoding ascii

if ($ZipSharePackage) {
    $shareZipPath = Join-Path $CaseDir ($CaseId + "-share-package.zip")
    if (Test-Path -LiteralPath $shareZipPath) {
        Remove-Item -LiteralPath $shareZipPath -Force
    }
    Compress-Archive -Path (Join-Path $DirShare "*") -DestinationPath $shareZipPath -CompressionLevel Optimal -Force
}

if (-not $NoZip) {
    $zipPath = Join-Path $OutputRoot ($CaseId + ".zip")
    if (Test-Path -LiteralPath $zipPath) {
        Remove-Item -LiteralPath $zipPath -Force
    }
    Compress-Archive -Path (Join-Path $CaseDir "*") -DestinationPath $zipPath -CompressionLevel Optimal -Force
    Write-Host "[+] Evidence ZIP created: $zipPath"
}

Write-Host "[+] Case collected in: $CaseDir"
