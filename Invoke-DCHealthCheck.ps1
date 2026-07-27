<#
.SYNOPSIS
    Domain Controller health check with HTML dashboard and optional JSON output.

.DESCRIPTION
    Designed to run repeatably as a scheduled task on a DC (or a management host
    with RSAT). Collects service state, replication health, dcdiag results,
    SYSVOL/share status, disk capacity, time sync, secure channel, port
    reachability, and recent Directory Service errors for every DC in the domain
    (or a supplied list). Renders a self-contained HTML dashboard and, when
    -ExportJson is specified, a timestamped JSON file suitable for ingestion by
    monitoring/reporting pipelines.

.PARAMETER OutputPath
    Folder for reports. Created if missing. Default: C:\Reports\DCHealth

.PARAMETER DomainController
    One or more DC names to check. Default: all DCs discovered in the domain.

.PARAMETER ExportJson
    Also write a serialized JSON copy of all results.

.PARAMETER KeepReports
    Number of historical HTML/JSON reports to retain (per type). Default: 30. 0 = keep all.

.PARAMETER DiskWarnPercent / DiskCritPercent
    Free-space thresholds. Defaults: warn <20%, critical <10%.

.PARAMETER EventLookbackHours
    How far back to scan Directory Service / DNS / Replication event logs. Default: 24.

.PARAMETER MaxReplFailures
    Replication consecutive-failure count that marks a partner Critical. Default: 1.

.PARAMETER TimeDriftWarnSeconds / TimeDriftCritSeconds
    Absolute drift (vs the PDC emulator) that raises Warning / Critical.
    Defaults: warn >1s, critical >5s. Kerberos hard-fails at 300s, but drift
    beyond a few seconds indicates a broken time hierarchy worth fixing early.

.EXAMPLE
    .\Invoke-DCHealthCheck.ps1 -ExportJson

.EXAMPLE (register as a scheduled task, daily 06:00, run as a gMSA or service account with read rights)
    $action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
               -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Invoke-DCHealthCheck.ps1" -ExportJson'
    $trigger = New-ScheduledTaskTrigger -Daily -At 06:00
    Register-ScheduledTask -TaskName 'DC Health Check' -Action $action -Trigger $trigger `
               -User 'DOMAIN\svc-dchealth$' -RunLevel Highest

.NOTES
    Exit codes: 0 = all healthy, 1 = warnings, 2 = critical findings, 3 = script failure.
    Requires: ActiveDirectory module (RSAT-AD-PowerShell), rights to query DCs remotely.
#>

[CmdletBinding()]
param(
    [string]   $OutputPath        = 'C:\Reports\DCHealth',
    [string[]] $DomainController,
    [switch]   $ExportJson,
    [int]      $KeepReports       = 30,
    [int]      $DiskWarnPercent   = 20,
    [int]      $DiskCritPercent   = 10,
    [int]      $EventLookbackHours = 24,
    [int]      $MaxReplFailures   = 1,
    [double]   $TimeDriftWarnSeconds = 1,
    [double]   $TimeDriftCritSeconds = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:RunStart = Get-Date
$timestamp = $script:RunStart.ToString('yyyyMMdd_HHmmss')

#region Helpers ---------------------------------------------------------------

# Status precedence used everywhere: Healthy < Warning < Critical < Unknown(treated as Warning for rollup)
function Get-WorstStatus {
    param([string[]]$Statuses)
    if ($Statuses -contains 'Critical') { return 'Critical' }
    if ($Statuses -contains 'Warning' -or $Statuses -contains 'Unknown') { return 'Warning' }
    return 'Healthy'
}

function New-CheckResult {
    param(
        [string]$Check,
        [ValidateSet('Healthy','Warning','Critical','Unknown')][string]$Status,
        [string]$Detail,
        [object]$Data = $null
    )
    [pscustomobject]@{
        Check  = $Check
        Status = $Status
        Detail = $Detail
        Data   = $Data
    }
}

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Verbose $line
    Add-Content -Path $script:LogFile -Value $line -ErrorAction SilentlyContinue
}
#endregion

#region Setup -----------------------------------------------------------------
try {
    if (-not (Test-Path $OutputPath)) { New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null }
    $script:LogFile = Join-Path $OutputPath "DCHealth_$timestamp.log"

    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Log 'ActiveDirectory module loaded.'

    $domain = Get-ADDomain
    $forest = Get-ADForest

    if (-not $DomainController) {
        $DomainController = (Get-ADDomainController -Filter *).HostName | Sort-Object
    }
    Write-Log ("Targets: {0}" -f ($DomainController -join ', '))
}
catch {
    Write-Error "Initialization failed: $($_.Exception.Message)"
    exit 3
}
#endregion

#region Per-DC checks ---------------------------------------------------------

function Test-DCServices {
    param([string]$DC)
    $required = 'NTDS','DNS','KDC','Netlogon','W32Time','DFSR'
    try {
        $svcs = Get-Service -ComputerName $DC -Name $required -ErrorAction SilentlyContinue
        $rows = foreach ($name in $required) {
            $s = $svcs | Where-Object Name -eq $name
            [pscustomobject]@{
                Service = $name
                Status  = if ($null -eq $s) { 'NotFound' } else { $s.Status.ToString() }
            }
        }
        $down = @($rows | Where-Object { $_.Status -ne 'Running' })
        # DNS may legitimately be absent on a DC that isn't a DNS server
        $downReal = @($down | Where-Object { -not ($_.Service -eq 'DNS' -and $_.Status -eq 'NotFound') })
        if ($downReal.Count -eq 0) {
            New-CheckResult -Check 'Services' -Status Healthy -Detail 'All core services running' -Data $rows
        } else {
            $names = ($downReal.Service -join ', ')
            New-CheckResult -Check 'Services' -Status Critical -Detail "Not running: $names" -Data $rows
        }
    }
    catch {
        New-CheckResult -Check 'Services' -Status Unknown -Detail $_.Exception.Message
    }
}

function Test-DCConnectivity {
    param([string]$DC)
    $ports = @(
        @{Port = 53;   Name = 'DNS' },
        @{Port = 88;   Name = 'Kerberos' },
        @{Port = 135;  Name = 'RPC' },
        @{Port = 389;  Name = 'LDAP' },
        @{Port = 445;  Name = 'SMB' },
        @{Port = 636;  Name = 'LDAPS' },
        @{Port = 3268; Name = 'GC' }
    )
    $rows = foreach ($p in $ports) {
        $r = Test-NetConnection -ComputerName $DC -Port $p.Port -WarningAction SilentlyContinue
        [pscustomobject]@{ Port = $p.Port; Name = $p.Name; Open = [bool]$r.TcpTestSucceeded }
    }
    $closed = @($rows | Where-Object { -not $_.Open })
    if ($closed.Count -eq 0) {
        New-CheckResult -Check 'Ports' -Status Healthy -Detail 'All expected ports reachable' -Data $rows
    }
    elseif ($closed.Port -contains 389 -or $closed.Port -contains 88) {
        New-CheckResult -Check 'Ports' -Status Critical -Detail ("Closed: " + (($closed | ForEach-Object { "$($_.Name)/$($_.Port)" }) -join ', ')) -Data $rows
    }
    else {
        New-CheckResult -Check 'Ports' -Status Warning -Detail ("Closed: " + (($closed | ForEach-Object { "$($_.Name)/$($_.Port)" }) -join ', ')) -Data $rows
    }
}

function Test-DCReplication {
    param([string]$DC)
    try {
        $partners = Get-ADReplicationPartnerMetadata -Target $DC -PartnerType Both -ErrorAction Stop
        $rows = foreach ($p in $partners) {
            [pscustomobject]@{
                Partner              = ($p.Partner -replace '^CN=NTDS Settings,CN=([^,]+),.*$', '$1')
                Partition            = $p.Partition
                LastSuccess          = $p.LastReplicationSuccess
                LastAttempt          = $p.LastReplicationAttempt
                ConsecutiveFailures  = $p.ConsecutiveReplicationFailures
                LastResult           = $p.LastReplicationResult
            }
        }
        $failed  = @($rows | Where-Object { $_.ConsecutiveFailures -ge $MaxReplFailures })
        $stale   = @($rows | Where-Object { $_.LastSuccess -lt (Get-Date).AddHours(-24) })
        if ($failed.Count -gt 0) {
            New-CheckResult -Check 'Replication' -Status Critical `
                -Detail ("{0} partner link(s) failing (e.g. {1})" -f $failed.Count, $failed[0].Partner) -Data $rows
        }
        elseif ($stale.Count -gt 0) {
            New-CheckResult -Check 'Replication' -Status Warning `
                -Detail ("{0} link(s) with no success in 24h" -f $stale.Count) -Data $rows
        }
        else {
            New-CheckResult -Check 'Replication' -Status Healthy -Detail ("{0} partner links healthy" -f $rows.Count) -Data $rows
        }
    }
    catch {
        New-CheckResult -Check 'Replication' -Status Unknown -Detail $_.Exception.Message
    }
}

function Test-DCDiag {
    param([string]$DC)
    # Focused, fast subset of dcdiag tests; extend as needed.
    $tests = 'Connectivity','Advertising','SysVolCheck','NetLogons','Services','Replications','FsmoCheck','MachineAccount','KccEvent'
    $rows = foreach ($t in $tests) {
        try {
            $out = & dcdiag.exe /s:$DC /test:$t 2>&1 | Out-String
            $passed = $out -match "passed test\s+$t"
            [pscustomobject]@{ Test = $t; Passed = [bool]$passed }
        }
        catch {
            [pscustomobject]@{ Test = $t; Passed = $false }
        }
    }
    $failedTests = @($rows | Where-Object { -not $_.Passed })
    if ($failedTests.Count -eq 0) {
        New-CheckResult -Check 'DCDiag' -Status Healthy -Detail "All $($rows.Count) tests passed" -Data $rows
    } else {
        New-CheckResult -Check 'DCDiag' -Status Critical -Detail ("Failed: " + ($failedTests.Test -join ', ')) -Data $rows
    }
}

function Test-DCSysvol {
    param([string]$DC)
    try {
        $sysvol   = Test-Path "\\$DC\SYSVOL"
        $netlogon = Test-Path "\\$DC\NETLOGON"
        $rows = [pscustomobject]@{ SYSVOL = $sysvol; NETLOGON = $netlogon }
        if ($sysvol -and $netlogon) {
            New-CheckResult -Check 'SYSVOL' -Status Healthy -Detail 'SYSVOL and NETLOGON shares reachable' -Data $rows
        } else {
            New-CheckResult -Check 'SYSVOL' -Status Critical -Detail "SYSVOL:$sysvol NETLOGON:$netlogon" -Data $rows
        }
    }
    catch {
        New-CheckResult -Check 'SYSVOL' -Status Unknown -Detail $_.Exception.Message
    }
}

function Test-DCDisk {
    param([string]$DC)
    try {
        $disks = Get-CimInstance -ComputerName $DC -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop
        $rows = foreach ($d in $disks) {
            $pct = if ($d.Size) { [math]::Round(($d.FreeSpace / $d.Size) * 100, 1) } else { 0 }
            [pscustomobject]@{
                Drive       = $d.DeviceID
                SizeGB      = [math]::Round($d.Size / 1GB, 1)
                FreeGB      = [math]::Round($d.FreeSpace / 1GB, 1)
                FreePercent = $pct
            }
        }
        $crit = @($rows | Where-Object { $_.FreePercent -lt $DiskCritPercent })
        $warn = @($rows | Where-Object { $_.FreePercent -lt $DiskWarnPercent -and $_.FreePercent -ge $DiskCritPercent })
        if ($crit.Count -gt 0) {
            New-CheckResult -Check 'Disk' -Status Critical -Detail ("Low space: " + (($crit | ForEach-Object { "$($_.Drive) $($_.FreePercent)%" }) -join ', ')) -Data $rows
        }
        elseif ($warn.Count -gt 0) {
            New-CheckResult -Check 'Disk' -Status Warning -Detail (($warn | ForEach-Object { "$($_.Drive) $($_.FreePercent)%" }) -join ', ') -Data $rows
        }
        else {
            New-CheckResult -Check 'Disk' -Status Healthy -Detail 'All volumes above threshold' -Data $rows
        }
    }
    catch {
        New-CheckResult -Check 'Disk' -Status Unknown -Detail $_.Exception.Message
    }
}

function Get-W32tmOffset {
    # Returns the target's clock offset (seconds) relative to THIS host's clock,
    # averaged over $Samples readings. $null if unparseable/unreachable.
    param([string]$Target, [int]$Samples = 3)
    try {
        $out = & w32tm.exe /stripchart /computer:$Target /samples:$Samples /dataonly 2>&1 | Out-String
        $offsets = [regex]::Matches($out, ',\s*([+-]?\d+\.\d+)s') |
                   ForEach-Object { [double]$_.Groups[1].Value }
        if ($offsets.Count -gt 0) {
            return ($offsets | Measure-Object -Average).Average
        }
        return $null
    }
    catch { return $null }
}

function Test-DCTimeSync {
    <#
        Validates time drift against the PDC emulator (the domain's authoritative
        time source). Both the DC and the PDC are sampled from this host with
        w32tm /stripchart; subtracting the two offsets cancels out this host's
        own clock error, leaving the true DC-vs-PDC drift.
        Also inspects the DC's configured time source and flags unsynchronized
        sources (Local CMOS Clock / Free-running System Clock).
    #>
    param([string]$DC, [string]$PdcEmulator)

    try {
        # Configured time source on the DC
        $sourceOut  = & w32tm.exe /query /source /computer:$DC 2>&1 | Out-String
        $timeSource = $sourceOut.Trim()
        $badSource  = $timeSource -match 'Local CMOS Clock|Free-running System Clock'

        $isPdc = ($DC -ieq $PdcEmulator) -or ($DC.Split('.')[0] -ieq $PdcEmulator.Split('.')[0])

        if ($isPdc) {
            # The PDC has no in-domain reference; validate it has an external NTP source.
            $data = [pscustomobject]@{
                Role          = 'PDCEmulator'
                TimeSource    = $timeSource
                DriftSeconds  = 0
                ReferenceDC   = $null
            }
            if ($badSource) {
                New-CheckResult -Check 'TimeSync' -Status Critical `
                    -Detail "PDC emulator time source is '$timeSource' - configure an external NTP source" -Data $data
            } else {
                New-CheckResult -Check 'TimeSync' -Status Healthy `
                    -Detail "PDC emulator (domain time root), source: $timeSource" -Data $data
            }
            return
        }

        # Measure DC and PDC against this host, then diff to get true drift.
        $dcOffset  = Get-W32tmOffset -Target $DC
        $pdcOffset = Get-W32tmOffset -Target $PdcEmulator

        if ($null -eq $dcOffset -or $null -eq $pdcOffset) {
            New-CheckResult -Check 'TimeSync' -Status Unknown `
                -Detail 'Could not sample w32tm offsets for DC and/or PDC emulator'
            return
        }

        $drift = [math]::Round([math]::Abs($dcOffset - $pdcOffset), 3)
        $data = [pscustomobject]@{
            Role          = 'MemberDC'
            TimeSource    = $timeSource
            DriftSeconds  = $drift
            ReferenceDC   = $PdcEmulator
        }

        if ($drift -gt $TimeDriftCritSeconds -or $badSource) {
            $reason = if ($badSource) { "unsynchronized source '$timeSource'" } else { "drift ${drift}s vs PDC" }
            New-CheckResult -Check 'TimeSync' -Status Critical -Detail "Time drift check failed: $reason" -Data $data
        }
        elseif ($drift -gt $TimeDriftWarnSeconds) {
            New-CheckResult -Check 'TimeSync' -Status Warning -Detail "Drift ${drift}s vs PDC (source: $timeSource)" -Data $data
        }
        else {
            New-CheckResult -Check 'TimeSync' -Status Healthy -Detail "Drift ${drift}s vs PDC (source: $timeSource)" -Data $data
        }
    }
    catch {
        New-CheckResult -Check 'TimeSync' -Status Unknown -Detail $_.Exception.Message
    }
}

function Test-DCEvents {
    param([string]$DC)
    try {
        $since = (Get-Date).AddHours(-$EventLookbackHours)
        $logs = 'Directory Service','DFS Replication','DNS Server'
        $rows = foreach ($log in $logs) {
            try {
                $events = Get-WinEvent -ComputerName $DC -FilterHashtable @{
                    LogName = $log; Level = 1,2; StartTime = $since
                } -MaxEvents 50 -ErrorAction SilentlyContinue
                foreach ($e in ($events | Group-Object Id | Sort-Object Count -Descending)) {
                    [pscustomobject]@{
                        Log     = $log
                        EventId = $e.Name
                        Count   = $e.Count
                        Sample  = ($e.Group[0].Message -split "`n")[0].Trim()
                    }
                }
            } catch { }
        }
        $rows = @($rows)
        if ($rows.Count -eq 0) {
            New-CheckResult -Check 'EventLogs' -Status Healthy -Detail "No errors in last ${EventLookbackHours}h" -Data @()
        } else {
            $total = ($rows | Measure-Object Count -Sum).Sum
            New-CheckResult -Check 'EventLogs' -Status Warning -Detail "$total error/critical event(s) across $($rows.Count) distinct ID(s)" -Data $rows
        }
    }
    catch {
        New-CheckResult -Check 'EventLogs' -Status Unknown -Detail $_.Exception.Message
    }
}

function Test-DCSecureChannel {
    param([string]$DC)
    try {
        $ok = Invoke-Command -ComputerName $DC -ScriptBlock { Test-ComputerSecureChannel } -ErrorAction Stop
        if ($ok) { New-CheckResult -Check 'SecureChannel' -Status Healthy  -Detail 'Secure channel intact' }
        else     { New-CheckResult -Check 'SecureChannel' -Status Critical -Detail 'Secure channel broken' }
    }
    catch {
        New-CheckResult -Check 'SecureChannel' -Status Unknown -Detail $_.Exception.Message
    }
}
#endregion

#region Collection ------------------------------------------------------------

$dcResults = foreach ($dc in $DomainController) {
    Write-Log "Checking $dc ..."
    $reachable = Test-Connection -ComputerName $dc -Count 1 -Quiet -ErrorAction SilentlyContinue

    if (-not $reachable) {
        Write-Log "$dc unreachable via ICMP; running limited checks." 'WARN'
    }

    $checks = @(
        Test-DCConnectivity  -DC $dc
        Test-DCServices      -DC $dc
        Test-DCReplication   -DC $dc
        Test-DCDiag          -DC $dc
        Test-DCSysvol        -DC $dc
        Test-DCDisk          -DC $dc
        Test-DCTimeSync      -DC $dc -PdcEmulator $domain.PDCEmulator
        Test-DCEvents        -DC $dc
        Test-DCSecureChannel -DC $dc
    )

    $overall = Get-WorstStatus -Statuses $checks.Status
    Write-Log "$dc => $overall"

    [pscustomobject]@{
        DomainController = $dc
        Reachable        = [bool]$reachable
        OverallStatus    = $overall
        Checks           = $checks
    }
}
$dcResults = @($dcResults)

# Forest/domain level context
$fsmo = [pscustomobject]@{
    SchemaMaster         = $forest.SchemaMaster
    DomainNamingMaster   = $forest.DomainNamingMaster
    PDCEmulator          = $domain.PDCEmulator
    RIDMaster            = $domain.RIDMaster
    InfrastructureMaster = $domain.InfrastructureMaster
}

$summary = [pscustomobject]@{
    ReportGenerated = $script:RunStart
    Domain          = $domain.DNSRoot
    Forest          = $forest.Name
    ForestMode      = $forest.ForestMode.ToString()
    DomainMode      = $domain.DomainMode.ToString()
    FSMO            = $fsmo
    DCCount         = $dcResults.Count
    Healthy         = @($dcResults | Where-Object OverallStatus -eq 'Healthy').Count
    Warning         = @($dcResults | Where-Object OverallStatus -eq 'Warning').Count
    Critical        = @($dcResults | Where-Object OverallStatus -eq 'Critical').Count
    OverallStatus   = Get-WorstStatus -Statuses $dcResults.OverallStatus
    DurationSeconds = [math]::Round(((Get-Date) - $script:RunStart).TotalSeconds, 1)
    DomainControllers = $dcResults
}
#endregion

#region JSON export -----------------------------------------------------------
if ($ExportJson) {
    $jsonPath = Join-Path $OutputPath "DCHealth_$timestamp.json"
    $summary | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding UTF8
    Write-Log "JSON written: $jsonPath"
}
#endregion

#region HTML dashboard --------------------------------------------------------

$statusColor = @{ Healthy = '#16a34a'; Warning = '#d97706'; Critical = '#dc2626'; Unknown = '#6b7280' }
$statusBg    = @{ Healthy = '#f0fdf4'; Warning = '#fffbeb'; Critical = '#fef2f2'; Unknown = '#f3f4f6' }

function ConvertTo-HtmlEncoded { param([string]$s) [System.Net.WebUtility]::HtmlEncode([string]$s) }

$dcCards = foreach ($dc in $dcResults) {
    $badge = $dc.OverallStatus
    $checkRows = foreach ($c in $dc.Checks) {
        $dot = $statusColor[$c.Status]
        '<tr><td><span class="dot" style="background:{0}"></span>{1}</td><td class="st" style="color:{0}">{2}</td><td>{3}</td></tr>' -f `
            $dot, (ConvertTo-HtmlEncoded $c.Check), $c.Status, (ConvertTo-HtmlEncoded $c.Detail)
    }
    @"
<div class="card" style="border-top:4px solid $($statusColor[$badge])">
  <div class="card-head">
    <h2>$(ConvertTo-HtmlEncoded $dc.DomainController)</h2>
    <span class="badge" style="background:$($statusBg[$badge]);color:$($statusColor[$badge])">$badge</span>
  </div>
  <table>
    <thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead>
    <tbody>
      $($checkRows -join "`n")
    </tbody>
  </table>
</div>
"@
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>DC Health &mdash; $(ConvertTo-HtmlEncoded $summary.Domain) &mdash; $($summary.ReportGenerated.ToString('yyyy-MM-dd HH:mm'))</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; background: #f1f5f9; color: #0f172a; }
  header { background: #0f172a; color: #f8fafc; padding: 24px 32px; }
  header h1 { margin: 0 0 4px; font-size: 22px; font-weight: 600; }
  header .sub { color: #94a3b8; font-size: 13px; }
  .wrap { max-width: 1200px; margin: 0 auto; padding: 24px 32px; }
  .tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .tile { background: #fff; border-radius: 10px; padding: 16px 20px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  .tile .num { font-size: 30px; font-weight: 700; line-height: 1; }
  .tile .lbl { font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: .05em; margin-top: 6px; }
  .card { background: #fff; border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,.08); margin-bottom: 20px; overflow: hidden; }
  .card-head { display: flex; justify-content: space-between; align-items: center; padding: 14px 20px 6px; }
  .card h2 { margin: 0; font-size: 16px; }
  .badge { font-size: 12px; font-weight: 600; padding: 4px 12px; border-radius: 999px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 8px 20px; color: #64748b; font-weight: 600; border-bottom: 1px solid #e2e8f0; }
  td { padding: 8px 20px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
  td.st { font-weight: 600; white-space: nowrap; }
  .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 8px; }
  .fsmo { font-size: 12px; color: #475569; background: #fff; border-radius: 10px; padding: 12px 20px;
          box-shadow: 0 1px 3px rgba(0,0,0,.08); margin-bottom: 24px; line-height: 1.8; }
  footer { text-align: center; color: #94a3b8; font-size: 12px; padding: 16px; }
</style>
</head>
<body>
<header>
  <h1>Domain Controller Health &mdash; $(ConvertTo-HtmlEncoded $summary.Domain)</h1>
  <div class="sub">Generated $($summary.ReportGenerated.ToString('dddd, dd MMMM yyyy HH:mm:ss')) &middot; run time $($summary.DurationSeconds)s &middot; forest $(ConvertTo-HtmlEncoded $summary.Forest) ($($summary.ForestMode))</div>
</header>
<div class="wrap">
  <div class="tiles">
    <div class="tile"><div class="num">$($summary.DCCount)</div><div class="lbl">Domain Controllers</div></div>
    <div class="tile"><div class="num" style="color:$($statusColor.Healthy)">$($summary.Healthy)</div><div class="lbl">Healthy</div></div>
    <div class="tile"><div class="num" style="color:$($statusColor.Warning)">$($summary.Warning)</div><div class="lbl">Warning</div></div>
    <div class="tile"><div class="num" style="color:$($statusColor.Critical)">$($summary.Critical)</div><div class="lbl">Critical</div></div>
  </div>
  <div class="fsmo">
    <strong>FSMO:</strong>
    PDC $(ConvertTo-HtmlEncoded $fsmo.PDCEmulator) &middot;
    RID $(ConvertTo-HtmlEncoded $fsmo.RIDMaster) &middot;
    Infra $(ConvertTo-HtmlEncoded $fsmo.InfrastructureMaster) &middot;
    Schema $(ConvertTo-HtmlEncoded $fsmo.SchemaMaster) &middot;
    Naming $(ConvertTo-HtmlEncoded $fsmo.DomainNamingMaster)
  </div>
  $($dcCards -join "`n")
</div>
<footer>Invoke-DCHealthCheck.ps1 &middot; report retained per -KeepReports policy</footer>
</body>
</html>
"@

$htmlPath = Join-Path $OutputPath "DCHealth_$timestamp.html"
$html | Set-Content -Path $htmlPath -Encoding UTF8
Write-Log "HTML written: $htmlPath"

# Also maintain a stable 'latest' copy so bookmarks / monitoring links never change
Copy-Item -Path $htmlPath -Destination (Join-Path $OutputPath 'DCHealth_latest.html') -Force
if ($ExportJson) {
    Copy-Item -Path (Join-Path $OutputPath "DCHealth_$timestamp.json") `
              -Destination (Join-Path $OutputPath 'DCHealth_latest.json') -Force
}
#endregion

#region Retention -------------------------------------------------------------
if ($KeepReports -gt 0) {
    foreach ($pattern in 'DCHealth_????????_??????.html','DCHealth_????????_??????.json','DCHealth_????????_??????.log') {
        Get-ChildItem -Path $OutputPath -Filter $pattern -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -Skip $KeepReports |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
}
#endregion

#region Exit code for monitoring ----------------------------------------------
switch ($summary.OverallStatus) {
    'Healthy'  { Write-Log 'Result: Healthy';  exit 0 }
    'Warning'  { Write-Log 'Result: Warning';  exit 1 }
    'Critical' { Write-Log 'Result: Critical'; exit 2 }
    default    { exit 1 }
}
#endregion
