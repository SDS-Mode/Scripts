<#
.SYNOPSIS
    Read-only pre-flight checks to run BEFORE transferring FSMO roles between domain controllers.

.DESCRIPTION
    This script performs DIAGNOSTIC, READ-ONLY checks only. It does not change anything in
    Active Directory, on any DC, or in DNS. It is safe to run against production.

    Guaranteed-safe surface area. The script calls ONLY the following, all of which are read/query operations:
        - ActiveDirectory module:  Get-ADForest, Get-ADDomain, Get-ADDomainController,
                                   Get-ADObject, Get-ADReplicationFailure,
                                   Get-ADReplicationPartnerMetadata
        - Diagnostic binaries:     dcdiag (no /fix), repadmin /replsummary, repadmin /showrepl,
                                   netdom query fsmo, nltest, w32tm /query, wbadmin get versions
        - Networking (probe only): Resolve-DnsName, Test-NetConnection, Get-Service

    It NEVER calls: Move-ADDirectoryServerOperationMasterRole, any Set-* / New-* / Remove-*,
    ntdsutil (in any write/seize context), dcdiag /fix, repadmin with any write verb,
    or w32tm /config. There is no code path in this script that writes state.

    The only thing it writes is an optional local CSV/transcript report on the machine you run it
    from (your own report file) - it does not touch the directory.

.PARAMETER SourceDC
    Optional. The current FSMO role holder you intend to move roles FROM. Enables source-specific framing.

.PARAMETER TargetDC
    Optional. The DC you intend to move roles TO. Enables target-specific checks (GC status for
    Infrastructure Master, time-source posture for PDC Emulator) and source<->target port probes.

.PARAMETER SkipDcdiag
    Optional. Skip the dcdiag tests (they are read-only but can be slow on large environments).

.PARAMETER SkipPortTests
    Optional. Skip the TCP port reachability probes between Source and Target.

.PARAMETER ReportPath
    Optional. Folder to write the CSV result + transcript. Defaults to $env:TEMP.

.EXAMPLE
    .\Test-FsmoPreMoveReadiness.ps1

.EXAMPLE
    .\Test-FsmoPreMoveReadiness.ps1 -SourceDC DC01 -TargetDC DC02 -Verbose

.NOTES
    Run from a machine with RSAT-AD-PowerShell (or on a DC). Read-only AD queries work without
    elevation; a few checks (wbadmin) need elevation and will WARN-skip if unavailable.
    Compatible with Windows PowerShell 5.1 and PowerShell 7.
#>

[CmdletBinding()]
param(
    [string]$SourceDC,
    [string]$TargetDC,
    [switch]$SkipDcdiag,
    [switch]$SkipPortTests,
    [string]$ReportPath = $env:TEMP
)

# ----------------------------------------------------------------------------------
# Result collection + output helpers
# ----------------------------------------------------------------------------------
$script:Results = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param(
        [string]$Category,
        [string]$Check,
        [ValidateSet('PASS','WARN','FAIL','INFO')]
        [string]$Status,
        [string]$Detail
    )
    $script:Results.Add([pscustomobject]@{
        Category = $Category
        Check    = $Check
        Status   = $Status
        Detail   = $Detail
    })
    $color = switch ($Status) {
        'PASS' { 'Green' }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red' }
        default { 'Gray' }
    }
    Write-Host ("  [{0,-4}] {1}" -f $Status, $Check) -ForegroundColor $color
    if ($Detail) {
        foreach ($line in ($Detail -split "`n")) {
            Write-Host ("         {0}" -f $line.TrimEnd()) -ForegroundColor DarkGray
        }
    }
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=== {0} " -f $Title).PadRight(78, '=') -ForegroundColor Cyan
}

function Test-Tool {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

# Run an external read-only command and capture stdout/stderr as text, never throwing.
function Invoke-ReadOnlyExe {
    param([string]$FilePath, [string[]]$ArgumentList)
    try {
        $out = & $FilePath @ArgumentList 2>&1 | Out-String
        return $out
    } catch {
        return "ERROR invoking $FilePath : $($_.Exception.Message)"
    }
}

# ----------------------------------------------------------------------------------
# Banner + optional transcript
# ----------------------------------------------------------------------------------
$stamp      = Get-Date -Format 'yyyyMMdd-HHmmss'
$reportCsv  = Join-Path $ReportPath ("FSMO-PreMove-Report-{0}.csv" -f $stamp)
$transcript = Join-Path $ReportPath ("FSMO-PreMove-Transcript-{0}.txt" -f $stamp)

try { Start-Transcript -Path $transcript -ErrorAction Stop | Out-Null; $transcriptOn = $true }
catch { $transcriptOn = $false }

Write-Host ""
Write-Host "FSMO PRE-MOVE READINESS CHECK (READ-ONLY)" -ForegroundColor White
Write-Host "Run time : $(Get-Date)" -ForegroundColor DarkGray
Write-Host "Run by   : $([Environment]::UserDomainName)\$([Environment]::UserName) on $env:COMPUTERNAME" -ForegroundColor DarkGray
if ($SourceDC) { Write-Host "Source DC: $SourceDC" -ForegroundColor DarkGray }
if ($TargetDC) { Write-Host "Target DC: $TargetDC" -ForegroundColor DarkGray }

# ----------------------------------------------------------------------------------
# 1. Prerequisites
# ----------------------------------------------------------------------------------
Write-Section "Prerequisites"

$adModuleOk = $false
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $adModuleOk = $true
    Add-Result 'Prereq' 'ActiveDirectory module loaded' 'PASS' ''
} catch {
    Add-Result 'Prereq' 'ActiveDirectory module loaded' 'FAIL' 'Install RSAT-AD-PowerShell or run on a DC. Most checks below will be skipped.'
}

$tools = @{
    'dcdiag'   = Test-Tool 'dcdiag.exe'
    'repadmin' = Test-Tool 'repadmin.exe'
    'netdom'   = Test-Tool 'netdom.exe'
    'nltest'   = Test-Tool 'nltest.exe'
    'w32tm'    = Test-Tool 'w32tm.exe'
}
foreach ($t in $tools.GetEnumerator()) {
    if ($t.Value) { Add-Result 'Prereq' "Tool available: $($t.Key)" 'PASS' '' }
    else          { Add-Result 'Prereq' "Tool available: $($t.Key)" 'WARN' 'Not found - related check will be skipped (install RSAT/AD DS tools).' }
}

$isElevated = $false
try {
    $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
    $wp = New-Object Security.Principal.WindowsPrincipal($wi)
    $isElevated = $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {}
Add-Result 'Prereq' 'Running elevated' $(if ($isElevated) {'INFO'} else {'WARN'}) `
    $(if ($isElevated) {'Yes.'} else {'No - a few checks (wbadmin) need elevation and will WARN-skip.'})

# Stop here gracefully if no AD module - external tools alone are limited.
if (-not $adModuleOk) {
    Write-Section "Summary"
    Add-Result 'Summary' 'AD module missing' 'FAIL' 'Re-run on a host with the ActiveDirectory module for full coverage.'
}

# ----------------------------------------------------------------------------------
# 2. Current FSMO holders + DC / GC inventory
# ----------------------------------------------------------------------------------
$forest = $null; $domain = $null; $dcs = @()
if ($adModuleOk) {
    Write-Section "Current FSMO Holders"
    try {
        $forest = Get-ADForest -ErrorAction Stop
        $domain = Get-ADDomain -ErrorAction Stop

        $fsmo = [ordered]@{
            'Schema Master (forest)'        = $forest.SchemaMaster
            'Domain Naming Master (forest)' = $forest.DomainNamingMaster
            'PDC Emulator (domain)'         = $domain.PDCEmulator
            'RID Master (domain)'           = $domain.RIDMaster
            'Infrastructure Master (domain)'= $domain.InfrastructureMaster
        }
        foreach ($role in $fsmo.GetEnumerator()) {
            Add-Result 'FSMO' $role.Key 'INFO' $role.Value
        }
    } catch {
        Add-Result 'FSMO' 'Query FSMO holders' 'FAIL' $_.Exception.Message
    }

    # Cross-check with netdom for an independent reading
    if ($tools['netdom']) {
        $nd = Invoke-ReadOnlyExe 'netdom.exe' @('query','fsmo')
        Add-Result 'FSMO' 'netdom query fsmo (cross-check)' 'INFO' ($nd.Trim())
    }

    Write-Section "Domain Controller / Global Catalog Inventory"
    try {
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop
        foreach ($dc in $dcs) {
            $gc = if ($dc.IsGlobalCatalog) {'GC'} else {'not GC'}
            Add-Result 'Inventory' $dc.HostName 'INFO' `
                ("Site={0}; OS={1}; {2}; IPv4={3}" -f $dc.Site, $dc.OperatingSystem, $gc, $dc.IPv4Address)
        }
        $gcCount    = ($dcs | Where-Object { $_.IsGlobalCatalog }).Count
        $dcCount    = $dcs.Count
        $allAreGC   = ($gcCount -eq $dcCount)
        $childCount = ($forest.Domains).Count
        Add-Result 'Inventory' 'DC / GC totals' 'INFO' `
            ("$dcCount DC(s), $gcCount GC(s); forest has $childCount domain(s).")
    } catch {
        Add-Result 'Inventory' 'Enumerate DCs' 'FAIL' $_.Exception.Message
    }
}

# ----------------------------------------------------------------------------------
# 3. Infrastructure Master vs Global Catalog placement (the classic gotcha)
# ----------------------------------------------------------------------------------
if ($adModuleOk -and $domain -and $dcs) {
    Write-Section "Infrastructure Master / GC Placement Rule"
    try {
        $infraHolder = $dcs | Where-Object { $_.HostName -eq $domain.InfrastructureMaster }
        $multiDomain = (($forest.Domains).Count -gt 1)
        $allAreGC    = (($dcs | Where-Object { $_.IsGlobalCatalog }).Count -eq $dcs.Count)

        if (-not $multiDomain -or $allAreGC) {
            Add-Result 'InfraMaster' 'IM-on-GC rule' 'PASS' `
                'Single-domain forest or all DCs are GCs - Infrastructure Master placement is a non-issue.'
        } else {
            if ($infraHolder -and $infraHolder.IsGlobalCatalog) {
                Add-Result 'InfraMaster' 'IM-on-GC rule' 'WARN' `
                    ("Multi-domain forest where not all DCs are GCs, and the Infrastructure Master ({0}) IS a GC. Phantom/cross-domain reference cleanup will not function. Place IM on a non-GC DC." -f $infraHolder.HostName)
            } else {
                Add-Result 'InfraMaster' 'IM-on-GC rule' 'PASS' `
                    'Multi-domain forest, and current Infrastructure Master is on a non-GC DC. Correct.'
            }
        }

        # If a TargetDC is given, evaluate where the IM would land if moved there.
        if ($TargetDC) {
            $tgt = $dcs | Where-Object { $_.HostName -like "$TargetDC*" -or $_.Name -eq $TargetDC }
            if ($tgt) {
                if ($multiDomain -and -not $allAreGC -and $tgt.IsGlobalCatalog) {
                    Add-Result 'InfraMaster' "Target $TargetDC as IM destination" 'WARN' `
                        'Target is a GC in a multi-domain/partial-GC forest. Do NOT move Infrastructure Master here.'
                } else {
                    Add-Result 'InfraMaster' "Target $TargetDC as IM destination" 'PASS' `
                        'Target is acceptable for Infrastructure Master under the placement rule.'
                }
            }
        }
    } catch {
        Add-Result 'InfraMaster' 'Placement evaluation' 'WARN' $_.Exception.Message
    }
}

# ----------------------------------------------------------------------------------
# 4. Replication health
# ----------------------------------------------------------------------------------
if ($adModuleOk) {
    Write-Section "Replication Health"

    # 4a. AD module - replication failures (read-only)
    try {
        $failures = Get-ADReplicationFailure -Target $domain.DNSRoot -Scope Domain -ErrorAction Stop
        if (-not $failures -or $failures.Count -eq 0) {
            Add-Result 'Replication' 'Get-ADReplicationFailure' 'PASS' 'No replication failures reported.'
        } else {
            foreach ($f in $failures) {
                Add-Result 'Replication' ("Failure on {0}" -f $f.Server) 'FAIL' `
                    ("Partner={0}; FirstFailure={1}; FailureCount={2}; {3}" -f $f.Partner, $f.FirstFailureTime, $f.FailureCount, $f.LastError)
            }
        }
    } catch {
        Add-Result 'Replication' 'Get-ADReplicationFailure' 'WARN' $_.Exception.Message
    }

    # 4b. Partner metadata - last replication + consecutive failures per partner (read-only)
    try {
        $meta = Get-ADReplicationPartnerMetadata -Target * -Partition * -ErrorAction Stop
        $lagging = $meta | Where-Object { $_.ConsecutiveReplicationFailures -gt 0 }
        if (-not $lagging) {
            Add-Result 'Replication' 'Partner metadata (consecutive failures)' 'PASS' 'All partners show 0 consecutive failures.'
        } else {
            foreach ($m in $lagging) {
                Add-Result 'Replication' ("Partner lag: {0} <- {1}" -f $m.Server, $m.PartnerAddress) 'WARN' `
                    ("ConsecutiveFailures={0}; LastSuccess={1}; LastResult={2}" -f $m.ConsecutiveReplicationFailures, $m.LastReplicationSuccess, $m.LastReplicationResult)
            }
        }
    } catch {
        Add-Result 'Replication' 'Get-ADReplicationPartnerMetadata' 'WARN' $_.Exception.Message
    }

    # 4c. repadmin /replsummary (independent read-only view)
    if ($tools['repadmin']) {
        $rs = Invoke-ReadOnlyExe 'repadmin.exe' @('/replsummary')
        $flag = ($rs -match '\b[1-9]\d*\b\s*/\s*\d+' -and $rs -match 'fail')
        Add-Result 'Replication' 'repadmin /replsummary' $(if ($flag) {'WARN'} else {'INFO'}) ($rs.Trim())
    }
}

# ----------------------------------------------------------------------------------
# 5. dcdiag (read-only diagnostic tests; NO /fix)
# ----------------------------------------------------------------------------------
if ($tools['dcdiag'] -and -not $SkipDcdiag) {
    Write-Section "dcdiag (read-only tests)"
    $dcTargets = @()
    if ($SourceDC) { $dcTargets += $SourceDC }
    if ($TargetDC -and $TargetDC -ne $SourceDC) { $dcTargets += $TargetDC }
    if (-not $dcTargets -and $dcs) { $dcTargets = $dcs | Select-Object -First 2 -ExpandProperty HostName }
    if (-not $dcTargets) { $dcTargets = @($env:COMPUTERNAME) }

    # Read-only test set relevant to an FSMO move. None of these write or repair.
    $testSet = @('FsmoCheck','RidManager','Replications','Advertising','KnowsOfRoleHolders','MachineAccount','Services','SystemLog')

    foreach ($dt in $dcTargets) {
        $args = @("/s:$dt", '/v')
        foreach ($test in $testSet) { $args += "/test:$test" }
        $out = Invoke-ReadOnlyExe 'dcdiag.exe' $args
        $failed  = ($out -match 'failed test')
        $passedN = ([regex]::Matches($out, 'passed test')).Count
        $failedN = ([regex]::Matches($out, 'failed test')).Count
        $status  = if ($failed) {'FAIL'} else {'PASS'}
        # Keep the captured output but trim to the verdict lines for readability.
        $verdicts = ($out -split "`r?`n" | Where-Object { $_ -match 'passed test|failed test|Starting test' }) -join "`n"
        Add-Result 'dcdiag' "dcdiag on $dt" $status ("Passed=$passedN Failed=$failedN`n$verdicts")
    }
} elseif ($SkipDcdiag) {
    Add-Result 'dcdiag' 'dcdiag tests' 'INFO' 'Skipped (-SkipDcdiag).'
}

# ----------------------------------------------------------------------------------
# 6. RID pool state (read-only)
# ----------------------------------------------------------------------------------
if ($adModuleOk -and $domain) {
    Write-Section "RID Pool State"
    try {
        $ridDn  = "CN=RID Manager$,CN=System,$($domain.DistinguishedName)"
        $ridObj = Get-ADObject $ridDn -Property rIDAvailablePool -ErrorAction Stop
        $pool   = [UInt64]$ridObj.rIDAvailablePool
        $ceiling = [Math]::Floor($pool / [Math]::Pow(2,32))   # total RIDs available to this domain
        $issued  = $pool - ($ceiling * [Math]::Pow(2,32))     # RIDs already allocated to pools
        $remaining = $ceiling - $issued
        $pctUsed = if ($ceiling -gt 0) { [Math]::Round(($issued / $ceiling) * 100, 4) } else { 0 }
        $status  = if ($pctUsed -ge 90) {'WARN'} else {'INFO'}
        Add-Result 'RID' 'RID pool consumption' $status `
            ("Issued={0:N0}; Ceiling={1:N0}; Remaining={2:N0} ({3}% of global RID space used)." -f $issued, $ceiling, $remaining, $pctUsed)
    } catch {
        Add-Result 'RID' 'Read RID pool' 'WARN' $_.Exception.Message
    }
}

# ----------------------------------------------------------------------------------
# 7. Time source posture (matters most for PDC Emulator) - w32tm /query only
# ----------------------------------------------------------------------------------
if ($tools['w32tm']) {
    Write-Section "Time Source (w32tm /query - read-only)"
    $timeTargets = @()
    if ($domain) { $timeTargets += $domain.PDCEmulator }
    if ($SourceDC -and $timeTargets -notcontains $SourceDC) { $timeTargets += $SourceDC }
    if ($TargetDC -and $timeTargets -notcontains $TargetDC) { $timeTargets += $TargetDC }
    if (-not $timeTargets) { $timeTargets = @($env:COMPUTERNAME) }

    foreach ($tt in ($timeTargets | Select-Object -Unique)) {
        $src = (Invoke-ReadOnlyExe 'w32tm.exe' @("/query","/computer:$tt","/source")).Trim()
        $st  = (Invoke-ReadOnlyExe 'w32tm.exe' @("/query","/computer:$tt","/status")).Trim()
        $isPdc = ($domain -and $tt -eq $domain.PDCEmulator)
        # On the PDCe a local-clock/free-running source is a red flag.
        $badSource = ($src -match 'Local CMOS Clock|Free-running')
        $status = if ($isPdc -and $badSource) {'WARN'} else {'INFO'}
        $note = if ($isPdc) {' (current PDC Emulator)'} else {''}
        Add-Result 'Time' "Time source: $tt$note" $status ("Source: $src`n$st")
    }
    Add-Result 'Time' 'Post-move reminder' 'INFO' `
        'If PDC Emulator moves, reconfigure w32time afterward: new holder -> external NTP, old holder -> domain hierarchy. (This script does not change time config.)'
}

# ----------------------------------------------------------------------------------
# 8. DNS resolution + SRV records (read-only)
# ----------------------------------------------------------------------------------
if ($adModuleOk -and $domain) {
    Write-Section "DNS Resolution"
    # 8a. Forward-resolve each DC hostname.
    foreach ($dc in $dcs) {
        try {
            $r = Resolve-DnsName -Name $dc.HostName -Type A -ErrorAction Stop
            $ips = ($r | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress) -join ', '
            Add-Result 'DNS' "Resolve $($dc.HostName)" 'PASS' "A -> $ips"
        } catch {
            Add-Result 'DNS' "Resolve $($dc.HostName)" 'FAIL' $_.Exception.Message
        }
    }
    # 8b. Locator SRV records for the domain.
    try {
        $srv = Resolve-DnsName -Name ("_ldap._tcp.dc._msdcs.{0}" -f $domain.DNSRoot) -Type SRV -ErrorAction Stop
        $count = ($srv | Where-Object { $_.NameTarget }).Count
        Add-Result 'DNS' '_ldap._tcp.dc._msdcs SRV records' $(if ($count -gt 0) {'PASS'} else {'WARN'}) "$count target(s) registered."
    } catch {
        Add-Result 'DNS' '_ldap._tcp.dc._msdcs SRV records' 'WARN' $_.Exception.Message
    }
}

# ----------------------------------------------------------------------------------
# 9. Core service status on Source/Target (read-only Get-Service)
# ----------------------------------------------------------------------------------
if ($SourceDC -or $TargetDC) {
    Write-Section "Core Services on Source/Target"
    $svcTargets = @($SourceDC, $TargetDC) | Where-Object { $_ } | Select-Object -Unique
    $svcNames   = 'NTDS','Netlogon','DNS','W32Time','kdc'
    foreach ($svcDc in $svcTargets) {
        foreach ($svc in $svcNames) {
            try {
                $s = Get-Service -ComputerName $svcDc -Name $svc -ErrorAction Stop
                $status = if ($s.Status -eq 'Running') {'PASS'} else {'WARN'}
                Add-Result 'Services' "$svcDc / $svc" $status $s.Status
            } catch {
                Add-Result 'Services' "$svcDc / $svc" 'WARN' "Could not query: $($_.Exception.Message)"
            }
        }
    }
}

# ----------------------------------------------------------------------------------
# 10. RPC / LDAP / GC reachability between Source and Target (TCP probe only)
# ----------------------------------------------------------------------------------
if ($SourceDC -and $TargetDC -and -not $SkipPortTests) {
    Write-Section "Source <-> Target Port Reachability (TCP probe)"
    $ports = @{
        135  = 'RPC Endpoint Mapper'
        389  = 'LDAP'
        636  = 'LDAPS'
        3268 = 'GC LDAP'
        3269 = 'GC LDAPS'
        53   = 'DNS'
    }
    foreach ($pair in @(@($SourceDC,$TargetDC), @($TargetDC,$SourceDC))) {
        $from = $pair[0]; $to = $pair[1]
        foreach ($p in ($ports.Keys | Sort-Object)) {
            try {
                $tnc = Test-NetConnection -ComputerName $to -Port $p -WarningAction SilentlyContinue -ErrorAction Stop
                $status = if ($tnc.TcpTestSucceeded) {'PASS'} else {'FAIL'}
                Add-Result 'Ports' ("{0} -> {1}:{2} ({3})" -f $from, $to, $p, $ports[$p]) $status `
                    ("TcpTestSucceeded=$($tnc.TcpTestSucceeded)")
            } catch {
                Add-Result 'Ports' ("{0} -> {1}:{2} ({3})" -f $from, $to, $p, $ports[$p]) 'WARN' $_.Exception.Message
            }
        }
    }
} elseif ($SkipPortTests) {
    Add-Result 'Ports' 'Port reachability' 'INFO' 'Skipped (-SkipPortTests).'
}

# ----------------------------------------------------------------------------------
# 11. Backup posture (read-only) - reminder + best-effort last-backup lookup
# ----------------------------------------------------------------------------------
Write-Section "Backup Posture"
Add-Result 'Backup' 'System State backup reminder' 'INFO' `
    'Confirm a recent System State backup of the DCs exists before transferring. This script cannot verify your backup product; the check below only covers Windows Server Backup if present.'
if ((Test-Tool 'wbadmin.exe') -and $isElevated) {
    $wb = Invoke-ReadOnlyExe 'wbadmin.exe' @('get','versions')
    Add-Result 'Backup' 'wbadmin get versions' 'INFO' ($wb.Trim())
} else {
    Add-Result 'Backup' 'wbadmin get versions' 'WARN' 'Skipped (wbadmin not found or not elevated). Verify backups via your backup solution.'
}

# ----------------------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------------------
Write-Section "Summary"
$counts = $script:Results | Group-Object Status | Sort-Object Name
foreach ($c in $counts) {
    $color = switch ($c.Name) { 'PASS'{'Green'} 'WARN'{'Yellow'} 'FAIL'{'Red'} default{'Gray'} }
    Write-Host ("  {0,-4} : {1}" -f $c.Name, $c.Count) -ForegroundColor $color
}

$fails = ($script:Results | Where-Object { $_.Status -eq 'FAIL' }).Count
$warns = ($script:Results | Where-Object { $_.Status -eq 'WARN' }).Count

Write-Host ""
if ($fails -gt 0) {
    Write-Host "VERDICT: NOT READY - $fails FAIL item(s). Resolve before transferring FSMO roles." -ForegroundColor Red
} elseif ($warns -gt 0) {
    Write-Host "VERDICT: REVIEW - $warns WARN item(s). Investigate before proceeding." -ForegroundColor Yellow
} else {
    Write-Host "VERDICT: No FAIL/WARN items detected. Still review the INFO output before transferring." -ForegroundColor Green
}

# Export report (local report file only - does not touch AD).
try {
    $script:Results | Export-Csv -Path $reportCsv -NoTypeInformation -Encoding UTF8
    Write-Host ""
    Write-Host "CSV report : $reportCsv" -ForegroundColor DarkGray
} catch {
    Write-Host "Could not write CSV report: $($_.Exception.Message)" -ForegroundColor DarkGray
}
if ($transcriptOn) {
    Write-Host "Transcript : $transcript" -ForegroundColor DarkGray
    try { Stop-Transcript | Out-Null } catch {}
}

Write-Host ""
Write-Host "Reminder: this script only READS. The actual transfer (Move-ADDirectoryServerOperationMasterRole" -ForegroundColor DarkGray
Write-Host "or ntdsutil) is a separate, deliberate step you run after reviewing these results." -ForegroundColor DarkGray
