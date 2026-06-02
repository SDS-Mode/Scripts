
#Requires -Modules ActiveDirectory
 
<#
.SYNOPSIS
    Analyzes an Active Directory domain for nested group membership, identifying
    which groups contain other groups and how deeply that nesting goes.
 
.DESCRIPTION
    Get-ADNestedGroupReport enumerates groups in the domain (or under a specified
    SearchBase), then walks each group's membership recursively to find groups that
    contain other groups as members. For every group it reports:
 
        - Whether it directly contains nested groups
        - The list of directly nested groups
        - The maximum nesting depth beneath it (how many levels of groups descend from it)
        - Total distinct groups reachable beneath it
        - Any circular nesting paths detected (A -> B -> A)
 
    Performance / correctness notes:
        - All group objects (with their 'member' attribute) are pulled in a SINGLE bulk
          query and cached in a hashtable keyed by DistinguishedName. All recursion then
          runs in memory. This avoids repeated DC round-trips and sidesteps the default
          5000-member limit and cross-domain/FSP errors you hit with -Recursive on
          Get-ADGroupMember.
        - Circular references are detected per recursion path and reported rather than
          causing an infinite loop.
        - Members that are not groups (users, computers, contacts, foreign security
          principals) are ignored for nesting purposes by design.
 
.PARAMETER SearchBase
    Optional distinguished name to scope the group search (e.g. an OU). Defaults to the
    whole domain.
 
.PARAMETER Server
    Optional domain controller / domain to target. Passed through to the AD cmdlets.
 
.PARAMETER NestedOnly
    Switch. If set, the object output is limited to groups that directly contain at
    least one nested group. (The console tree view always shows only nested groups.)
 
.PARAMETER ShowTree
    Switch. Renders an indented tree to the console showing the nesting hierarchy.
 
.PARAMETER MaxDepth
    Safety ceiling on recursion depth. Default 50. Cycles are already handled separately;
    this is a backstop against pathological structures.
 
.PARAMETER CsvPath
    Optional path. If supplied, the report objects are exported to CSV at this path.
 
.EXAMPLE
    .\Get-ADNestedGroupReport.ps1 -ShowTree
 
    Full-domain analysis with a console tree of nested groups, plus the report objects
    on the pipeline.
 
.EXAMPLE
    .\Get-ADNestedGroupReport.ps1 -NestedOnly | Sort-Object MaxNestingDepth -Descending | Format-Table Name, DirectNestedCount, MaxNestingDepth, HasCircularReference
 
    Just the parent groups, ranked by how deep their nesting goes.
 
.EXAMPLE
    .\Get-ADNestedGroupReport.ps1 -SearchBase "OU=Groups,DC=corp,DC=contoso,DC=com" -CsvPath C:\Temp\nesting.csv
 
    Scope to an OU and export to CSV.
 
.NOTES
    Requires the ActiveDirectory module (RSAT). Read-only; makes no changes to AD.
#>
 
[CmdletBinding()]
param(
    [string]$SearchBase,
    [string]$Server,
    [switch]$NestedOnly,
    [switch]$ShowTree,
    [int]$MaxDepth = 50,
    [string]$CsvPath
)
 
Import-Module ActiveDirectory -ErrorAction Stop
 
# --- 1. Bulk-load all groups once, with their member attribute -----------------
$adParams = @{
    Filter     = '*'
    Properties = @('member', 'groupCategory', 'groupScope')
}
if ($SearchBase) { $adParams['SearchBase'] = $SearchBase }
if ($Server)     { $adParams['Server']     = $Server }
 
Write-Verbose "Querying groups..."
$allGroups = Get-ADGroup @adParams
 
if (-not $allGroups) {
    Write-Warning "No groups returned for the given scope."
    return
}
 
# Hashtable: DistinguishedName -> group object. Also serves as the fast
# "is this member DN a group?" lookup. Using OrdinalIgnoreCase because DNs are
# case-insensitive in AD.
$groupByDN = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($g in $allGroups) {
    if (-not $groupByDN.ContainsKey($g.DistinguishedName)) {
        $groupByDN[$g.DistinguishedName] = $g
    }
}
 
Write-Verbose ("Loaded {0} groups into cache." -f $groupByDN.Count)
 
# --- 2. Recursive descent with cycle detection --------------------------------
# Returns a hashtable: @{ MaxDepth = <int>; Reachable = <HashSet[string]>; Cycles = <List[string]> }
# $pathStack is the ordered list of DNs from the current root down to here (for cycle reporting).
# $pathSet is the same set for O(1) membership tests.
function Resolve-GroupNesting {
    param(
        [string]$GroupDN,
        [int]$CurrentDepth,
        [System.Collections.Generic.List[string]]$PathStack,
        [System.Collections.Generic.HashSet[string]]$PathSet
    )
 
    $result = @{
        MaxDepth  = 0
        Reachable = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        Cycles    = [System.Collections.Generic.List[string]]::new()
    }
 
    if ($CurrentDepth -ge $script:MaxDepth) {
        Write-Warning ("MaxDepth ({0}) reached at: {1}" -f $script:MaxDepth, $GroupDN)
        return $result
    }
 
    $group = $null
    if (-not $groupByDN.TryGetValue($GroupDN, [ref]$group)) {
        return $result   # member group lives outside our scope/cache; treat as leaf
    }
 
    $memberDNs = @($group.member)
    foreach ($memberDN in $memberDNs) {
        # Only members that are themselves groups matter for nesting.
        if (-not $groupByDN.ContainsKey($memberDN)) { continue }
 
        if ($PathSet.Contains($memberDN)) {
            # Cycle: this group is already an ancestor in the current path.
            $cyclePath = ($PathStack + $memberDN) -join ' -> '
            $result.Cycles.Add($cyclePath)
            continue
        }
 
        [void]$result.Reachable.Add($memberDN)
 
        $null = $PathStack.Add($memberDN)
        $null = $PathSet.Add($memberDN)
 
        $child = Resolve-GroupNesting -GroupDN $memberDN -CurrentDepth ($CurrentDepth + 1) `
                                      -PathStack $PathStack -PathSet $PathSet
 
        # depth contributed by this branch = 1 (this child) + child's own depth
        $branchDepth = 1 + $child.MaxDepth
        if ($branchDepth -gt $result.MaxDepth) { $result.MaxDepth = $branchDepth }
 
        foreach ($r in $child.Reachable) { [void]$result.Reachable.Add($r) }
        foreach ($c in $child.Cycles)    { $result.Cycles.Add($c) }
 
        # pop
        $PathStack.RemoveAt($PathStack.Count - 1)
        [void]$PathSet.Remove($memberDN)
    }
 
    return $result
}
 
# --- 3. Build the report ------------------------------------------------------
$report = foreach ($g in $allGroups) {
 
    $directNested = @(
        foreach ($memberDN in @($g.member)) {
            if ($groupByDN.ContainsKey($memberDN)) { $groupByDN[$memberDN].Name }
        }
    )
 
    $pathStack = [System.Collections.Generic.List[string]]::new()
    $pathSet   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $null = $pathStack.Add($g.DistinguishedName)
    $null = $pathSet.Add($g.DistinguishedName)
 
    $nesting = Resolve-GroupNesting -GroupDN $g.DistinguishedName -CurrentDepth 0 `
                                    -PathStack $pathStack -PathSet $pathSet
 
    [pscustomobject]@{
        Name                 = $g.Name
        DistinguishedName    = $g.DistinguishedName
        GroupCategory        = $g.groupCategory
        GroupScope           = $g.groupScope
        HasNestedGroups      = ($directNested.Count -gt 0)
        DirectNestedCount    = $directNested.Count
        DirectNestedGroups   = ($directNested -join '; ')
        MaxNestingDepth      = $nesting.MaxDepth
        TotalGroupsBeneath   = $nesting.Reachable.Count
        HasCircularReference = ($nesting.Cycles.Count -gt 0)
        CircularPaths        = ($nesting.Cycles | Select-Object -Unique) -join ' | '
    }
}
 
if ($NestedOnly) {
    $report = $report | Where-Object HasNestedGroups
}
 
# --- 4. Optional console tree -------------------------------------------------
if ($ShowTree) {
    function Write-NestingTree {
        param(
            [string]$GroupDN,
            [int]$Indent,
            [System.Collections.Generic.HashSet[string]]$PathSet
        )
        $group = $null
        if (-not $groupByDN.TryGetValue($GroupDN, [ref]$group)) { return }
 
        foreach ($memberDN in @($group.member)) {
            if (-not $groupByDN.ContainsKey($memberDN)) { continue }
            $childName = $groupByDN[$memberDN].Name
            $prefix = ('  ' * $Indent) + '+- '
 
            if ($PathSet.Contains($memberDN)) {
                Write-Host ("{0}{1}  [CIRCULAR]" -f $prefix, $childName) -ForegroundColor Red
                continue
            }
            Write-Host ("{0}{1}" -f $prefix, $childName) -ForegroundColor Cyan
            [void]$PathSet.Add($memberDN)
            Write-NestingTree -GroupDN $memberDN -Indent ($Indent + 1) -PathSet $PathSet
            [void]$PathSet.Remove($memberDN)
        }
    }
 
    Write-Host "`n=== Nested Group Hierarchy ===" -ForegroundColor Yellow
    foreach ($g in ($allGroups | Where-Object { @($_.member | Where-Object { $groupByDN.ContainsKey($_) }).Count -gt 0 } | Sort-Object Name)) {
        Write-Host $g.Name -ForegroundColor Green
        $seed = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        [void]$seed.Add($g.DistinguishedName)
        Write-NestingTree -GroupDN $g.DistinguishedName -Indent 1 -PathSet $seed
    }
    Write-Host ""
}
 
# --- 5. Output ----------------------------------------------------------------
if ($CsvPath) {
    $report | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Verbose "Exported report to $CsvPath"
}
 
$report
