#!/usr/bin/env pwsh
# Requires: PowerShell 7+, .NET SDK
# Scans recursively for .csproj/.sln/.slnx, deduplicates projects, then reports NuGet vulnerabilities and updates using nuget.org only.

param(
    [string]$Path,
    [switch]$Restore,
    [int]$ThrottleLimit = 4
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$NuGetSource = 'https://api.nuget.org/v3/index.json'
$Root = if ([string]::IsNullOrWhiteSpace($Path)) {
    (Get-Location).Path
} else {
    (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
}

function Resolve-ExistingPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        return $item.FullName
    } catch {
        return $null
    }
}

function Add-Project([hashtable]$Projects, [string]$Path) {
    $full = Resolve-ExistingPath $Path
    if ($full -and $full.EndsWith('.csproj', [StringComparison]::OrdinalIgnoreCase)) {
        $Projects[$full.ToLowerInvariant()] = $full
    }
}

function Get-ProjectsFromSln([string]$SlnPath) {
    $dir = Split-Path -Parent $SlnPath
    foreach ($line in Get-Content -LiteralPath $SlnPath) {
        if ($line -match '^Project\("\{[^}]+\}"\)\s*=\s*"[^"]+",\s*"([^"]+\.csproj)",') {
            Join-Path $dir $matches[1]
        }
    }
}

function Get-ProjectsFromSlnx([string]$SlnxPath) {
    $dir = Split-Path -Parent $SlnxPath
    $text = Get-Content -LiteralPath $SlnxPath -Raw

    try {
        [xml]$xml = $text
        $nodes = $xml.SelectNodes('//*[@Path or @path]')
        foreach ($node in $nodes) {
            $p = $node.Path
            if (-not $p) { $p = $node.path }
            if ($p -and $p.EndsWith('.csproj', [StringComparison]::OrdinalIgnoreCase)) {
                Join-Path $dir $p
            }
        }
    } catch {
        foreach ($m in [regex]::Matches($text, '[^"''<>]+\.csproj')) {
            Join-Path $dir $m.Value
        }
    }
}

# Shared helper functions passed into parallel runspaces as a string (scriptblocks can't cross runspace boundaries via $using:)
$HelperFunctionsStr = {
    function Invoke-DotNetJson([string[]]$Arguments) {
        $output = @(& dotnet @Arguments 2>&1)
        $exit = $LASTEXITCODE
        $jsonStart = ($output | Select-String -Pattern '^\s*[\[{]' | Select-Object -First 1)?.LineNumber
        if (-not $jsonStart) {
            return [pscustomobject]@{ Ok = $false; Error = ($output -join [Environment]::NewLine).Trim(); Json = $null }
        }
        $jsonText = ($output[($jsonStart - 1)..($output.Count - 1)] -join [Environment]::NewLine)
        try {
            $parsed = $jsonText | ConvertFrom-Json -Depth 100
            if ($exit -ne 0) {
                $problems = @($parsed.PSObject.Properties['problems']?.Value)
                $errorText = if ($problems.Count) {
                    ($problems | ForEach-Object { "[$($_.level)] $($_.text)" }) -join [Environment]::NewLine
                } else {
                    ($output -join [Environment]::NewLine).Trim()
                }
                return [pscustomobject]@{ Ok = $false; Error = $errorText; Json = $null }
            }
            return [pscustomobject]@{ Ok = $true; Error = $null; Json = $parsed }
        } catch {
            return [pscustomobject]@{ Ok = $false; Error = "Failed to parse JSON: $($_.Exception.Message)$([Environment]::NewLine)$jsonText"; Json = $null }
        }
    }

    function Get-PropertyValue($Object, [string]$Name) {
        if ($null -eq $Object) { return $null }
        $prop = $Object.PSObject.Properties[$Name]
        if ($null -eq $prop) { return $null }
        return $prop.Value
    }

    function Get-PropertyArray($Object, [string]$Name) {
        $value = Get-PropertyValue $Object $Name
        if ($null -eq $value) { return @() }
        return @($value)
    }

    function Format-Version($Value) {
        if ($null -eq $Value) { return '' }
        return [string]$Value
    }

    function Get-PackageRows($Json) {
        foreach ($project in Get-PropertyArray $Json 'projects') {
            foreach ($framework in Get-PropertyArray $project 'frameworks') {
                $frameworkName = Format-Version (Get-PropertyValue $framework 'framework')
                foreach ($package in Get-PropertyArray $framework 'topLevelPackages') {
                    [pscustomobject]@{ Framework = $frameworkName; Kind = 'TopLevel'; Package = $package }
                }
                foreach ($package in Get-PropertyArray $framework 'transitivePackages') {
                    [pscustomobject]@{ Framework = $frameworkName; Kind = 'Transitive'; Package = $package }
                }
            }
        }
    }
}

$projects = @{}

Get-ChildItem -LiteralPath $Root -Recurse -File -Filter '*.csproj' | ForEach-Object {
    Add-Project $projects $_.FullName
}

Get-ChildItem -LiteralPath $Root -Recurse -File -Filter '*.sln' | ForEach-Object {
    foreach ($p in Get-ProjectsFromSln $_.FullName) { Add-Project $projects $p }
}

Get-ChildItem -LiteralPath $Root -Recurse -File -Filter '*.slnx' | ForEach-Object {
    foreach ($p in Get-ProjectsFromSlnx $_.FullName) { Add-Project $projects $p }
}

$projectList = $projects.Values | Sort-Object
if (-not $projectList) {
    Write-Host 'No projects found.'
    exit 0
}

Write-Host "Projects found: $($projectList.Count)"
Write-Host "NuGet source: $NuGetSource"
Write-Host "Throttle limit: $ThrottleLimit"
Write-Host ''

$HelperFunctionsStr = $HelperFunctionsStr.ToString()

# Process projects in parallel; each block returns a list of buffered output lines
$projectList | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $project      = $_
    $nugetSource  = $using:NuGetSource
    $doRestore    = $using:Restore
    $root         = $using:Root
    $helperFns    = $using:HelperFunctionsStr

    # Recreate scriptblock from string and dot-source helpers into this runspace
    . ([scriptblock]::Create($helperFns))

    # Buffer output so lines from different projects don't interleave
    $buf = [System.Collections.Generic.List[pscustomobject]]::new()
    function Emit([string]$text, [string]$color = '') {
        $null = $buf.Add([pscustomobject]@{ Text = $text; Color = $color })
    }

    $relativeProject = [System.IO.Path]::GetRelativePath($root, $project)
    Emit "== $relativeProject =="

    if ($doRestore) {
        $restoreOutput = @(& dotnet restore $project --source $nugetSource 2>&1)
        if ($LASTEXITCODE -ne 0) {
            Emit '  Restore failed:' 'Red'
            Emit (($restoreOutput -join [Environment]::NewLine) -replace '(?m)^', '    ') 'Red'
            Emit ''
            return $buf
        }
    }

    # Launch all three dotnet queries concurrently within this project
    $initSb = [scriptblock]::Create($helperFns)
    $jobVuln = Start-ThreadJob -InitializationScript $initSb -ScriptBlock {
        param($p, $src)
        Invoke-DotNetJson @('list', $p, 'package', '--vulnerable', '--include-transitive', '--format', 'json', '--source', $src)
    } -ArgumentList $project, $nugetSource

    $jobAny = Start-ThreadJob -InitializationScript $initSb -ScriptBlock {
        param($p, $src)
        Invoke-DotNetJson @('list', $p, 'package', '--outdated', '--include-transitive', '--format', 'json', '--source', $src)
    } -ArgumentList $project, $nugetSource

    $jobSameMajor = Start-ThreadJob -InitializationScript $initSb -ScriptBlock {
        param($p, $src)
        Invoke-DotNetJson @('list', $p, 'package', '--outdated', '--include-transitive', '--highest-minor', '--format', 'json', '--source', $src)
    } -ArgumentList $project, $nugetSource

    $null = Wait-Job $jobVuln, $jobAny, $jobSameMajor
    $vulnerable      = Receive-Job $jobVuln
    $latestAny       = Receive-Job $jobAny
    $latestSameMajor = Receive-Job $jobSameMajor
    Remove-Job $jobVuln, $jobAny, $jobSameMajor

    # --- Vulnerabilities ---
    if ($vulnerable.Ok) {
        $vulnRows = @(Get-PackageRows $vulnerable.Json | Where-Object { (Get-PropertyArray $_.Package 'vulnerabilities').Count -gt 0 })
        if ($vulnRows.Count) {
            Emit 'Vulnerabilities:'
            foreach ($row in $vulnRows) {
                $packageId       = Format-Version (Get-PropertyValue $row.Package 'id')
                $resolvedVersion = Format-Version (Get-PropertyValue $row.Package 'resolvedVersion')
                foreach ($v in Get-PropertyArray $row.Package 'vulnerabilities') {
                    Emit ("  [{0}] {1} {2} ({3}) severity={4} {5}" -f `
                        $row.Framework, $packageId, $resolvedVersion, $row.Kind,
                        (Format-Version (Get-PropertyValue $v 'severity')),
                        (Format-Version (Get-PropertyValue $v 'advisoryUrl'))) 'Red'
                }
            }
        } else {
            Emit 'Vulnerabilities: none'
        }
    } else {
        Emit 'Vulnerabilities: check failed' 'Red'
        Emit ($vulnerable.Error -replace '(?m)^', '  ') 'Red'
    }

    # --- Updates ---
    if ($latestAny.Ok -and $latestSameMajor.Ok) {
        $sameMajorByKey = @{}
        foreach ($row in Get-PackageRows $latestSameMajor.Json) {
            $packageId = Format-Version (Get-PropertyValue $row.Package 'id')
            $key = "$($row.Framework)|$($row.Kind)|$packageId"
            $sameMajorByKey[$key] = Get-PropertyValue $row.Package 'latestVersion'
        }

        $updateRows = @(Get-PackageRows $latestAny.Json | Where-Object { $null -ne (Get-PropertyValue $_.Package 'latestVersion') })
        if ($updateRows.Count) {
            Emit 'Updates:'
            foreach ($row in $updateRows) {
                $packageId       = Format-Version (Get-PropertyValue $row.Package 'id')
                $resolvedVersion = Get-PropertyValue $row.Package 'resolvedVersion'
                $latestVersion   = Get-PropertyValue $row.Package 'latestVersion'
                $key             = "$($row.Framework)|$($row.Kind)|$packageId"
                $sameMajor       = $sameMajorByKey[$key]
                if (-not $sameMajor) { $sameMajor = $resolvedVersion }

                $hasSameMajorUpdate = $sameMajor -and ($sameMajor -ne $resolvedVersion)
                $color = if ($hasSameMajorUpdate) { 'Green' } else { 'DarkYellow' }

                Emit ("  [{0}] {1} ({2}) current={3} latestSameMajor={4} latest={5}" -f `
                    $row.Framework, $packageId, $row.Kind,
                    (Format-Version $resolvedVersion),
                    (Format-Version $sameMajor),
                    (Format-Version $latestVersion)) $color
            }
        } else {
            Emit 'Updates: none'
        }
    } else {
        Emit 'Updates: check failed' 'Red'
        if (-not $latestAny.Ok) {
            Emit '  Latest check:' 'Red'
            Emit ($latestAny.Error -replace '(?m)^', '    ') 'Red'
        }
        if (-not $latestSameMajor.Ok) {
            Emit '  Same-major check:' 'Red'
            Emit ($latestSameMajor.Error -replace '(?m)^', '    ') 'Red'
        }
    }

    Emit ''
    return $buf

} | ForEach-Object {
    # Flush each project's buffered output in the order results arrive
    foreach ($line in $_) {
        if ($line.Color) {
            Write-Host $line.Text -ForegroundColor $line.Color
        } else {
            Write-Host $line.Text
        }
    }
}

