#Requires -Version 7.0
function Get-DllAssemblyInfo {
    <#
.SYNOPSIS
  Lists assembly version, public key token, and relative path for matching DLLs.

.DESCRIPTION
  Recursively searches for DLL files matching the given filter under the specified path.
  For each found DLL, prints the assembly version, public key token (as hex string), and the path relative to the search root.

.PARAMETER Path
  The root directory to search. Defaults to the current directory ('.').

.PARAMETER Filter
  The file name pattern to search for. Defaults to '*.dll'.

.EXAMPLE
  Get-DllAssemblyInfo -Path . -Filter 'Microsoft.Owin.Cors'
  # Lists version, public key token, and relative path for all matching DLLs under the current directory.

.EXAMPLE
  Get-DllAssemblyInfo -Path 'C:\Projects'
  # Lists info for all DLLs under C:\Projects.

.EXAMPLE
  Get-DllAssemblyInfo -Path 'C:\Projects' -Filter '*Cors*'
  # Lists info for all DLLs under C:\Projects that contain `Cors` in their name.  

.NOTES
  Author: SeanFu
  Date: 2026-02-18
#>

    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$false)]
        [string]$Path = '.',
        [Parameter(Position=1, Mandatory=$false)]
        [string]$Filter = '*.dll'
    )
        $basePath = (Resolve-Path $Path).Path
    $searchFilter = if ([string]::IsNullOrWhiteSpace($Filter)) {
      '*.dll'
    } else {
      if ($Filter -notmatch '\.dll$') {
        "$Filter.dll"
      } else {
        $Filter
      }
    }
    $results = Get-ChildItem -Path $basePath -Filter $searchFilter -Recurse -File |
      ForEach-Object {
        try {
          $assembly = [System.Reflection.AssemblyName]::GetAssemblyName($_.FullName)
          $versionObj = $assembly.Version
          $version = $versionObj.ToString()
          $pkt = ($assembly.GetPublicKeyToken() | ForEach-Object { $_.ToString("x2") }) -join ''
          $name = $assembly.Name
          $isError = $false
        } catch {
          $versionObj = $null
          $version = $null
          $pkt = $null
          $name = $null
          $isError = $true
        }
        $relativePath = $_.FullName
            if ($relativePath.StartsWith($basePath, [System.StringComparison]::OrdinalIgnoreCase)) {
              $relativePath = $relativePath.Substring($basePath.Length)
              $relativePath = $relativePath.TrimStart([char]'\',[char]'/')
            }
        [PSCustomObject]@{
          Name = $name
          Version = $version
          VersionObj = $versionObj
          PublicKeyToken = $pkt
          Path = $relativePath
          IsError = $isError
        }
      }
    $results |
      Where-Object { -not $_.IsError } |
      Sort-Object Name, @{Expression = { $_.VersionObj }; Descending = $true}, Path |
      Select-Object Name, Version, PublicKeyToken, Path |
      Format-Table -AutoSize
}

# Example usage:
# Get-DllAssemblyInfo -Path . -Filter 'Microsoft.Owin.Cors'
