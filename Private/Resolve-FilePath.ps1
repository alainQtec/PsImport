function Resolve-FilePath {
    <#
    .SYNOPSIS
        Resolve FilePath
    .DESCRIPTION
        Gets the full Path of any file in a repo
    .INPUTS
        [string[]]
    .OUTPUTS
        [String[]]
    .EXAMPLE
        Resolve-FilePath * -Extensions ('.ps1', '.psm1')
        Will get paths of powershell files in current location; thus [psimport]::ParseFile("*") will parse any powershell file in current location.
    .EXAMPLE
        Resolve-FilePath "Tests\Resources\Test-H*", "Tests\Resources\Test-F*"
    .EXAMPLE
        REsolve-FilePath ..\*.Tests.ps1
    .NOTES
        Created to work with the "PsImport" module. (Its not tested for other use cases)
        TopLevel directory search takes Priority.
            eg: REsolve-FilePath PsImport.ps1 will return ./PsImport.ps1 instead of ./BuildOutput/PsImport/0.1.0/PsImport.psm1
                Unless ./PsImport.ps1 doesn't exist; In that case it will Recursively search for other Names in the repo.
    .LINK
        https://github.com/alainQtec/PsImport/blob/main/Private/Resolve-FilePath.ps1
    #>
    [CmdletBinding(DefaultParameterSetName = 'Query')]
    [OutputType([System.Object[]])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Query')]
        [ValidateNotNullOrEmpty()]
        [Alias('Path')]
        [string]$Query,

        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ParameterSetName = 'Paths')]
        [ValidateNotNullOrEmpty()]
        [string[]]$Paths,

        [Parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $false, ParameterSetName = '__AllParameterSets')]
        [ValidateNotNullOrEmpty()]
        [Alias('Extension')]
        [string[]]$Extensions,

        [Parameter(Mandatory = $false, Position = 2, ValueFromPipeline = $false, ParameterSetName = '__AllParameterSets')]
        [string[]]$Exclude,

        [switch]$throwOnFailure = $false,

        [switch]$NoAmbiguous
    )

    begin {
        $pathsToSearch = @(); $resolved = @(); $error_Msg = $null
        $pathsToSearch += if ($PSCmdlet.ParameterSetName.Equals('Query')) { @($Query) } else { $Paths }
        $GitHubrepoRoot = $(if (Get-Command -Name git -CommandType Application -ErrorAction Ignore) { git rev-parse --show-toplevel }else { $null }) -as [IO.DirectoryInfo]
        # TODO: Add functionality for the $Exclude param. By default will be filled with all paths in the gitIgnore ie:
        # [IO.File]::ReadAllLines([IO.Path]::Combine($ExecutionContext.SessionState.Path.CurrentLocation, '.gitignore')).Where({!$_.StartsWith('#') -and ![string]::IsNullOrWhiteSpace($_)})
    }
    process {
        forEach ($p in $pathsToSearch) {
            # TopLevel directory search:
            $q = $p; $p = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($p);
            [string[]]$resolvedPaths = (Resolve-Path $p -ErrorAction Ignore).Path
            [string[]]$existingPaths = ($resolvedPaths | Where-Object { (Test-Path -Path "$_" -PathType Any -ErrorAction Ignore) })
            $resolvedPaths, $error_Msg = $existingPaths, $null
            if ($null -ne $existingPaths) {
                if ($existingPaths.Count -gt 1) {
                    $resolvedPaths, $error_Msg = $(if ($NoAmbiguous) { $existingPaths[0], "Path '$p' is ambiguous: $($existingPaths -join ', ')" } else { $existingPaths, $null })
                } else {
                    $resolvedPaths = $existingPaths[0]
                }
                Continue
            }
            # Multi-Level directory search / -Recurse :
            $resolvedPaths = $null; if ((Test-Path -Path $GitHubrepoRoot.FullName -PathType Container -ErrorAction Ignore)) {
                $resolvedPaths = $(switch ($true) {
                        ([IO.Path]::IsPathFullyQualified($q)) {
                            Get-Item -Path $q -ErrorAction Ignore
                            break
                        }
                        (![IO.Path]::IsPathFullyQualified($q) -and $q.Contains([IO.Path]::DirectorySeparatorChar)) {
                            $IsMatch = if ($q.Contains('*')) {
                                [scriptblock]::Create("([IO.Path]::GetRelativePath(`$ExecutionContext.SessionState.Path.CurrentLocation, `$_.FullName)) -like `"$q`" -or `$_.FullName -like `"$q`"")
                            } else {
                                [scriptblock]::Create("([IO.Path]::GetRelativePath(`$ExecutionContext.SessionState.Path.CurrentLocation, `$_.FullName)) -eq `"$q`" -or `$_.FullName -eq `"$q`"")
                            }
                            $(Get-ChildItem -Path $GitHubrepoRoot.FullName -File -Recurse -ErrorAction Ignore).Where($IsMatch)
                            break
                        }
                        (![IO.Path]::IsPathFullyQualified($q) -and !$q.Contains([IO.Path]::DirectorySeparatorChar)) {
                            $IsMatch = if ($q.Contains('*')) { [scriptblock]::Create('$_.Name -like $q -or $_.BaseName -like $q') } else { [scriptblock]::Create('$_.Name -eq $q -or $_.BaseName -eq $q') }
                            $(Get-ChildItem -Path $GitHubrepoRoot.FullName -File -Recurse -ErrorAction Ignore).Where($IsMatch)
                            break
                        }
                        Default {
                            Get-ChildItem -Path $GitHubrepoRoot.FullName -File -Recurse -Filter $q -ErrorAction Ignore
                        }
                    }
                ) | Select-Object -ExpandProperty FullName
            }; $resolvedPaths, $error_Msg = $(if (!$resolvedPaths) { $null, "Path '$p' was not found." } else { $resolvedPaths, $null })
        }
        # Sort & Filter Results:
        if ($null -ne $resolvedPaths -and $resolvedPaths.count -gt 0) {
            $(# Filter extensions:
                if ($PSBoundParameters.ContainsKey('Extensions')) {
                    $(Get-Item $resolvedPaths).Where({ [string]$_.Attributes -ne 'Directory' -and $_.Extension -in $Extensions })
                } else {
                    $(Get-Item $resolvedPaths).Where({ [string]$_.Attributes -ne 'Directory' })
                }
            ) | Sort-Object -Unique | ForEach-Object { $resolved += $_.FullName }
        } else {
            $error_Msg = "FileNotFound! " + $error_Msg
        }
    }

    end {
        if ($error_Msg) { if ($throwOnFailure) { throw [System.Management.Automation.ItemNotFoundException]::new($error_Msg) } else { Write-Warning -Message $error_Msg } }
        if ($resolved.Count -gt 1 -and $NoAmbiguous) {
            $error_Msg = 'Resolved to Multiple paths'
            if ($throwOnFailure) {
                throw $error_Msg
            } else {
                Write-Verbose $error_Msg
            }
        }
        return $resolved
    }
}