function Resolve-FilePath {
    <#
    .SYNOPSIS
        Resolve FilePath
    .DESCRIPTION
        Gets the full Path of any file in a repo
    .NOTES
        Only Created to work with the "PsImport" module. (Its not tested for other use cases)
    .LINK
        https://github.com/alainQtec/PsImport/blob/main/Private/Resolve-FilePath.ps1
    .OUTPUTS
        [String[]]
    .EXAMPLE
        Resolve-FilePath * -Extensions ('.ps1', '.psm1')
        Will get paths of powershell files in current location; thus [psimport]::ParseFile("*") will parse any powershell file in current location.
        #Bug: EX: Resolve-FilePath PsImport.psm1
    #>
    [CmdletBinding(DefaultParameterSetName = 'Query')]
    [OutputType([System.Object[]])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Query')]
        [ValidateNotNullOrEmpty()][Alias('Path')][string]$Query,
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ParameterSetName = 'Paths')]
        [ValidateNotNullOrEmpty()][string[]]$Paths,
        [Parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $false, ParameterSetName = '__AllParameterSets')]
        [ValidateNotNullOrEmpty()][string[]]$Extensions,
        [switch]$throwOnFailure = $false,
        [switch]$NoAmbiguous
    )

    begin {
        $pathsToSearch = @(); $resolved = @();
        $pathsToSearch += if ($PSCmdlet.ParameterSetName.Equals('Query')) { @($Query) } else { $Paths }
        $GitHubrepoRoot = $(if (Get-Command -Name git -CommandType Application -ErrorAction Ignore) { git rev-parse --show-toplevel }else { $null }) -as [IO.DirectoryInfo]
    }
    process {
        forEach ($p in $pathsToSearch) {
            $q = $p; $p = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($p);
            $resolvedPaths = (Resolve-Path $p -ErrorAction Ignore).Path
            $existingPaths = $resolvedPaths | Where-Object { (Test-Path -Path "$_" -PathType Any -ErrorAction Ignore) };
            $resolvedPaths, $error_Msg = $existingPaths, $null
            if ($null -ne $existingPaths -or $existingPaths.Count -gt 0) {
                if ($existingPaths.Count -gt 1) {
                    $resolvedPaths, $error_Msg = $(if ($NoAmbiguous) { $existingPaths[0], "Path '$p' is ambiguous: $($existingPaths -join ', ')" } else { $existingPaths, $null })
                } else {
                    $resolvedPaths = $existingPaths[0]
                }
            } else {
                $foundpaths = $null; if ((Test-Path -Path $GitHubrepoRoot.FullName -PathType Container -ErrorAction Ignore)) {
                    $foundpaths = $(switch ($true) {
                        ([IO.Path]::IsPathFullyQualified($q)) {
                                Get-ChildItem -Path $q -File -Recurse -ErrorAction Ignore
                                break
                            }
                        (![IO.Path]::IsPathFullyQualified($q) -and $q.Contains([IO.Path]::DirectorySeparatorChar)) {
                                $Query = if ($q.Contains('*')) { $q } else { "*$q*" }
                                $(Get-ChildItem -Path $GitHubrepoRoot.FullName -File -Recurse -ErrorAction Ignore).Where({ $_.FullName -like $Query })
                                break
                            }
                        (![IO.Path]::IsPathFullyQualified($q) -and !$q.Contains([IO.Path]::DirectorySeparatorChar)) {
                            (Get-ChildItem -Path $GitHubrepoRoot.FullName -File -Recurse -ErrorAction Ignore).Where({
                                        if ($q.Contains('*')) {
                                            $_.Name -like $q -or
                                            $_.BaseName -like $q
                                        } else {
                                            $_.Name -eq $q -or
                                            $_.BaseName -eq $q
                                        }
                                    }
                                )
                                break
                            }
                            Default {
                                Write-Debug "GCI $($GitHubrepoRoot.FullName) srchFiltr: '$q' ..." -Debug
                                Get-ChildItem -Path $GitHubrepoRoot.FullName -File -Recurse -Filter $q -ErrorAction Ignore
                            }
                        }) | Select-Object -ExpandProperty FullName
                }; $resolvedPaths, $error_Msg = $(if (!$foundpaths) { $null, "Path '$p' not found" } else { $foundpaths, $null })
            }
            if ($null -ne $resolvedPaths -and $resolvedPaths.count -gt 0) {
                if ($PSBoundParameters.ContainsKey('Extensions')) {
                    $resolvedPaths = $(Get-Item $resolvedPaths).Where({ [string]$_.Attributes -ne 'Directory' -and $_.Extension -in $Extensions }).FullName
                } else {
                    $resolvedPaths = $(Get-Item $resolvedPaths).Where({ [string]$_.Attributes -ne 'Directory' }).FullName
                }
                $resolvedPaths.Foreach({ $resolved += $_ })
            } else {
                # BUG: IDK Why!
                $error_Msg += 'FileNotFound!!!! (BUG)'
            }
            if ($error_Msg) { if ($throwOnFailure) { throw [System.Management.Automation.ItemNotFoundException]::new($error_Msg) } else { Write-Warning -Message $error_Msg } }
        }
        if ($resolved.Count -gt 1 -and $NoAmbiguous) {
            $error_Msg = 'Resolved to Multiple paths'
            if ($throwOnFailure) {
                throw $error_Msg
            } else {
                Write-Verbose $error_Msg
            }
        }
    }

    end {
        return $resolved
    }
}