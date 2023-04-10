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
        Resolve-FilePath *
        will list fullNames of files in current location; thus [psimport]::ParseFile("*") will parse any powershell file in current location.
    #>
    [CmdletBinding(DefaultParameterSetName = 'singlePath')]
    [OutputType([System.Object[]])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'singlePath')]
        [ValidateNotNullOrEmpty()][string]$Path,
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ParameterSetName = 'multiplePaths')]
        [ValidateNotNullOrEmpty()][string[]]$FilePaths,
        [switch]$throwOnFailure = $false,
        [switch]$NoAmbiguous
    )

    begin {
        $paths = @(); $resolved = @();
        $paths += if ($PSCmdlet.ParameterSetName.Equals('singlePath')) { @($Path) } else { $FilePaths }
        $rRoot = if (Get-Command -Name git -CommandType Application -ErrorAction Ignore) { git rev-parse --show-toplevel }else { $null }
    }
    process {
        forEach ($p in $paths) {
            if ($p.Contains('*')) {
                $(Get-Item $p).Where({ $_.Attributes.ToString() -ne 'Directory' }).FullName.Foreach({ $resolved += $_ })
                continue
            }
            $resolvedPaths = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($p);
            $existingPaths = $resolvedPaths | Where-Object { [IO.Path]::Exists($_) };
            $resolvedPaths, $error_Msg = switch ($true) {
                ($existingPaths.Count -gt 1) {
                    if ($NoAmbiguous) { $existingPaths[0], "Path '$p' is ambiguous: $($existingPaths -join ', ')" } else { $existingPaths, $null };
                    break
                }
                ($existingPaths.Count -eq 0) {
                    $fp = $null; if ([IO.Path]::Exists($rRoot)) {
                        $ft = if (![IO.Path]::HasExtension($p)) { $p + '*' } else { $p }
                        $fp = Get-ChildItem -Recurse -Path $rRoot -Filter $ft -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
                    }
                    if (!$fp) { $null, "Path '$p' not found" } else { $fp, $null };
                    break
                }
                Default { $existingPaths, $null }
            }; if ($error_Msg) { if ($throwOnFailure) { throw [System.Management.Automation.ItemNotFoundException]::new($error_Msg) } else { Write-Warning -Message $error_Msg } }
            $resolvedPaths.Foreach({ $resolved += $_ })
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