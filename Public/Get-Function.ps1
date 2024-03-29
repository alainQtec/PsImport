﻿function Get-Function {
    <#
    .SYNOPSIS
        Import functions from other scripts into the current script.
    .DESCRIPTION
        Close to javascript's ESmodule import functionality.
        Features:
        + can import many functions at once
        + Support wildcards. See examples.
        + No need to know relative paths of files in the repo. just use unique filename
    .INPUTS
        [string[]]
    .OUTPUTS
        [scriptBlock[]]
    .LINK
        https://github.com/alainQtec/PsImport/blob/main/Public/Get-Function.ps1
    .EXAMPLE
        (Import fnName1, fnName2 -From '/relative/path/to/script.ps1').ForEach({ . $_ })
        # Imports the functions fnName1 fnName2

    .EXAMPLE
        (Import * -from '/relative/path/to/script.ps1').ForEach({ . $_ })
        # Using wildcards for names: All functions in the file get loaded in current script scope.

        (Import * -from '/relative/path/to/fileNamedlikeabc*.ps1').ForEach({ . $_ })
        # Import all functions in files that look like fileNamedlikeabc
    #>
    [CmdletBinding(DefaultParameterSetName = "File")]
    [OutputType([System.Object[]])]
    [Alias("Import", "require", "Get-Functions")]
    param (
        # Query or Names of functions to import
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = '__AllParameterSets')]
        [ValidateNotNullOrEmpty()]
        [Alias('n', 'names', 'function', 'functions')]
        [string[]]$Name,

        # FilePath from which to import
        [Parameter(Position = 1, Mandatory = $false, ParameterSetName = 'File')]
        [ValidateNotNullOrEmpty()]
        [Alias('f', "file")]
        [string[]]$path,

        [Parameter(Position = 1, Mandatory = $false, ParameterSetName = 'Url')]
        [ValidateNotNullOrEmpty()]
        [Alias("from", "uri")]
        [uri[]]$rawUri,

        # Minimum version of function to import
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = '__AllParameterSets')]
        [ValidateNotNull()][Alias('MinVersion')]
        [version]$Version
    )

    begin {
        $Functions = @()
    }
    process {
        try {
            if (!$PSBoundParameters.ContainsKey('path')) {
                $path = Resolve-FilePath $Name
            }
            $source = $(if ($PSCmdlet.ParameterSetName -eq "Url") { $rawUri } else { $path })
            [PsImport]::GetFunctions(($Name -as [Query[]]), $source, ([string]$ErrorActionPreference -eq 'Stop')).Foreach({
                    $Functions += $_.scriptBlock
                }
            )
        } catch {
            $PSCmdlet.ThrowTerminatingError(
                [System.Management.Automation.ErrorRecord]::New(
                    $_.Exception, $_.FullyQualifiedErrorId, $_.CategoryInfo.Category, [PSCustomObject]@{
                        Params = $PSCmdlet.MyInvocation.BoundParameters
                    }
                )
            )
        }
    }
    end {
        return $Functions
    }
}