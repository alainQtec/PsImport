function Get-Function {
    <#
    .SYNOPSIS
        Import functions from other scripts into the current script.
    .DESCRIPTION
        Close to javascript's ESmodule import functionality.
        Features:
        + can import many functions at once
        + Support wildcards. See examples.
        + No need to know relative paths of files in the repo. just use unique filename
    .NOTES
        Inspiration: https://gist.github.com/alainQtec/71123a1d28f37eaa49fd032ba0248650
    .LINK
        https://github.com/alainQtec/PsImport/blob/main/Public/Get-Function.ps1
    .EXAMPLE
        (Import fnName1, fnName2 -From '/relative/path/to/script.ps1').ForEach({ . $_ })
        # Imports the functions fnName1 fnName2

    .EXAMPLE
        (Import * -from '/relative/path/to/script.ps1').ForEach({ . $_ })
        # Using wildcards for names: All functions in the file get loaded in current script scope.

        (Import * -from '/relative/path/to/fileNamedlikeabc*.ps1').ForEach({ . $_ })
        # Import all functions in files that look kike ileNamedlikeabc
    #>
    [CmdletBinding(DefaultParameterSetName = 'Names')]
    [OutputType([System.Object[]])]
    [Alias("Import", "require", "Get-Functions")]
    param (
        # Names of functions to import
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'Names')]
        [ValidateNotNullOrEmpty()]
        [Alias('functions')]
        [string[]]$Names,

        # Names of functions to import
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'Name')]
        [ValidateNotNullOrEmpty()]
        [Alias('n', 'function')]
        [string]$Name,

        # FilePath from which to import
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName = '__AllParameterSets')]
        [ValidateNotNullOrEmpty()]
        [Alias('f', "from")]
        [string[]]$path,

        # Minimum version of function to import
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'Name')]
        [ValidateNotNull()][Alias('MinVersion')]
        [version]$Version
    )

    begin {
        $Functions = @(); $FnNames = [string[]](if ($PSCmdlet.ParameterSetName -eq 'Name') { $Name } else { $Names })
        if ($path.Count -eq 1) { [string]$path = $path[0] }
    }
    process {
        $throwOnFailure = $false
        $Functions += [PsImport]::GetFunctions($FnNames, $path, $throwOnFailure).scriptBlock
    }
    end {
        return $Functions
    }
}