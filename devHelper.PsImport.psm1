using namespace System.Management.Automation.Language
#region    Classes
Class PsImport {
    static [System.Collections.Generic.List[string]] $ExcludedNames
    static [System.Collections.Generic.Dictionary[string, FunctionDetails]] $Functions # Dictionary of Functions that have already been parsed, so it won't have to do it over again (for performance reasons).
    static [FunctionDetails[]] GetFunction([string]$FnName) { return [PsImport]::GetFunction($FnName, $false) }
    static [FunctionDetails[]] GetFunction([string]$FnName, [string]$FilePath) { return [PsImport]::GetFunction($FnName, $FilePath, $false) }
    static [FunctionDetails[]] GetFunction([string]$FnName, [string[]]$FilePaths) { return [PsImport]::GetFunction($FnName, $FilePaths, $false) }
    static [FunctionDetails[]] GetFunction([string]$FnName, [bool]$throwOnFailure) {
        [ValidateNotNullOrEmpty()][string]$FnName = $FnName; $res = @();
        [string[]]$FnNames = switch ($true) {
            $FnName.Equals('*') { foreach ($Name in [PsImport]::GetFnNames()) { $res += [PsImport]::GetFunction($Name) } ; break }
            $FnName.Contains('*') {
                $AllNames = [PsImport]::GetFnNames(); $Fn_Names = @($AllNames | Where-Object { $_ -like $FnName });
                if (($Fn_Names | Where-Object { $_ -notin $AllNames }).Count -gt 0 -and $throwOnFailure) {
                    throw [System.Management.Automation.ItemNotFoundException]::New($($Fn_Names -join ', '))
                }; $Fn_Names; break
            }
            ([PsImport]::IsValidSource($FnName, $false)) { $(Get-Command -CommandType Function | Where-Object { $_.Source -eq "$FnName" } | Select-Object -ExpandProperty Name); break }
            Default { $FnName }
        }
        if ($res.Count -ne 0) { return $res }
        foreach ($Name in $FnNames) {
            if ([bool]$(try { [PsImport]::Functions.Keys.Contains($Name) } catch { $false })) { $res += [PsImport]::Functions["$Name"]; continue }
            $c = Get-Command $Name -CommandType Function -ErrorAction Ignore
            if ($null -eq $c) { continue }
            [string]$fn = $("function script:$Name {`n" + $((((($c | Format-List) | Out-String) -Split ('Definition  :')) -split ('CommandType : Function')) -split ("Name        : $($Name)")).TrimEnd().Replace('# .EXTERNALHELP', '# EXTERNALHELP').Trim() + "`n}")
            $res += [FunctionDetails]::New($c.Module.Path, $Name, [scriptblock]::Create("$fn"))
        }
        if ($res.Count -eq 0) {
            $_Message = "Could not find function(s). Named: '$FnName'"
            if ($throwOnFailure) { throw [System.Management.Automation.ItemNotFoundException]::New($_Message) }
            $(Get-Variable -Name host).Value.UI.WriteWarningLine("$_Message")
        }
        return $res
    }
    static [FunctionDetails[]] GetFunction([string]$FnName, [string]$FilePath, [bool]$throwOnFailure) {
        [ValidateNotNullOrEmpty()][string]$FnName = $FnName; [ValidateNotNullOrEmpty()][string]$FilePath = $FilePath
        [string[]]$FilePaths = if ($FilePath.Contains('*')) { @(Get-Item $FilePath | Where-Object { $_.Attributes.ToString() -ne 'Directory' } | Select-Object -ExpandProperty FullName) } else { @($FilePath) }
        return [PsImport]::GetFunction($FnName, $FilePaths, $throwOnFailure)
    }
    static [FunctionDetails[]] GetFunction([string]$FnName, [string[]]$FilePaths, [bool]$throwOnFailure) {
        # Validate paths and select only those which can be resolved
        $_FilePaths = @(); foreach ($path in $FilePaths) {
            if ([string]::IsNullOrWhiteSpace($Path)) { continue };
            $_FilePaths += Resolve-FilePath -Path $path -throwOnFailure:$throwOnFailure -NoAmbiguous
        }
        if ($FnName -ne "*") {
            return [PsImport]::ParseFile($_FilePaths).Where({ $_.Name -in $FnName })
        } else {
            return [PsImport]::ParseFile($_FilePaths)
        }
    }
    [System.Management.Automation.Language.FunctionDefinitionAST[]] static GetFncDefinition([string]$Path) {
        return [PsImport]::GetFncDefinition([System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$Null))
    }
    [System.Management.Automation.Language.FunctionDefinitionAST[]] static GetFncDefinition([scriptBlock]$scriptBlock) {
        return [PsImport]::GetFncDefinition([System.Management.Automation.Language.Parser]::ParseInput($scriptBlock.Tostring(), [ref]$null, [ref]$Null))
    }
    [System.Management.Automation.Language.FunctionDefinitionAST[]] static hidden GetFncDefinition([System.Management.Automation.Language.ScriptBlockAst]$ast) {
        $RawFunctions = $null
        $RawAstDocument = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.Ast] }, $true)
        if ($RawASTDocument.Count -gt 0 ) {
            # https://stackoverflow.com/questions/45929043/get-all-functions-in-a-powershell-script/45929412
            $RawFunctions = $RawASTDocument.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $($args[0].parent) -isnot [System.Management.Automation.Language.FunctionMemberAst] })
        }
        return $RawFunctions
    }
    static hidden [string[]] GetFnNames() {
        # Get all Names of loaded funtions whose source is known (loaded from modules)
        return @((Get-Command -CommandType Function | Where-Object { $_.Source -in [PsImport]::GetCommandSources() }).Name)
    }
    static [FunctionDetails[]] ParseFile([string[]]$Path) {
        return [PsImport]::ParseFile($Path, $false, $false)
    }
    static [FunctionDetails[]] ParseFile([string[]]$Path, [bool]$ExcludePSCmdlets) {
        return [PsImport]::ParseFile($Path, $ExcludePSCmdlets, $false)
    }
    static [FunctionDetails[]] ParseFile([string[]]$Path, [bool]$ExcludePSCmdlets, [bool]$UseTitleCase) {
        if ([PsImport]::ExcludedNames.Count -eq 0 -and $ExcludePSCmdlets) {
            [PsImport]::ExcludedNames = [System.Collections.Generic.List[string]]::new()
            $((Get-Command -Module @(
                        "Microsoft.PowerShell.Archive", "Microsoft.PowerShell.Utility",
                        "Microsoft.PowerShell.ODataUtils", "Microsoft.PowerShell.Operation.Validation",
                        "Microsoft.PowerShell.Management", "Microsoft.PowerShell.Core", "Microsoft.PowerShell.LocalAccounts",
                        "Microsoft.WSMan.Management", "Microsoft.PowerShell.Security", "Microsoft.PowerShell.Diagnostics", "Microsoft.PowerShell.Host"
                    )
                ).Name + (Get-Alias).Name).Foreach({
                    [void][PsImport]::ExcludedNames.Add($_)
                }
            )
        }
        $FnDetails = @(); $Paths = (Resolve-FilePath -FilePaths $Path -throwOnFailure:$false).Where({
                $item = Get-Item -Path $_; $item -is [system.io.FileInfo] -and $item.Extension -in @('.ps1', '.psm1')
            }
        )
        forEach ($p in $Paths) {
            $FncDef = [PsImport]::GetFncDefinition($p)
            foreach ($RawASTFunction in $FncDef) {
                $FnDetails += if ([PsImport]::ExcludedNames.Count -gt 0) {
                    [FunctionDetails]::Create($p, $RawASTFunction, [PsImport]::ExcludedNames, $UseTitleCase)
                } else {
                    [FunctionDetails]::Create($p, $RawASTFunction, $UseTitleCase)
                }
            }
        }
        $FnDetails | ForEach-Object { [void][PsImport]::Record($_) }
        return $FnDetails
    }
    static hidden [string[]] GetCommandSources() {
        [string[]]$availableSources = @(Get-Command -CommandType Function | Select-Object Source -Unique).Source | Where-Object { $_.Length -gt 0 }
        return $availableSources
    }
    static hidden [bool] IsValidSource([String]$Source, [bool]$throwOnFailure) {
        $IsValid = $Source -in [PsImport]::GetCommandSources()
        if (!$IsValid -and $throwOnFailure) { throw $(New-Object System.Management.Automation.ErrorRecord $([System.Management.Automation.ItemNotFoundException]"Source named '$Source' was not found"), "ItemNotFoundException", $([System.Management.Automation.ErrorCategory]::ObjectNotFound), "PID: $((Get-Variable -Name PID).Value)") }
        return $IsValid
    }
    static [void] Record([FunctionDetails]$result) {
        $_nl = $null; $Should_Add = [bool]$(try { ![PsImport]::Functions.Keys.Contains($result.Name) } catch {
                $_nl = $_.Exception.Message.Equals('You cannot call a method on a null-valued expression.'); $_nl
            }
        ); if ($_nl) { [PsImport]::Functions = [System.Collections.Generic.Dictionary[string, FunctionDetails]]::New() }
        if ($Should_Add) {
            [PsImport]::Functions.Add($result.Name, $result)
        }
        # else { Write-Debug "[Recording] Skipped $($result.Name)" }
    }
    static [void] Record([FunctionDetails[]]$result) {
        foreach ($item in $result) { [PsImport]::Record($item) }
    }
    static [String] ToTitleCase ([string]$String) { return (Get-Culture).TextInfo.ToTitleCase($String.ToLower()) }
    static [hashtable] ReadPSDataFile([string]$FilePath) {
        return [scriptblock]::Create("$(Get-Content $FilePath | Out-String)").Invoke()
    }
}
class FunctionDetails {
    [string]$Name
    [string]$Path
    [string]$Source
    [System.Collections.ArrayList]$Commands = @()
    hidden [string]$DefaultParameterSet
    hidden [scriptblock]$ScriptBlock
    hidden [PsmoduleInfo]$Module
    hidden [string]$Description
    hidden [string]$ModuleName
    hidden [version]$Version
    hidden [string]$HelpUri
    hidden [string]$Noun
    hidden [string]$Verb
    hidden [ValidateNotNull()][System.Management.Automation.Language.FunctionDefinitionAST]$Definition
    FunctionDetails ([string]$Path, [string]$Name, [scriptblock]$ScriptBlock) {
        $FnDetails = @(); $FncDefinition = [PsImport]::GetFncDefinition($ScriptBlock)
        foreach ($FncAST in $FncDefinition) { $FnDetails += [FunctionDetails]::Create($path, $FncAST, $false) }
        $this.Definition = $FnDetails.Definition;
        $this.Path = Resolve-FilePath -Path $path -NoAmbiguous
        $this.Source = $this.Path.Split([IO.Path]::DirectorySeparatorChar)[-2]
        $this.SetName($Name) ; $this.SetCommands($false); $this.Module = Get-Module -Name $this.Source -ErrorAction Ignore
        $this.ScriptBlock = [scriptBlock]::Create("$($this.Definition.Extent.Text -replace '(?<=^function\s)(?!script:)', 'script:')")
    }
    FunctionDetails ([string]$Path, [System.Management.Automation.Language.FunctionDefinitionAST]$Raw, [Bool]$UseTitleCase) {
        $this.Definition = $Raw;
        $this.Path = Resolve-FilePath -Path $path -NoAmbiguous
        $this.Source = $this.Path.Split([IO.Path]::DirectorySeparatorChar)[-2]
        $this.SetCommands($UseTitleCase); $this.Module = Get-Module -Name $this.Source -ErrorAction Ignore
        $this.SetName($(if ($UseTitleCase) { [PsImport]::ToTitleCase($this.Definition.name) } else { $this.Definition.name }))
        $this.ScriptBlock = [scriptBlock]::Create("$($this.Definition.Extent.Text -replace '(?<=^function\s)(?!script:)', 'script:')")
    }
    FunctionDetails ([string]$Path, [System.Management.Automation.Language.FunctionDefinitionAST]$Raw, [string[]]$NamesToExculde, [Bool]$UseTitleCase) {
        $this.Definition = $Raw;
        $this.Path = Resolve-FilePath -Path $path -NoAmbiguous
        $this.Source = $this.Path.Split([IO.Path]::DirectorySeparatorChar)[-2]
        $this.SetCommands($NamesToExculde, $UseTitleCase); $this.Module = Get-Module -Name $this.Source -ErrorAction Ignore
        $this.SetName($(if ($UseTitleCase) { [PsImport]::ToTitleCase($this.Definition.name) } else { $this.Definition.name }))
        $this.ScriptBlock = [scriptBlock]::Create("$($this.Definition.Extent.Text -replace '(?<=^function\s)(?!script:)', 'script:')")
    }
    [FunctionDetails] Static Create([string]$path, [System.Management.Automation.Language.FunctionDefinitionAST]$RawAST, [bool]$UseTitleCase) {
        $res = [FunctionDetails]::New($path, $RawAST, $UseTitleCase)
        [void][PsImport]::Record($res); return $res
    }
    [FunctionDetails] Static Create([string]$path, [System.Management.Automation.Language.FunctionDefinitionAST]$RawAST, [string[]]$NamesToExculde, [bool]$UseTitleCase) {
        $res = [FunctionDetails]::New($path, $RawAST, $NamesToExculde, $UseTitleCase)
        [void][PsImport]::Record($res); return $res
    }
    hidden [void] SetName([string]$text) {
        [ValidateNotNullOrEmpty()]$text = $text
        $text = switch ($true) {
            $text.StartsWith('script:') { $text.Substring(7); break }
            $text.StartsWith('local:') { $text.Substring(6); break }
            Default { $text }
        }
        $this.Name = $text
    }
    hidden [void] SetCommands ([bool]$UseTitleCase) {
        $this.SetCommands(@(), $UseTitleCase)
    }
    hidden [void] SetCommands ([string[]]$ExclusionList, [Bool]$UseTitleCase) {
        $t = $this.Definition.findall({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)
        if ($t.Count -le 0 ) { return }
        ($t.GetCommandName() | Select-Object -Unique).Foreach({
                $Command = if ($UseTitleCase ) { [PsImport]::ToTitleCase($_) } else { $_ };
                if ($ExclusionList -contains $Command) { continue };
                $this.Commands.Add($Command)
            }
        )
    }
}
#endregion Classes

#region    Functions
function Import-Function {
    <#
    .SYNOPSIS
        Import functions from other scripts into the current script.
    .DESCRIPTION
        Close to javascript's ESmodule import functionality.
        Features:
        + can import many functions at once
        + Support wildcards. See examples.
    .NOTES
        Caution: Not tested well.
        Inspiration: https://gist.github.com/alainQtec/71123a1d28f37eaa49fd032ba0248650
    .LINK
        https://github.com/alainQtec/devHelper.PsImport/blob/main/devHelper.PsImport.psm1
    .EXAMPLE
        Import fnName1, fnName2 -From '/relative/path/to/script.ps1'
        # Imports the functions fnName1 fnName2

    .EXAMPLE
        Import * -from '/relative/path/to/script.ps1'
        # Using wildcards for names: All functions in the file get loaded in current script scope.

        Import * -from '/relative/path/to/fileNamedlikeabc*.ps1'
        # Import all functions in files that look kike ileNamedlikeabc
    #>
    [CmdletBinding(DefaultParameterSetName = 'Names')]
    [Alias("Import", "require")]
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
        [Alias('f', 'From')]
        [string[]]$path,

        # Minimum version of function to import
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'Name')]
        [ValidateNotNull()][Alias('MinVersion')]
        [version]$Version
    )

    begin {
        [string[]]$fnNames = if ($PSCmdlet.ParameterSetName -eq 'Name') { $Name } else { $Names }
        $functions = @(); if ($path.Count -eq 1) { [string]$path = $path[0] }
    }
    process {
        foreach ($n in $fnNames) {
            $functions += [PsImport]::GetFunction($n, $path)
        }
        foreach ($function in $functions) {
            . $function.scriptblock
        }
    }
}
function Resolve-FilePath {
    <#
    .SYNOPSIS
        Resolve FilePath
    .DESCRIPTION
        A longer description of the function, its purpose, common use cases, etc.
    .NOTES
        Only Created to work with the "devHelper.PsImport" module. (Its not tested for other use cases)
    .LINK
        https://github.com/alainQtec/devHelper/blob/main/Private/devHelper.PsImport/devHelper.PsImport.psm1
    .EXAMPLE
        Resolve-FilePath *
        will list fullNames of files in current location; thus [psimport]::ParseFile("*") will parse any powershell file in current location.
    #>
    [CmdletBinding(DefaultParameterSetName = 's')]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 's')]
        [ValidateNotNullOrEmpty()][string]$Path,
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ParameterSetName = 'm')]
        [ValidateNotNullOrEmpty()][string[]]$FilePaths,
        [switch]$throwOnFailure = $false,
        [switch]$NoAmbiguous
    )

    begin {
        $paths = @(); $resolved = @();
        $paths += if ($PSCmdlet.ParameterSetName.Equals('s')) { @($Path) } else { $FilePaths }
    }
    process {
        forEach ($p in $paths) {
            $(if ($p.Contains('*')) {
                    $(Get-Item $p).Where({ $_.Attributes.ToString() -ne 'Directory' }).FullName
                } else {
                    $resolvedPaths = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($p);
                    $existingPaths = $resolvedPaths | Where-Object { [IO.Path]::Exists($_) };
                    $resolvedPaths, $error_Msg = switch ($true) {
                        ($existingPaths.Count -gt 1) { if ($NoAmbiguous) { $existingPaths[0], "Path '$p' is ambiguous: $($existingPaths -join ', ')" } else { $existingPaths, $null } ; break }
                        ($existingPaths.Count -eq 0) { $null, "Path '$p' not found"; break }
                        Default { $existingPaths, $null }
                    }; if ($error_Msg) { if ($throwOnFailure) { throw [System.Management.Automation.ItemNotFoundException]::new($error_Msg) } else { Write-Warning -Message $error_Msg } }
                    $resolvedPaths
                }
            ).Foreach({ $resolved += $_ })
        }
        if ($resolved.Count -gt 1 -and $NoAmbiguous) {
            $error_Msg = 'Resolved to Multiple paths'
            if ($throwOnFailure) {
                throw $error_Msg
            } else {
                Write-Warning -Message $error_Msg
            }
        }
    }

    end {
        return $resolved
    }
}
# endregion Functions
$Private = Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Private')) -Filter "*.ps1" -ErrorAction SilentlyContinue
$Public = Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Public')) -Filter "*.ps1" -ErrorAction SilentlyContinue
# Load dependencies
$PrivateModules = [string[]](Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Private')) -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } | Select-Object -ExpandProperty FullName)
if ($PrivateModules.Count -gt 0) {
    foreach ($Module in $PrivateModules) {
        Try {
            Import-Module $Module -ErrorAction Stop
        } Catch {
            Write-Error "Failed to import module $Module : $_"
        }
    }
}
# Dot source the files
foreach ($Import in ($Public + $Private)) {
    Try {
        . $Import.fullname
    } Catch {
        Write-Warning "Failed to import function $($Import.BaseName): $_"
        $host.UI.WriteErrorLine($_)
    }
}
# Export Public Functions
$Public | ForEach-Object { Export-ModuleMember -Function $_.BaseName }
#Export-ModuleMember -Alias @('<Aliases>')