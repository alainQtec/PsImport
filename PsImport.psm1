using namespace System.Management.Automation.Language
#region    Classes
Class PsImport {
    static [System.Collections.Generic.List[string]] $ExcludedNames
    static [System.Collections.Generic.Dictionary[string, FunctionDetails]] $Functions # Dictionary of Functions that have already been parsed, so we won't have to do it over again (for performance reasons).
    static [FunctionDetails[]] GetFunctions([Query[]]$FnNames) { return [PsImport]::GetFunctions($FnNames, $false) }
    static [FunctionDetails[]] GetFunctions([Query[]]$FnNames, [bool]$throwOnFailure) {
        [ValidateNotNullOrEmpty()][Query[]]$FnNames = $FnNames;
        $res = @(); $_FnNames = @()
        foreach ($Fn in $FnNames) {
            $_FnNames += switch ($true) {
                $Fn.Text.Equals('*') { foreach ($Name in [PsImport]::GetFnNames()) { $res += [PsImport]::GetFunctions($Name) } ; break }
                $Fn.Text.Contains('*') {
                    $AllNames = [PsImport]::GetFnNames(); $Fn_Names = @($AllNames | Where-Object { $_ -like $Fn.Text });
                    if (($Fn_Names | Where-Object { $_ -notin $AllNames }).Count -gt 0 -and $throwOnFailure) {
                        throw [System.Management.Automation.ItemNotFoundException]::New($($Fn_Names -join ', '))
                    }; $Fn_Names; break
                }
                ([PsImport]::IsValidSource($FnNames, $false)) { $(Get-Command -CommandType Function | Where-Object { $_.Source -eq "$($Fn.Text)" } | Select-Object -ExpandProperty Name); break }
                Default { $Fn.Text }
            }
        }
        if ($res.Count -ne 0) { return $res }
        foreach ($Name in $_FnNames) {
            if ([bool]$(try { [PsImport]::Functions.Keys.Contains($Name) } catch { $false })) { $res += [PsImport]::Functions["$Name"]; continue }
            $c = Get-Command $Name -CommandType Function -ErrorAction Ignore
            if ($null -eq $c) { continue }
            [string]$fn = $("function script:$Name {`n" + $((((($c | Format-List) | Out-String) -Split ('Definition  :')) -split ('CommandType : Function')) -split ("Name        : $($Name)")).TrimEnd().Replace('# .EXTERNALHELP', '# EXTERNALHELP').Trim() + "`n}")
            $res += [FunctionDetails]::New($c.Module.Path, $Name, [scriptblock]::Create("$fn"))
        }
        if ($res.Count -eq 0) {
            $_Message = "Could not find function(s). Named: $($FnNames -join ', ')"
            if ($throwOnFailure) { throw [System.Management.Automation.ItemNotFoundException]::New($_Message) }
            $(Get-Variable -Name host).Value.UI.WriteWarningLine("$_Message")
        }
        return $res
    }
    static [FunctionDetails[]] GetFunctions([Query[]]$FnNames, [string[]]$FilePaths) {
        return [PsImport]::GetFunctions($FnNames, $FilePaths, $false)
    }
    static [FunctionDetails[]] GetFunctions([Query[]]$FnNames, [string[]]$FilePaths, [bool]$throwOnFailure) {
        [ValidateNotNullOrEmpty()][string[]]$FilePaths = $FilePaths; [ValidateNotNullOrEmpty()][Query[]]$FnNames = $FnNames
        $result = @(); $_Functions = @(); $_FilePaths = @(); [string[]]$PathsToSearch = @();
        foreach ($line in $FilePaths) {
            if ([string]::IsNullOrWhiteSpace("$line")) { continue }
            if ([Regex]::IsMatch("$line", '^https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(:[0-9]+)?\/?.*$')) {
                $PathsToSearch += "$line"; continue
            }
            $PathsToSearch += Resolve-FilePath "$line" -Extensions '.ps1', '.psm1'
        }
        foreach ($path in $PathsToSearch) {
            if (![string]::IsNullOrWhiteSpace("$Path")) {
                $path = [PsImport]::ParseLink($path)
                if (!$path.Scheme.IsValid) {
                    throw [System.IO.InvalidDataException]::New("'$($path.FullName)' is not a valid filePath or HTTPS URL.")
                }
                if ($path.Scheme.IsGistUrl) {
                    Write-Verbose "Use Ciphertron github functions"
                    Get-GistContent -
                    Pause
                }
                if ([Regex]::IsMatch($path.FullName, '^https:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(:[0-9]+)?\/?.*$')) {
                    $outFile = [PsImport]::DownloadFile($path.FullName, $([IO.FileInfo]::New([IO.Path]::ChangeExtension([IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName()), '.ps1'))).FullName);
                    $_FilePaths += $outFile.FullName; Continue
                }; $_FilePaths += $path.FullName
            }
        }
        if ($_FilePaths.count -eq 0) {
            if ($throwOnFailure) { throw [System.IO.FileNotFoundException]::New("$FilePaths") }
            return $_Functions #still null
        }
        $_FilePaths = $_FilePaths | Sort-Object -Unique
        foreach ($file in $_FilePaths) {
            $_Functions += [PsImport]::ParseFile($file)
        }
        if (!$FnNames.Text.Contains('*')) {
            foreach ($q in $FnNames) {
                if ($q.Text.Contains('*')) {
                    $result += $_Functions.Where({ $_.Name -like $q.Text })
                    Continue
                }; $result += $_Functions.Where({ $_.Name -eq $q.Text })
            }
        } else {
            $result += $_Functions
        }
        $result = $result | Sort-Object -Property Name -Unique
        return $result
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
        $sources = [PsImport]::GetCommandSources()
        return $(Get-Command -CommandType Function | Where-Object { $_.Source -in $sources }).Name -as [string[]]
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
        $FnDetails = @(); $Paths = (Resolve-FilePath -Paths $Path -throwOnFailure:$false).Where({
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
    static [psobject] ParseLink([string]$text) {
        [ValidateNotNullOrEmpty()][string]$text = $text
        $uri = $text -as 'Uri'; if ($uri -isnot [Uri]) {
            throw [System.InvalidOperationException]::New("Could not create uri from text '$text'.")
        }; $Scheme = $uri.Scheme
        if ([regex]::IsMatch($text, '^(\/[a-zA-Z0-9_-]+)+|([a-zA-Z]:\\(((?![<>:"\/\\|?*]).)+\\?)*((?![<>:"\/\\|?*]).)+)$')) {
            if ($text.ToCharArray().Where({ $_ -in [IO.Path]::InvalidPathChars }).Count -eq 0) {
                $Scheme = 'file'
            } else {
                Write-Debug "'$text' has invalidPathChars in it !" -Debug
            }
        }
        $IsValid = $Scheme -in @('file', 'https')
        $IsGistUrl = [Regex]::IsMatch($text, "^https://gist.github.com/[a-z0-9]+(?:/[a-z0-9]+)?$")
        $OutptObject = [pscustomobject]@{
            FullName = $text
            Scheme   = [PSCustomObject]@{
                Name      = $Scheme
                IsValid   = $IsValid
                IsGistUrl = $IsGistUrl
            }
        }
        return $OutptObject
    }
    static [IO.FileInfo] DownloadFile([uri]$url) {
        # No $outFile so we create ones ourselves, and use suffix to prevent duplicaltes
        $randomSuffix = [Guid]::NewGuid().Guid.subString(15).replace('-', [string]::Join('', (0..9 | Get-Random -Count 1)))
        return [PsImport]::DownloadFile($url, "$(Split-Path $url.AbsolutePath -Leaf)_$randomSuffix");
    }
    static [IO.FileInfo] DownloadFile([uri]$url, [string]$outFile) {
        return [PsImport]::DownloadFile($url, $outFile, $false)
    }
    static [IO.FileInfo] DownloadFile([uri]$url, [string]$outFile, [bool]$Force) {
        [ValidateNotNullOrEmpty()][uri]$url = [uri]$url;
        $outFile = [PsImport]::GetUnResolvedPath($outFile);
        if ([System.IO.Directory]::Exists($outFile)) {
            throw [InvalidOperationException]::new("outFile", "Please provide valid file path, not a directory.")
        }
        if ((Test-Path -Path $outFile -PathType Leaf -ErrorAction Ignore)) {
            if (!$Force) { throw "$outFile already exists" }
            Remove-Item $outFile -Force -ErrorAction Ignore | Out-Null
        }
        $stream = $null; $fileStream = $null; $name = Split-Path $url -Leaf;
        $request = [System.Net.HttpWebRequest]::Create($url)
        $request.UserAgent = "Mozilla/5.0"
        $response = $request.GetResponse()
        $contentLength = $response.ContentLength
        $stream = $response.GetResponseStream()
        $buffer = New-Object byte[] 1024
        $fileStream = [System.IO.FileStream]::new($outFile, [System.IO.FileMode]::CreateNew)
        $totalBytesReceived = 0
        $totalBytesToReceive = $contentLength
        while ($totalBytesToReceive -gt 0) {
            $bytesRead = $stream.Read($buffer, 0, 1024)
            $totalBytesReceived += $bytesRead
            $totalBytesToReceive -= $bytesRead
            $fileStream.Write($buffer, 0, $bytesRead)
            $percentComplete = [int]($totalBytesReceived / $contentLength * 100)
            Write-Progress -Activity "Downloading $name to $Outfile" -Status "Progress: $percentComplete%" -PercentComplete $percentComplete
        }
        try { Invoke-Command -ScriptBlock { $stream.Close(); $fileStream.Close() } -ErrorAction SilentlyContinue } catch { $null }
        return (Get-Item $outFile)
    }
    static hidden [string[]] GetCommandSources() {
        [string[]]$availableSources = @(Get-Command -CommandType Function | Select-Object Source -Unique).Source | Where-Object { $_.Length -gt 0 }
        return $availableSources
    }
    static [string] GetResolvedPath([string]$Path) {
        return [PsImport]::GetResolvedPath($((Get-Variable ExecutionContext).Value.SessionState), $Path)
    }
    static [string] GetResolvedPath([System.Management.Automation.SessionState]$session, [string]$Path) {
        $paths = $session.Path.GetResolvedPSPathFromPSPath($Path);
        if ($paths.Count -gt 1) {
            throw [System.IO.IOException]::new([string]::Format([cultureinfo]::InvariantCulture, "Path {0} is ambiguous", $Path))
        } elseif ($paths.Count -lt 1) {
            throw [System.IO.IOException]::new([string]::Format([cultureinfo]::InvariantCulture, "Path {0} not Found", $Path))
        }
        return $paths[0].Path
    }
    static [string] GetUnResolvedPath([string]$Path) {
        return [PsImport]::GetUnResolvedPath($((Get-Variable ExecutionContext).Value.SessionState), $Path)
    }
    static [string] GetUnResolvedPath([System.Management.Automation.SessionState]$session, [string]$Path) {
        return $session.Path.GetUnresolvedProviderPathFromPSPath($Path)
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
class Query: Microsoft.PowerShell.Cmdletization.QueryBuilder {
    [ValidateNotNullOrEmpty()][string]$text
    Query() {}
    Query([string]$text) {
        $this.Text = $text
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
foreach ($file in ($Public, $Private)) {
    Try {
        . $file.fullname
    } Catch {
        Write-Warning "Failed to import function $($Import.BaseName): $_"
        $host.UI.WriteErrorLine($_)
    }
}
# Export Public Functions
$Public | ForEach-Object { Export-ModuleMember -Function $_.BaseName }
Export-ModuleMember -Alias @('Import', 'require')