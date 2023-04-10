<#
.SYNOPSIS
    A custom buildScript for the module PsImport
.DESCRIPTION
    A longer description of the function, its purpose, common use cases, etc.
.LINK
    Specify a URI to a help page, this will show when Get-Help -Online is used.
.EXAMPLE
    .\build.ps1 -Task deploy
#>
[cmdletbinding(DefaultParameterSetName = 'task')]
param(
    # $Tasks = @('Init', 'Clean', 'Compile', 'Import', 'Test', 'Deploy')
    [parameter(Position = 0, ParameterSetName = 'task')]
    [ValidateScript({
            $task_seq = [string[]]$_; $IsValid = $true
            $Tasks = @('Init', 'Clean', 'Compile', 'Import', 'Test', 'Deploy')
            foreach ($name in $task_seq) {
                $IsValid = $IsValid -and ($name -in $Tasks)
            }
            if ($IsValid) {
                return $true
            } else {
                throw "ValidSet: $($Tasks -join ', ')."
            }
        }
    )
    ][ValidateNotNullOrEmpty()]
    [string[]]$Task = @('Init', 'Clean', 'Compile', 'Import'),

    [parameter(ParameterSetName = 'help')]
    [switch]$Help,

    [switch]$UpdateModules
)

Begin {
    #Requires -RunAsAdministrator
    if ($null -ne ${env:=::}) { Throw 'Please Run this script as Administrator' }
    #region    Variables
    [Environment]::SetEnvironmentVariable('IsAC', $(if (![string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable('GITHUB_WORKFLOW'))) { '1' } else { '0' }), [System.EnvironmentVariableTarget]::Process)
    [Environment]::SetEnvironmentVariable('IsCI', $(if (![string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable('TF_BUILD'))) { '1' }else { '0' }), [System.EnvironmentVariableTarget]::Process)
    [Environment]::SetEnvironmentVariable('RUN_ID', $(if ([bool][int]$env:IsAC) { [Environment]::GetEnvironmentVariable('GITHUB_RUN_ID') }else { [Guid]::NewGuid().Guid.substring(0, 21).replace('-', [string]::Join('', (0..9 | Get-Random -Count 1))) + '_' }), [System.EnvironmentVariableTarget]::Process);
    $dataFile = [System.IO.FileInfo]::new([IO.Path]::Combine($PSScriptRoot, 'en-US', 'PsImport.strings.psd1'))
    if (!$dataFile.Exists) { throw [System.IO.FileNotFoundException]::new('Unable to find the LocalizedData file.', 'PsImport.strings.psd1') }
    $script:localizedData = [scriptblock]::Create("$([IO.File]::ReadAllText($dataFile))").Invoke() # same as "Get-LocalizedData -DefaultUICulture 'en-US'" but the cmdlet is not always installed
    #region    ScriptBlocks
    $script:PSake_ScriptBlock = [scriptblock]::Create({
            # PSake makes variables declared here available in other scriptblocks
            Properties {
                # Find the build folder based on build system
                $ProjectRoot = [Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectPath')
                if (-not $ProjectRoot) {
                    if ($pwd.Path -like "*ci*") {
                        Set-Location ..
                    }
                    $ProjectRoot = $pwd.Path
                }
                $outputDir = [Environment]::GetEnvironmentVariable($env:RUN_ID + 'BuildOutput')
                $Timestamp = Get-Date -UFormat "%Y%m%d-%H%M%S"
                $PSVersion = $PSVersionTable.PSVersion.ToString()
                $outputModDir = [IO.path]::Combine([Environment]::GetEnvironmentVariable($env:RUN_ID + 'BuildOutput'), [Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName'))
                $tests = "$projectRoot\Tests"
                $lines = ('-' * 70)
                $Verbose = @{}
                $TestFile = "TestResults_PS$PSVersion`_$TimeStamp.xml"
                $outputModVerDir = [IO.path]::Combine([Environment]::GetEnvironmentVariable($env:RUN_ID + 'BuildOutput'), [Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName'), [Environment]::GetEnvironmentVariable($env:RUN_ID + 'BuildNumber'))
                $PathSeperator = [IO.Path]::PathSeparator
                $DirSeperator = [IO.Path]::DirectorySeparatorChar
                if ([Environment]::GetEnvironmentVariable($env:RUN_ID + 'CommitMessage') -match "!verbose") {
                    $Verbose = @{Verbose = $True }
                }
                $null = @($tests, $Verbose, $TestFile, $outputDir, $outputModDir, $outputModVerDir, $lines, $DirSeperator, $PathSeperator)
                $null = Invoke-Command -NoNewScope -ScriptBlock {
                    $l = [IO.File]::ReadAllLines([IO.Path]::Combine($([Environment]::GetEnvironmentVariable($env:RUN_ID + 'BuildScriptPath')), 'build.ps1'))
                    $t = New-Item $([IO.Path]::GetTempFileName().Replace('.tmp', '.ps1'))
                    Set-Content -Path "$($t.FullName)" -Value $l[$l.IndexOf('    #region    BuildHelper_Functions')..$l.IndexOf('    #endregion BuildHelper_Functions')] -Encoding UTF8 | Out-Null; . $t;
                    Remove-Item -Path $t.FullName
                }
            }
            FormatTaskName ({
                    param($String)
                    "$((Write-Heading "Executing task: {0}" -PassThru) -join "`n")" -f $String
                }
            )

            #Task Default -Depends Init,Test,Build,Deploy
            Task default -depends Test

            Task Init {
                Set-Location $ProjectRoot
                Write-Verbose "Build System Details:"
                Write-Verbose "$((Get-ChildItem Env: | Where-Object {$_.Name -match "^(BUILD_|SYSTEM_|BH)"} | Sort-Object Name | Format-Table Name,Value -AutoSize | Out-String).Trim())"

                Write-Verbose "Module Build version: $([Environment]::GetEnvironmentVariable($env:RUN_ID + 'BuildNumber'))"
                'Pester' | ForEach-Object {
                    $m = Get-Module $_ -ListAvailable -ErrorAction SilentlyContinue
                    if ($null -ne $m) {
                        Import-Module $(($m | Sort-Object Version -Descending)[0].Path) -Verbose:$false -ErrorAction Stop -Force
                    } else {
                        Install-Module $_ -Repository PSGallery -Scope CurrentUser -AllowClobber -SkipPublisherCheck -Confirm:$false -ErrorAction Stop -Force
                        Import-Module $_ -Verbose:$false -ErrorAction Stop -Force
                    }
                }
            } -description 'Initialize build environment'

            Task clean -depends Init {
                Remove-Module $([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName')) -Force -ErrorAction SilentlyContinue
                if (Test-Path -Path $outputDir -PathType Container -ErrorAction SilentlyContinue) {
                    Write-Verbose "Cleaning Previous build Output ..."
                    Get-ChildItem -Path $outputDir -Recurse -Force | Remove-Item -Force -Recurse
                }
                "    Cleaned previous Output directory [$outputDir]"
            } -description 'Cleans module output directory'

            Task Compile -depends Clean {
                Write-Verbose "Create module Output directory"
                New-Item -Path $outputModVerDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
                $ModuleManifest = [IO.FileInfo]::New([Environment]::GetEnvironmentVariable($env:RUN_ID + 'PSModuleManifest'))
                Write-Verbose "Add Module files ..."
                try {
                    @(
                        "en-US"
                        "Private"
                        "Public"
                        "LICENSE"
                        "$($ModuleManifest.Name)"
                        "$([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName')).psm1"
                    ).ForEach({ Copy-Item -Recurse -Path $([IO.Path]::Combine($([Environment]::GetEnvironmentVariable($env:RUN_ID + 'BuildScriptPath')), $_)) -Destination $([Environment]::GetEnvironmentVariable($env:RUN_ID + 'PSModulePath')) })
                } catch {
                    throw $_
                }
                if (!$ModuleManifest.Exists) { throw [System.IO.FileNotFoundException]::New('Could Not Create Module Manifest!') }
                $functionsToExport = @(); $publicFunctionsPath = [IO.Path]::Combine([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectPath'), "Public")
                if (Test-Path $publicFunctionsPath -PathType Container -ErrorAction SilentlyContinue) {
                    Get-ChildItem -Path $publicFunctionsPath -Filter "*.ps1" -Recurse -File | ForEach-Object {
                        $functionsToExport += $_.BaseName
                    }
                }
                $manifestContent = Get-Content -Path $ModuleManifest -Raw
                $publicFunctionNames = Get-ChildItem -Path $publicFunctionsPath -Filter "*.ps1" | Select-Object -ExpandProperty BaseName

                Write-Verbose -Message "Editing $($ModuleManifest.Name) ..."
                # Using .Replace() is Better than Update-ModuleManifest as this does not destroy the Indentation in the Psd1 file.
                $manifestContent = $manifestContent.Replace(
                    "'<FunctionsToExport>'", $(if ((Test-Path -Path $publicFunctionsPath) -and $publicFunctionNames.count -gt 0) { "'$($publicFunctionNames -join "',`n        '")'" }else { $null })
                ).Replace(
                    "<ModuleVersion>", $([Environment]::GetEnvironmentVariable($env:RUN_ID + 'BuildNumber'))
                ).Replace(
                    "<ReleaseNotes>", $([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ReleaseNotes'))
                ).Replace(
                    "<Year>", ([Datetime]::Now.Year)
                )
                $manifestContent | Set-Content -Path $ModuleManifest
                if ((Get-ChildItem $outputModVerDir | Where-Object { $_.Name -eq "$($([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName'))).psd1" }).BaseName -cne $([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName'))) {
                    "    Renaming manifest to correct casing"
                    Rename-Item (Join-Path $outputModVerDir "$($([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName'))).psd1") -NewName "$($([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName'))).psd1" -Force
                }
                "    Created compiled module at [$outputModDir]"
                "    Output version directory contents"
                Get-ChildItem $outputModVerDir | Format-Table -AutoSize
            } -description 'Compiles module from source'

            Task Import -depends Compile {
                '    Testing import of the Compiled module.'
                Test-ModuleManifest -Path $([Environment]::GetEnvironmentVariable($env:RUN_ID + 'PSModuleManifest'))
                Import-Module $([Environment]::GetEnvironmentVariable($env:RUN_ID + 'PSModuleManifest'))
            } -description 'Imports the newly compiled module'

            Task Test -depends Init {
                '    Importing Pester'
                Import-Module Pester -Verbose:$false -Force -ErrorAction Stop
                Push-Location $([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectPath'))
                $origModulePath = $Env:PSModulePath
                if ($Env:PSModulePath.split($pathSeperator) -notcontains $outputDir ) {
                    $Env:PSModulePath = ($outputDir + $pathSeperator + $origModulePath)
                }
                Remove-Module $([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName')) -ErrorAction SilentlyContinue -Verbose:$false
                Import-Module $outputModDir -Force -Verbose:$false
                $test_Script = [IO.FileInfo]::New('Test-Module.ps1')
                if (!$test_Script.Exists) { throw [System.IO.FileNotFoundException]::New($test_Script.FullName) }
                $TestResults = & $test_Script
                '    Pester invocation complete!'
                if ($TestResults.FailedCount -gt 0) {
                    $TestResults | Format-List
                    Write-Error -Message 'One or more Pester tests failed. Build cannot continue!'
                }
                Pop-Location
                $Env:PSModulePath = $origModulePath
            } -description 'Run Pester tests against compiled module'

            Task Deploy -depends Test -description 'Deploy module to PSGallery' -preaction {
                if (($([Environment]::GetEnvironmentVariable($env:RUN_ID + 'BuildSystem')) -eq 'VSTS' -and $([Environment]::GetEnvironmentVariable($env:RUN_ID + 'CommitMessage')) -match '!deploy' -and $([Environment]::GetEnvironmentVariable($env:RUN_ID + 'BranchName')) -eq "main") -or $script:ForceDeploy -eq $true) {
                    if ($null -eq (Get-Module PoshTwit -ListAvailable)) {
                        "    Installing PoshTwit module..."
                        Install-Module PoshTwit -Scope CurrentUser
                    }
                    Import-Module PoshTwit -Verbose:$false
                    # Load the module, read the exported functions, update the psd1 FunctionsToExport
                    $commParsed = [Environment]::GetEnvironmentVariable($env:RUN_ID + 'CommitMessage') | Select-String -Pattern '\sv\d+\.\d+\.\d+\s'
                    if ($commParsed) {
                        $commitVer = $commParsed.Matches.Value.Trim().Replace('v', '')
                    }
                    $CurrentVersion = (Get-Module $([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName'))).Version
                    $galVer = '0.0.1'; if ($moduleInGallery = Find-Module "$([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName'))*" -Repository PSGallery) {
                        $galVer = $moduleInGallery.Version.ToString()
                        "    Current version on the PSGallery is: $galVer"
                    }
                    $galVerSplit = $galVer.Split('.')
                    $nextGalVer = [System.Version](($galVerSplit[0..($galVerSplit.Count - 2)] -join '.') + '.' + ([int]$galVerSplit[-1] + 1))

                    $versionToDeploy = switch ($true) {
                        ($commitVer -and ([System.Version]$commitVer -lt $nextGalVer)) {
                            Write-Host -ForegroundColor Yellow "Version in commit message is $commitVer, which is less than the next Gallery version and would result in an error. Possible duplicate deployment build, skipping module bump and negating deployment"
                            Set-EnvironmentVariable -name ($env:RUN_ID + 'CommitMessage') -Value $([Environment]::GetEnvironmentVariable($env:RUN_ID + 'CommitMessage')).Replace('!deploy', '')
                            $null
                            break
                        }
                        ($commitVer -and ([System.Version]$commitVer -gt $nextGalVer)) {
                            Write-Host -ForegroundColor Green "Module version to deploy: $commitVer [from commit message]"
                            [System.Version]$commitVer
                            break
                        }
                        ($CurrentVersion -ge $nextGalVer) {
                            Write-Host -ForegroundColor Green "Module version to deploy: $CurrentVersion [from manifest]"
                            $CurrentVersion
                            break
                        }
                        ($([Environment]::GetEnvironmentVariable($env:RUN_ID + 'CommitMessage')) -match '!hotfix') {
                            Write-Host -ForegroundColor Green "Module version to deploy: $nextGalVer [commit message match '!hotfix']"
                            $nextGalVer
                            break
                        }
                        ($([Environment]::GetEnvironmentVariable($env:RUN_ID + 'CommitMessage')) -match '!minor') {
                            $minorVers = [System.Version]("{0}.{1}.{2}" -f $nextGalVer.Major, ([int]$nextGalVer.Minor + 1), 0)
                            Write-Host -ForegroundColor Green "Module version to deploy: $minorVers [commit message match '!minor']"
                            $minorVers
                            break
                        }
                        ($([Environment]::GetEnvironmentVariable($env:RUN_ID + 'CommitMessage')) -match '!major') {
                            $majorVers = [System.Version]("{0}.{1}.{2}" -f ([int]$nextGalVer.Major + 1), 0, 0)
                            Write-Host -ForegroundColor Green "Module version to deploy: $majorVers [commit message match '!major']"
                            $majorVers
                            break
                        }
                        Default {
                            Write-Host -ForegroundColor Green "Module version to deploy: $nextGalVer [PSGallery next version]"
                            $nextGalVer
                        }
                    }
                    # Bump the module version
                    if ($versionToDeploy) {
                        try {
                            $manifest = Import-PowerShellDataFile -Path $([Environment]::GetEnvironmentVariable($env:RUN_ID + 'PSModuleManifest'))
                            if ($([Environment]::GetEnvironmentVariable($env:RUN_ID + 'BuildSystem')) -eq 'VSTS' -and -not [String]::IsNullOrEmpty($Env:NugetApiKey)) {
                                $manifestPath = Join-Path $outputModVerDir "$($([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName'))).psd1"
                                if (-not $manifest) {
                                    $manifest = Import-PowerShellDataFile -Path $manifestPath
                                }
                                if ($manifest.ModuleVersion.ToString() -eq $versionToDeploy.ToString()) {
                                    "    Manifest is already the expected version. Skipping manifest version update"
                                } else {
                                    "    Updating module version on manifest to [$($versionToDeploy)]"
                                    Update-Metadata -Path $manifestPath -PropertyName ModuleVersion -Value $versionToDeploy -Verbose
                                }
                                try {
                                    "    Publishing version [$($versionToDeploy)] to PSGallery..."
                                    Publish-Module -Path $outputModVerDir -NuGetApiKey $Env:NugetApiKey -Repository PSGallery -Verbose
                                    "    Deployment successful!"
                                } catch {
                                    $err = $_
                                    Write-BuildError $err.Exception.Message
                                    throw $err
                                }
                            } else {
                                "    [SKIPPED] Deployment of version [$($versionToDeploy)] to PSGallery"
                            }
                            $commitId = git rev-parse --verify HEAD
                            if (![string]::IsNullOrWhiteSpace($Env:GitHubPAT) -and [bool][int]$env:IsAC) {
                                "    Creating Release ZIP..."
                                $zipPath = [System.IO.Path]::Combine($PSScriptRoot, "$($([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName'))).zip")
                                if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
                                Add-Type -Assembly System.IO.Compression.FileSystem
                                [System.IO.Compression.ZipFile]::CreateFromDirectory($outputModDir, $zipPath)
                                "    Publishing Release v$($versionToDeploy.ToString()) @ commit Id [$($commitId)] to GitHub..."
                                $ReleaseNotes = [Environment]::GetEnvironmentVariable($env:RUN_ID + 'ReleaseNotes')
                                $ReleaseNotes += (git log -1 --pretty=%B | Select-Object -Skip 2) -join "`n"
                                $ReleaseNotes += $script:localizedData.ReleaseNotes.Replace('<versionToDeploy>', $versionToDeploy.ToString())
                                Set-EnvironmentVariable -name ('{0}{1}' -f $env:RUN_ID, 'ReleaseNotes') -Value $ReleaseNotes
                                $gitHubParams = @{
                                    VersionNumber    = $versionToDeploy.ToString()
                                    CommitId         = $commitId
                                    ReleaseNotes     = [Environment]::GetEnvironmentVariable($env:RUN_ID + 'ReleaseNotes')
                                    ArtifactPath     = $zipPath
                                    GitHubUsername   = 'alainQtec'
                                    GitHubRepository = [Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName')
                                    GitHubApiKey     = $Env:GitHubPAT
                                    Draft            = $false
                                }
                                Publish-GithubRelease @gitHubParams
                                "    Release creation successful!"
                            } else {
                                "    [SKIPPED] Publishing Release v$($versionToDeploy) @ commit Id [$($commitId)] to GitHub"
                            }
                            if ($([Environment]::GetEnvironmentVariable($env:RUN_ID + 'BuildSystem')) -eq 'VSTS' -and -not [String]::IsNullOrEmpty($Env:TwitterAccessSecret) -and -not [String]::IsNullOrEmpty($Env:TwitterAccessToken) -and -not [String]::IsNullOrEmpty($Env:TwitterConsumerKey) -and -not [String]::IsNullOrEmpty($Env:TwitterConsumerSecret)) {
                                "    Publishing tweet about new release..."
                                $text = "#$($([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName'))) v$($versionToDeploy) is now available on the #PSGallery! https://www.powershellgallery.com/packages/$($([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName')))/$($versionToDeploy.ToString()) #PowerShell"
                                $manifest.PrivateData.PSData.Tags | ForEach-Object {
                                    $text += " #$($_)"
                                }
                                if ($text.Length -gt 280) {
                                    "    Trimming [$($text.Length - 280)] extra characters from tweet text to get to 280 character limit..."
                                    $text = $text.Substring(0, 280)
                                }
                                "    Tweet text: $text"
                                Publish-Tweet -Tweet $text -ConsumerKey $Env:TwitterConsumerKey -ConsumerSecret $Env:TwitterConsumerSecret -AccessToken $Env:TwitterAccessToken -AccessSecret $Env:TwitterAccessSecret
                                "    Tweet successful!"
                            } else {
                                "    [SKIPPED] Twitter update of new release"
                            }
                        } catch {
                            Write-BuildError $_
                        }
                    } else {
                        Write-Host -ForegroundColor Yellow "No module version matched! Negating deployment to prevent errors"
                        Set-EnvironmentVariable -name ($env:RUN_ID + 'CommitMessage') -Value $([Environment]::GetEnvironmentVariable($env:RUN_ID + 'CommitMessage')).Replace('!deploy', '')
                    }
                } else {
                    Write-Host -ForegroundColor Magenta "Build system is not VSTS!"
                }
            }
        }
    )
    $script:PSake_Build = [ScriptBlock]::Create({
            @(
                "Psake"
                "Pester"
                "PSScriptAnalyzer"
            ) | Resolve-Module -UpdateModules -Verbose
            Write-BuildLog "Module Requirements Successfully resolved."
            $null = Set-Content -Path $Psake_BuildFile -Value $PSake_ScriptBlock

            Write-Heading "Invoking psake with task list: [ $($Task -join ', ') ]"
            $psakeParams = @{
                nologo    = $true
                buildFile = $Psake_BuildFile.FullName
                taskList  = $Task
            }
            if ($Task -eq 'TestOnly') {
                Set-Variable -Name ExcludeTag -Scope global -Value @('Module')
            } else {
                Set-Variable -Name ExcludeTag -Scope global -Value $null
            }
            Invoke-psake @psakeParams @verbose
            Remove-Item $Psake_BuildFile -Verbose | Out-Null
        }
    )
    $script:Clean_EnvBuildvariables = [scriptblock]::Create({
            Param (
                [Parameter(Position = 0)]
                [ValidatePattern('\w*')]
                [ValidateNotNullOrEmpty()]
                [string]$build_Id
            )
            if (![string]::IsNullOrWhiteSpace($build_Id)) {
                Write-Heading "CleanUp"
                $OldEnvNames = [Environment]::GetEnvironmentVariables().Keys | Where-Object { $_ -like "$build_Id*" }
                if ($OldEnvNames.Count -gt 0) {
                    foreach ($Name in $OldEnvNames) {
                        Write-BuildLog "Remove env variable $Name"
                        [Environment]::SetEnvironmentVariable($Name, $null)
                    }
                    [Console]::WriteLine()
                } else {
                    Write-BuildLog "No old Env variables to remove; Move on ...`n"
                }
            } else {
                Write-Warning "Invalid RUN_ID! Skipping ...`n"
            }
        }
    )
    #endregion ScriptBlockss
    $Psake_BuildFile = New-Item $([IO.Path]::GetTempFileName().Replace('.tmp', '.ps1'))
    #endregion Variables

    #region    BuildHelper_Functions
    class dotEnv {
        [Array]static Read([string]$EnvFile) {
            $content = Get-Content $EnvFile -ErrorAction Stop
            $res_Obj = [System.Collections.Generic.List[string[]]]::new()
            foreach ($line in $content) {
                if ([string]::IsNullOrWhiteSpace($line)) {
                    Write-Verbose "[GetdotEnv] Skipping empty line"
                    continue
                }
                if ($line.StartsWith("#") -or $line.StartsWith("//")) {
                    Write-Verbose "[GetdotEnv] Skipping comment: $line"
                    continue
                }
            ($m, $d ) = switch -Wildcard ($line) {
                    "*:=*" { "Prefix", ($line -split ":=", 2); Break }
                    "*=:*" { "Suffix", ($line -split "=:", 2); Break }
                    "*=*" { "Assign", ($line -split "=", 2); Break }
                    Default {
                        throw 'Unable to find Key value pair in line'
                    }
                }
                $res_Obj.Add(($d[0].Trim(), $d[1].Trim(), $m));
            }
            return $res_Obj
        }
        static [void] Update([string]$EnvFile, [string]$Key, [string]$Value) {
            [void]($d = [dotenv]::Read($EnvFile) | Select-Object @{l = 'key'; e = { $_[0] } }, @{l = 'value'; e = { $_[1] } }, @{l = 'method'; e = { $_[2] } })
            $Entry = $d | Where-Object { $_.key -eq $Key }
            if ([string]::IsNullOrEmpty($Entry)) {
                throw [System.Exception]::new("key: $Key not found.")
            }
            $Entry.value = $Value; $ms = [PSObject]@{ Assign = '='; Prefix = ":="; Suffix = "=:" };
            Remove-Item $EnvFile -Force; New-Item $EnvFile -ItemType File | Out-Null;
            foreach ($e in $d) { "{0} {1} {2}" -f $e.key, $ms[$e.method], $e.value | Out-File $EnvFile -Append -Encoding utf8 }
        }

        static [void] Set([string]$EnvFile) {
            #return if no env file
            if (!(Test-Path $EnvFile)) {
                Write-Verbose "[setdotEnv] Could not find .env file"
                return
            }

            #read the local env file
            $content = [dotEnv]::Read($EnvFile)
            Write-Verbose "[setdotEnv] Parsed .env file: $EnvFile"
            foreach ($value in $content) {
                switch ($value[2]) {
                    "Assign" {
                        [Environment]::SetEnvironmentVariable($value[0], $value[1], "Process") | Out-Null
                    }
                    "Prefix" {
                        $value[1] = "{0};{1}" -f $value[1], [System.Environment]::GetEnvironmentVariable($value[0])
                        [Environment]::SetEnvironmentVariable($value[0], $value[1], "Process") | Out-Null
                    }
                    "Suffix" {
                        $value[1] = "{1};{0}" -f $value[1], [System.Environment]::GetEnvironmentVariable($value[0])
                        [Environment]::SetEnvironmentVariable($value[0], $value[1], "Process") | Out-Null
                    }
                    Default {
                        throw [System.IO.InvalidDataException]::new()
                    }
                }
            }
        }
    }
    function Set-BuildVariables {
        <#
        .SYNOPSIS
            Prepares build env variables
        .DESCRIPTION
            sets unique build env variables, and auto Cleans Last Builds's Env~ variables when on local pc
            good for cleaning leftover variables when last build fails
        #>
        [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
        param(
            [Parameter(Position = 0)]
            [ValidateNotNullOrEmpty()]
            [Alias('RootPath')]
            [string]$Path,

            [Parameter(Position = 1)]
            [ValidatePattern('\w*')]
            [ValidateNotNullOrEmpty()][Alias('Prefix', 'RUN_ID')]
            [String]$VarNamePrefix
        )

        Process {
            if (![bool][int]$env:IsAC) {
                $LocEnvFile = [IO.FileInfo]::New([IO.Path]::GetFullPath([IO.Path]::Combine($Path, '.env')))
                if (!$LocEnvFile.Exists) {
                    New-Item -Path $LocEnvFile.FullName -ItemType File -ErrorAction Stop
                    Write-BuildLog "Created a new .env file"
                }
                # Set all Default/Preset Env: variables from the .env
                [dotEnv]::Set($LocEnvFile);
                if (![string]::IsNullOrWhiteSpace($env:LAST_BUILD_ID)) {
                    [dotEnv]::Update($LocEnvFile, 'LAST_BUILD_ID', $env:RUN_ID);
                    Get-Item $LocEnvFile -Force | ForEach-Object { $_.Attributes = $_.Attributes -bor "Hidden" }
                    if ($PSCmdlet.ShouldProcess("$Env:ComputerName", "Clean Last Builds's Env~ variables")) {
                        Invoke-Command $Clean_EnvBuildvariables -ArgumentList $env:LAST_BUILD_ID
                    }
                }
            }
            $Version = $script:localizedData.ModuleVersion
            if ($null -eq $Version) { throw [System.ArgumentNullException]::new('version', "Please make sure localizedData.ModuleVersion is not null.") }
            Write-Heading "Set Build Variables for Version: $Version"
            Set-EnvironmentVariable -Name ('{0}{1}' -f $env:RUN_ID, 'BuildStart') -Value $(Get-Date -Format o)
            Set-EnvironmentVariable -Name ('{0}{1}' -f $env:RUN_ID, 'BuildScriptPath') -Value $Path
            Set-Variable -Name BuildScriptPath -Value ([Environment]::GetEnvironmentVariable($env:RUN_ID + 'BuildScriptPath')) -Scope Local -Force
            Set-EnvironmentVariable -Name ('{0}{1}' -f $env:RUN_ID, 'BuildSystem') -Value $(if ([bool][int]$env:IsCI) { "VSTS" }else { [System.Environment]::MachineName })
            Set-EnvironmentVariable -Name ('{0}{1}' -f $env:RUN_ID, 'ProjectPath') -Value $(if ([bool][int]$env:IsCI) { $Env:SYSTEM_DEFAULTWORKINGDIRECTORY }else { $BuildScriptPath })
            Set-EnvironmentVariable -Name ('{0}{1}' -f $env:RUN_ID, 'BranchName') -Value $(if ([bool][int]$env:IsCI) { $Env:BUILD_SOURCEBRANCHNAME }else { $(Push-Location $BuildScriptPath; (git rev-parse --abbrev-ref HEAD).Trim(); Pop-Location) })
            Set-EnvironmentVariable -Name ('{0}{1}' -f $env:RUN_ID, 'CommitMessage') -Value $(if ([bool][int]$env:IsCI) { $Env:BUILD_SOURCEVERSIONMESSAGE }else { $(Push-Location $BuildScriptPath; (git log --format=%B -n 1).Trim(); Pop-Location) })
            Set-EnvironmentVariable -Name ('{0}{1}' -f $env:RUN_ID, 'BuildNumber') -Value $(if ([bool][int]$env:IsCI) { $Env:BUILD_BUILDNUMBER } else { $(if ([string]::IsNullOrWhiteSpace($Version)) { Set-Content $VersionFile -Value '1.0.0.1' -Encoding UTF8 -PassThru }else { $Version }) })
            Set-Variable -Name BuildNumber -Value ([Environment]::GetEnvironmentVariable($env:RUN_ID + 'BuildNumber')) -Scope Local -Force
            Set-EnvironmentVariable -Name ('{0}{1}' -f $env:RUN_ID, 'BuildOutput') -Value $([IO.path]::Combine($BuildScriptPath, "BuildOutput"))
            Set-Variable -Name BuildOutput -Value ([Environment]::GetEnvironmentVariable($env:RUN_ID + 'BuildOutput')) -Scope Local -Force
            Set-EnvironmentVariable -Name ('{0}{1}' -f $env:RUN_ID, 'ProjectName') -Value $script:localizedData.ModuleName
            Set-Variable -Name ProjectName -Value ([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName')) -Scope Local -Force
            Set-EnvironmentVariable -Name ('{0}{1}' -f $env:RUN_ID, 'PSModulePath') -Value $([IO.path]::Combine($BuildOutput, $ProjectName, $BuildNumber))
            Set-EnvironmentVariable -Name ('{0}{1}' -f $env:RUN_ID, 'PSModuleManifest') -Value $([IO.path]::Combine($BuildOutput, $ProjectName, $BuildNumber, "$ProjectName.psd1"))
            Set-EnvironmentVariable -Name ('{0}{1}' -f $env:RUN_ID, 'ModulePath') -Value $(if (![string]::IsNullOrWhiteSpace($Env:PSModuleManifest)) { [IO.Path]::GetDirectoryName($Env:PSModuleManifest) }else { [IO.Path]::GetDirectoryName($BuildOutput) })
            Set-EnvironmentVariable -Name ('{0}{1}' -f $env:RUN_ID, 'ReleaseNotes') -Value $script:localizedData.ReleaseNotes
        }
    }
    function Get-Elapsed {
        $buildstart = [Environment]::GetEnvironmentVariable($ENV:RUN_ID + 'BuildStart')
        $build_date = if ([string]::IsNullOrWhiteSpace($buildstart)) { Get-Date }else { Get-Date $buildstart }
        $elapse_msg = if ([bool][int]$env:IsCI) {
            "[ + $(((Get-Date) - $build_date).ToString())]"
        } else {
            "[$((Get-Date).ToString("HH:mm:ss")) + $(((Get-Date) - $build_date).ToString())]"
        }
        "$elapse_msg{0}" -f (' ' * (30 - $elapse_msg.Length))
    }
    function Install-PsGalleryModule {
        # .SYNOPSIS
        # Installs a PowerShell module even on systems that don't have a working PowerShellGet.
        # .DESCRIPTION
        # For some reason Install-Module fails on Arch. This is a manual workaround to narrow down the sourse of errors.
        [CmdletBinding()]
        [OutputType([IO.FileInfo])]
        param (
            [Parameter(Mandatory = $true)]
            [ValidateScript({ $_ -match '^[a-zA-Z0-9_.-]+$' })]
            [Alias('Name', 'n')]
            [string]$moduleName,

            [Parameter(Mandatory = $false)]
            [ValidateScript({ ($_ -as 'version') -is [version] -or $_ -eq 'latest' })]
            [string]$Version = 'latest',

            [switch]$Passthru
        )
        Begin {
            # Enable TLS1.1/TLS1.2 if they're available but disabled (eg. .NET 4.5)
            $security_protocols = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::SystemDefault
            if ([Net.SecurityProtocolType].GetMember("Tls11").Count -gt 0) { $security_protocols = $security_protocols -bor [Net.SecurityProtocolType]::Tls11 }
            if ([Net.SecurityProtocolType].GetMember("Tls12").Count -gt 0) { $security_protocols = $security_protocols -bor [Net.SecurityProtocolType]::Tls12 }
            [Net.ServicePointManager]::SecurityProtocol = $security_protocols
            $Is_Windows_OS = !(Get-Variable -Name IsWindows -ErrorAction Ignore) -or $IsWindows
            $Get_Module_Path = [scriptblock]::Create({
                    # ie: when [IO.Path]::Combine([environment]::GetEnvironmentVariable('PSModulePath').Split([IO.Path]::PathSeparator)[0], $moduleName) won't cut it!
                    param([string]$Name, [ValidateSet('CurrentUser', 'Machine')][string]$Scope = 'CurrentUser')
                    if ($Is_Windows_OS) {
                        try {
                            $documents_path = [System.Environment]::GetFolderPath('MyDocuments')
                        } catch {
                            $documents_path = Join-Path -Path $env:USERPROFILE -ChildPath 'Documents'
                        }
                        #Is module Folder desktop or core?
                        $module_folder = if ($PSVersionTable.ContainsKey('PSEdition') -and $PSVersionTable.PSEdition -eq 'Core') { 'PowerShell' } else { 'WindowsPowerShell' }
                        $allUsers_path = Join-Path -Path $env:ProgramFiles -ChildPath $module_folder
                        $curr_UserPath = Join-Path -Path $documents_path -ChildPath $module_folder
                    } else {
                        $allUsers_path = Split-Path -Path ([System.Management.Automation.Platform]::SelectProductNameForDirectory('SHARED_MODULES')) -Parent
                        $curr_UserPath = Split-Path -Path ([System.Management.Automation.Platform]::SelectProductNameForDirectory('USER_MODULES')) -Parent
                    }
                    if ($Scope -eq 'Machine') {
                        return [IO.Path]::Combine($allUsers_path, 'Modules', $Name)
                    } else {
                        return [IO.Path]::Combine($curr_UserPath, 'Modules', $Name)
                    }
                }
            )
        }
        Process {
            $Module_Path = $Get_Module_Path.Invoke($moduleName)
            if ([string]::IsNullOrWhiteSpace($Module_Path)) { throw 'Unable To find Module_Path' }
            $version_filter = if ($Version -eq 'latest') { 'IsLatestVersion' } else { "Version eq '$Version'" }
            $response = [string]::Empty; $url = "https://www.powershellgallery.com/api/v2/Packages?`$filter=Id eq '$moduleName' and $version_filter"
            try {
                $response = Invoke-RestMethod -Uri $url -Method Get -Verbose:$false
            } catch {
                $PSCmdlet.ThrowTerminatingError(
                    [System.Management.Automation.ErrorRecord]::new(
                        [System.InvalidOperationException]::new("Failed to find PowerShell Gallery release for '$moduleName' at version '$Version'. $($_.Exception.Message)"), 'RestMethod_Failed',
                        [System.Management.Automation.ErrorCategory]::OperationStopped,
                        $url
                    )
                )
            }
            if ($null -eq $response) {
                $PSCmdlet.ThrowTerminatingError(
                    [System.Management.Automation.ErrorRecord]::new(
                        [System.InvalidOperationException]::new("Module not found in PSGallery repository."), 'Module_Not_Found',
                        [System.Management.Automation.ErrorCategory]::InvalidResult,
                        $moduleName
                    )
                )
            }
            $downloadUrl = $response.content.src
            Write-Host "Installing $moduleName ... " -NoNewline -ForegroundColor DarkCyan
            if (![IO.Path]::Exists($Module_Path)) {
                [ValidateNotNullOrEmpty()][System.IO.DirectoryInfo]$Path = [System.IO.DirectoryInfo]::New($Module_Path)
                $nF = @(); $p = $Path; while (!$p.Exists) { $nF += $p; $p = $p.Parent }
                [Array]::Reverse($nF); $nF | ForEach-Object { $_.Create() }
            }
            $ModuleNupkg = [IO.Path]::Combine($Module_Path, "$moduleName.nupkg")
            Invoke-WebRequest -Uri $downloadUrl -OutFile $ModuleNupkg -Verbose:$false;
            if ($Is_Windows_OS) { Unblock-File -Path $ModuleNupkg }
            Expand-Archive $ModuleNupkg -DestinationPath $Module_Path -Verbose:$false -Force
            # CleanUp
            @('_rels', 'package', "[Content_Types].xml", $ModuleNupkg, "$($moduleName.Tolower()).nuspec" ) | ForEach-Object {
                $Item = [IO.FileInfo]::new([IO.Path]::Combine($Module_Path, $_))
                if ($Item.Attributes -eq [System.IO.FileAttributes]::Directory) {
                    Remove-Item $Item.FullName -Recurse -Force -ErrorAction SilentlyContinue
                } else {
                    Remove-Item $Item.FullName -Force -ErrorAction SilentlyContinue
                }
            }
        }

        end {
            Write-Host " Done." -ForegroundColor Green
            if ($Passthru.IsPresent) {
                return [IO.FileInfo]::new([IO.Path]::Combine($Module_Path, "$moduleName.psd1"))
            }
        }
    }
    function Resolve-Module {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
            [Alias('Name')]
            [string[]]$Names,
            [switch]$UpdateModules
        )
        begin {
            function private:Get-LatestModuleVersion {
                [CmdletBinding()][OutputType([version])]
                param ([Parameter(Mandatory)][string]$Name)
                # access the main module page, and add a random number to trick proxies
                $url = "https://www.powershellgallery.com/packages/$Name/?dummy=$(Get-Random)"
                $request = [System.Net.WebRequest]::Create($url)
                # do not allow to redirect. The result is a "MovedPermanently"
                $version = [version]::new(); $request.AllowAutoRedirect = $false
                try {
                    # [todo] Should -Be a retriable command.
                    # send the request
                    $response = $request.GetResponse()
                    # get back the URL of the true destination page, and split off the version
                    $version = $response.GetResponseHeader("Location").Split("/")[-1] -as [Version]
                    # make sure to clean up
                    $response.Close()
                    $response.Dispose()
                } catch [System.Net.WebException] {
                    throw 'WebException, Please check your Internet.'
                } catch {
                    Write-Warning $_.Exception.Message
                }
                return [version]$version
            }
        }

        process {
            foreach ($moduleName in $Names) {
                Write-Host "Resolving Module [$moduleName]" -ForegroundColor Magenta
                $module = Get-Module -Name $moduleName -ListAvailable -ErrorAction SilentlyContinue
                if ($module) {
                    # Determine latest version on PSGallery and warn us if we're out of date
                    $latestLocalVersion = ($module | Measure-Object -Property Version -Maximum).Maximum -as [version]
                    $latestGalleryVersion = Get-LatestModuleVersion -Name $moduleName
                    if (!$latestGalleryVersion) {
                        Write-Warning "Unable to find module $moduleName. Check your internet connection."
                    } elseif ($latestLocalVersion -lt $latestGalleryVersion -and $UpdateModules.IsPresent) {
                        Write-Verbose -Message "$moduleName installed version [$latestLocalVersion] is outdated. Installing gallery version [$latestGalleryVersion]."
                        Install-PsGalleryModule -Name $moduleName -Version $latestGalleryVersion
                    }
                } else {
                    Write-Verbose -Message "[$moduleName] missing. Installing..."
                    $ModulePsd1 = Install-PsGalleryModule -Name $moduleName -PassThru
                }
                $versionToImport = (Get-Module -Name $moduleName -ListAvailable | Measure-Object -Property Version -Maximum).Maximum
                Write-Verbose -Message "Importing module $moduleName."
                if ($ModulePsd1) {
                    Import-Module $ModulePsd1.FullName
                } else {
                    if (![string]::IsNullOrEmpty($versionToImport)) {
                        Import-Module $moduleName -RequiredVersion $versionToImport
                    } else {
                        Import-Module $moduleName
                    }
                }
            }
        }
    }
    function Write-BuildLog {
        [CmdletBinding()]
        param(
            [parameter(Mandatory, Position = 0, ValueFromRemainingArguments, ValueFromPipeline)]
            [System.Object]$Message,

            [parameter()]
            [Alias('c', 'Command')]
            [Switch]$Cmd,

            [parameter()]
            [Alias('w')]
            [Switch]$Warning,

            [parameter()]
            [Alias('s', 'e')]
            [Switch]$Severe,

            [parameter()]
            [Alias('x', 'nd', 'n')]
            [Switch]$Clean
        )
        Begin {
            if ($PSBoundParameters.ContainsKey('Debug') -and $PSBoundParameters['Debug'] -eq $true) {
                $fg = 'Yellow'
                $lvl = '##[debug]   '
            } elseif ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters['Verbose'] -eq $true) {
                $fg = if ($Host.UI.RawUI.ForegroundColor -eq 'Gray') {
                    'White'
                } else {
                    'Gray'
                }
                $lvl = '##[Verbose] '
            } elseif ($Severe) {
                $fg = 'Red'
                $lvl = '##[Error]   '
            } elseif ($Warning) {
                $fg = 'Yellow'
                $lvl = '##[Warning] '
            } elseif ($Cmd) {
                $fg = 'Magenta'
                $lvl = '##[Command] '
            } else {
                $fg = if ($Host.UI.RawUI.ForegroundColor -eq 'Gray') {
                    'White'
                } else {
                    'Gray'
                }
                $lvl = '##[Info]    '
            }
        }
        Process {
            $fmtMsg = if ($Clean) {
                $Message -split "[\r\n]" | Where-Object { $_ } | ForEach-Object {
                    $lvl + $_
                }
            } else {
                $date = "$(Get-Elapsed) "
                if ($Cmd) {
                    $i = 0
                    $Message -split "[\r\n]" | Where-Object { $_ } | ForEach-Object {
                        $tag = if ($i -eq 0) {
                            'PS > '
                        } else {
                            '  >> '
                        }
                        $lvl + $date + $tag + $_
                        $i++
                    }
                } else {
                    $Message -split "[\r\n]" | Where-Object { $_ } | ForEach-Object {
                        $lvl + $date + $_
                    }
                }
            }
            Write-Host -ForegroundColor $fg $($fmtMsg -join "`n")
        }
    }
    function Write-BuildWarning {
        param(
            [parameter(Mandatory, Position = 0, ValueFromRemainingArguments, ValueFromPipeline)]
            [System.String]$Message
        )
        Process {
            if ([bool][int]$env:IsCI) {
                Write-Host "##vso[task.logissue type=warning; ]$Message"
            } else {
                Write-Warning $Message
            }
        }
    }
    function Write-BuildError {
        param(
            [parameter(Mandatory, Position = 0, ValueFromRemainingArguments, ValueFromPipeline)]
            [System.String]$Message
        )
        Process {
            if ([bool][int]$env:IsCI) {
                Write-Host "##vso[task.logissue type=error; ]$Message"
            }
            Write-Error $Message
        }
    }
    function Set-EnvironmentVariable {
        [CmdletBinding(SupportsShouldProcess = $true)]
        param(
            [parameter(Position = 0)]
            [String]$Name,

            [parameter(Position = 1, ValueFromRemainingArguments)]
            [String[]]$Value
        )
        $FullVal = $Value -join " "
        Write-BuildLog "Setting env variable '$Name' to '$fullVal'"
        Set-Item -Path ([IO.Path]::Combine('Env:', $Name)) -Value $FullVal -Force
    }
    function Invoke-CommandWithLog {
        [CmdletBinding()]
        Param (
            [parameter(Mandatory, Position = 0)]
            [ScriptBlock]$ScriptBlock
        )
        Write-BuildLog -Command ($ScriptBlock.ToString() -join "`n"); $ScriptBlock.Invoke()
    }
    function Write-Heading {
        param(
            [parameter(Position = 0)]
            [String]$Title,

            [parameter(Position = 1)]
            [Switch]$Passthru
        )
        $msgList = @(
            ''
            "##[section] $(Get-Elapsed) $Title"
        ) -join "`n"
        if ($Passthru) {
            $msgList
        } else {
            $msgList | Write-Host -ForegroundColor Cyan
        }
    }
    function Write-EnvironmentSummary {
        param(
            [parameter(Position = 0, ValueFromRemainingArguments)]
            [String]$State
        )
        Write-Heading -Title "Build Environment Summary:`n"
        @(
            $(if ($([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName'))) { "Project : $([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName'))" })
            $(if ($State) { "State   : $State" })
            "Engine  : PowerShell $($PSVersionTable.PSVersion.ToString())"
            "Host OS : $(if($PSVersionTable.PSVersion.Major -le 5 -or $IsWindows){"Windows"}elseif($IsLinux){"Linux"}elseif($IsMacOS){"macOS"}else{"[UNKNOWN]"})"
            "PWD     : $PWD"
            ''
        ) | Write-Host
    }
    function FindHashKeyValue {
        [CmdletBinding()]
        param(
            $SearchPath,
            $Ast,
            [string[]]
            $CurrentPath = @()
        )
        # Write-Debug "FindHashKeyValue: $SearchPath -eq $($CurrentPath -Join '.')"
        if ($SearchPath -eq ($CurrentPath -Join '.') -or $SearchPath -eq $CurrentPath[-1]) {
            return $Ast |
                Add-Member NoteProperty HashKeyPath ($CurrentPath -join '.') -PassThru -Force | Add-Member NoteProperty HashKeyName ($CurrentPath[-1]) -PassThru -Force
        }

        if ($Ast.PipelineElements.Expression -is [System.Management.Automation.Language.HashtableAst] ) {
            $KeyValue = $Ast.PipelineElements.Expression
            foreach ($KV in $KeyValue.KeyValuePairs) {
                $result = FindHashKeyValue $SearchPath -Ast $KV.Item2 -CurrentPath ($CurrentPath + $KV.Item1.Value)
                if ($null -ne $result) {
                    $result
                }
            }
        }
    }
    function Get-ModuleManifest {
        <#
        .SYNOPSIS
            Reads a specific value from a PowerShell metdata file (e.g. a module manifest)
        .DESCRIPTION
            By default Get-ModuleManifest gets the ModuleVersion, but it can read any key in the metadata file
        .EXAMPLE
            Get-ModuleManifest .\Configuration.psd1
            Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines
        .Example
            Get-ModuleManifest .\Configuration.psd1 ReleaseNotes
            Returns the release notes!
        #>
        [CmdletBinding()]
        param(
            # The path to the module manifest file
            [Parameter(ValueFromPipelineByPropertyName = "True", Position = 0)]
            [Alias("PSPath")]
            [ValidateScript({ if ([IO.Path]::GetExtension($_) -ne ".psd1") { throw "Path must point to a .psd1 file" } $true })]
            [string]$Path,

            # The property (or dotted property path) to be read from the manifest.
            # Get-ModuleManifest searches the Manifest root properties, and also the nested hashtable properties.
            [Parameter(ParameterSetName = "Overwrite", Position = 1)]
            [string]$PropertyName = 'ModuleVersion',

            [switch]$Passthru
        )
        Begin {
            $eap = $ErrorActionPreference
            $ErrorActionPreference = "Stop"
            $Tokens = $Null; $ParseErrors = $Null
        }
        Process {
            if (!(Test-Path $Path)) {
                Write-Error -Exception System.Management.Automation.ItemNotFoundException -Message "Can't find file $Path" -ErrorId "PathNotFound,Metadata\Import-Metadata" -Category "ObjectNotFound"
                return
            }
            $Path = Convert-Path $Path
            $AST = [System.Management.Automation.Language.Parser]::ParseFile( $Path, [ref]$Tokens, [ref]$ParseErrors )

            $KeyValue = $Ast.EndBlock.Statements
            $KeyValue = @(FindHashKeyValue $PropertyName $KeyValue)
            if ($KeyValue.Count -eq 0) {
                Write-Error -Exception System.Management.Automation.ItemNotFoundException -Message "Can't find '$PropertyName' in $Path" -ErrorId "PropertyNotFound,Metadata\Get-Metadata" -Category "ObjectNotFound"
                return
            }
            if ($KeyValue.Count -gt 1) {
                $SingleKey = @($KeyValue | Where-Object { $_.HashKeyPath -eq $PropertyName })

                if ($SingleKey.Count -gt 1) {
                    Write-Error -Exception System.Reflection.AmbiguousMatchException -Message ("Found more than one '$PropertyName' in $Path. Please specify a dotted path instead. Matching paths include: '{0}'" -f ($KeyValue.HashKeyPath -join "', '")) -ErrorId "AmbiguousMatch,Metadata\Get-Metadata" -Category "InvalidArgument"
                    return
                } else {
                    $KeyValue = $SingleKey
                }
            }
            $KeyValue = $KeyValue[0]

            if ($Passthru) { $KeyValue } else {
                # # Write-Debug "Start $($KeyValue.Extent.StartLineNumber) : $($KeyValue.Extent.StartColumnNumber) (char $($KeyValue.Extent.StartOffset))"
                # # Write-Debug "End   $($KeyValue.Extent.EndLineNumber) : $($KeyValue.Extent.EndColumnNumber) (char $($KeyValue.Extent.EndOffset))"
                $KeyValue.SafeGetValue()
            }
        }
        End {
            $ErrorActionPreference = $eap
        }
    }
    function Publish-GitHubRelease {
        <#
        .SYNOPSIS
            Publishes a release to GitHub Releases. Borrowed from https://www.herebedragons.io/powershell-create-github-release-with-artifact
        #>
        [CmdletBinding()]
        Param (
            [parameter(Mandatory = $true)]
            [String]$VersionNumber,

            [parameter(Mandatory = $false)]
            [String]$CommitId = 'main',

            [parameter(Mandatory = $true)]
            [String]$ReleaseNotes,

            [parameter(Mandatory = $true)]
            [ValidateScript( { Test-Path $_ })]
            [String]$ArtifactPath,

            [parameter(Mandatory = $true)]
            [String]$GitHubUsername,

            [parameter(Mandatory = $true)]
            [String]$GitHubRepository,

            [parameter(Mandatory = $true)]
            [String]$GitHubApiKey,

            [parameter(Mandatory = $false)]
            [Switch]$PreRelease,

            [parameter(Mandatory = $false)]
            [Switch]$Draft
        )
        $releaseData = @{
            tag_name         = [string]::Format("v{0}", $VersionNumber)
            target_commitish = $CommitId
            name             = [string]::Format("$($([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName'))) v{0}", $VersionNumber)
            body             = $ReleaseNotes
            draft            = [bool]$Draft
            prerelease       = [bool]$PreRelease
        }

        $auth = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($gitHubApiKey + ":x-oauth-basic"))

        $releaseParams = @{
            Uri         = "https://api.github.com/repos/$GitHubUsername/$GitHubRepository/releases"
            Method      = 'POST'
            Headers     = @{
                Authorization = $auth
            }
            ContentType = 'application/json'
            Body        = (ConvertTo-Json $releaseData -Compress)
        }
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $result = Invoke-RestMethod @releaseParams
        $uploadUri = $result | Select-Object -ExpandProperty upload_url
        $uploadUri = $uploadUri -creplace '\{\?name,label\}'
        $artifact = Get-Item $ArtifactPath
        $uploadUri = $uploadUri + "?name=$($artifact.Name)"
        $uploadFile = $artifact.FullName

        $uploadParams = @{
            Uri         = $uploadUri
            Method      = 'POST'
            Headers     = @{
                Authorization = $auth
            }
            ContentType = 'application/zip'
            InFile      = $uploadFile
        }
        $result = Invoke-RestMethod @uploadParams
    }
    #endregion BuildHelper_Functions
}
Process {
    Set-BuildVariables -Path $PSScriptRoot -Prefix $env:RUN_ID
    Write-EnvironmentSummary "Build started"
    Write-Heading "Setting package feeds"
    $PKGRepoHash = @{
        PackageManagement = '1.3.1'
        PowerShellGet     = '2.1.2'
    }
    foreach ($PkgRepoName in $PKGRepoHash.Keys | Sort-Object) {
        Write-BuildLog "Updating $PkgRepoName"
        if ($null -eq (Get-Module $PkgRepoName -ListAvailable | Where-Object { [System.Version]$_.Version -ge [System.Version]($PKGRepoHash[$PkgRepoName]) })) {
            Write-BuildLog "$PkgRepoName is below the minimum required version! Updating ..."
            Install-Module "$PkgRepoName" -MinimumVersion $PKGRepoHash[$PkgRepoName] -Force -AllowClobber -SkipPublisherCheck -Scope CurrentUser -Verbose:$false -ErrorAction SilentlyContinue
        }
    }
    Invoke-CommandWithLog { Get-PackageProvider -Name Nuget -ForceBootstrap -Verbose:$false }
    if (!(Get-PackageProvider -Name Nuget)) {
        Invoke-CommandWithLog { Install-PackageProvider -Name NuGet -Force | Out-Null }
    }
    $null = Import-PackageProvider -Name NuGet -Force
    if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne 'Trusted') {
        Invoke-CommandWithLog { Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -Verbose:$false }
    }
    $host.ui.WriteLine()
    Invoke-CommandWithLog { $PSDefaultParameterValues = @{
            '*-Module:Verbose'            = $false
            'Import-Module:ErrorAction'   = 'Stop'
            'Import-Module:Force'         = $true
            'Import-Module:Verbose'       = $false
            'Install-Module:AllowClobber' = $true
            'Install-Module:ErrorAction'  = 'Stop'
            'Install-Module:Force'        = $true
            'Install-Module:Scope'        = 'CurrentUser'
            'Install-Module:Verbose'      = $false
        }
    }
    $update = @{}
    $verbose = @{}
    if ($PSBoundParameters.ContainsKey('UpdateModules')) {
        $update['UpdateModules'] = $PSBoundParameters['UpdateModules']
    }
    if ($PSBoundParameters.ContainsKey('Verbose')) {
        $verbose['Verbose'] = $PSBoundParameters['Verbose']
    }

    if ($Help) {
        Write-Heading "Getting help"
        Write-BuildLog -c '"psake" | Resolve-Module @update -Verbose'
        'psake' | Resolve-Module @update -Verbose
        Get-PSakeScriptTasks -buildFile $Psake_BuildFile.FullName | Sort-Object -Property Name | Format-Table -Property Name, Description, Alias, DependsOn
    } else {
        Write-Heading "Finalizing build Prerequisites and Resolving dependencies ..."
        if ($([Environment]::GetEnvironmentVariable($env:RUN_ID + 'BuildSystem')) -eq 'VSTS') {
            if ($Task -eq 'Deploy') {
                $MSG = "Task is 'Deploy' and conditions for deployment are:`n" +
                "    + Current build system is VSTS     : $($Env:BUILD_BUILDURI -like 'vstfs:*') [$Env:BUILD_BUILDURI]`n" +
                "    + Current branch is main         : $($Env:BUILD_SOURCEBRANCHNAME -eq 'main') [$Env:BUILD_SOURCEBRANCHNAME]`n" +
                "    + Source is not a pull request     : $($Env:BUILD_SOURCEBRANCH -notlike '*pull*') [$Env:BUILD_SOURCEBRANCH]`n" +
                "    + Commit message matches '!deploy' : $($Env:BUILD_SOURCEVERSIONMESSAGE -match '!deploy') [$Env:BUILD_SOURCEVERSIONMESSAGE]`n" +
                "    + Current PS major version is 5    : $($PSVersionTable.PSVersion.Major -eq 5) [$($PSVersionTable.PSVersion.ToString())]`n" +
                "    + NuGet API key is not null        : $($null -ne $Env:NugetApiKey)`n"
                if (
                    $Env:BUILD_BUILDURI -notlike 'vstfs:*' -or
                    $Env:BUILD_SOURCEBRANCH -like '*pull*' -or
                    $Env:BUILD_SOURCEVERSIONMESSAGE -notmatch '!deploy' -or
                    $Env:BUILD_SOURCEBRANCHNAME -ne 'main' -or
                    $PSVersionTable.PSVersion.Major -ne 5 -or
                    $null -eq $Env:NugetApiKey
                ) {
                    $MSG = $MSG.Replace('and conditions for deployment are:', 'but conditions are not correct for deployment.')
                    $MSG | Write-Host -ForegroundColor Yellow
                    if (($([Environment]::GetEnvironmentVariable($env:RUN_ID + 'CommitMessage')) -match '!deploy' -and $([Environment]::GetEnvironmentVariable($env:RUN_ID + 'BranchName')) -eq "main") -or $script:ForceDeploy -eq $true) {
                        Write-Warning "Force Deploy"
                    } else {
                        "Skipping psake for this job!" | Write-Host -ForegroundColor Yellow
                        exit 0
                    }
                } else {
                    $MSG | Write-Host -ForegroundColor Green
                }
            }
            Invoke-Command -ScriptBlock $PSake_Build
            if ($Task -contains 'Import' -and $psake.build_success) {
                $Project_Name = [Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName')
                $Project_Path = [Environment]::GetEnvironmentVariable($env:RUN_ID + 'BuildOutput')
                Write-Heading "Importing $Project_Name to local scope"
                $Module_Path = [IO.Path]::Combine($Project_Path, $Project_Name);
                Invoke-CommandWithLog { Import-Module $Module_Path -Verbose:$false }
            }
        } else {
            Invoke-Command -ScriptBlock $PSake_Build
            Write-BuildLog "Create a 'local' repository"
            $RepoPath = New-Item -Path "$([IO.Path]::Combine($Env:USERPROFILE, 'LocalPSRepo'))" -ItemType Directory -Force
            Register-PSRepository LocalPSRepo -SourceLocation "$RepoPath" -PublishLocation "$RepoPath" -InstallationPolicy Trusted -ErrorAction SilentlyContinue -Verbose:$false
            Write-Verbose "Verify that the new repository was created successfully"
            $PsRepo = Get-PSRepository LocalPSRepo -Verbose:$false
            if (-not (Test-Path -Path ($PsRepo.SourceLocation) -PathType Container -ErrorAction SilentlyContinue -Verbose:$false)) {
                New-Item -Path $PsRepo.SourceLocation -ItemType Directory -Force | Out-Null
            }
            $ModuleName = [Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName')
            $ModulePath = [IO.Path]::Combine($([Environment]::GetEnvironmentVariable($env:RUN_ID + 'BuildOutput')), $([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName')), $([Environment]::GetEnvironmentVariable($env:RUN_ID + 'BuildNumber')))
            # Publish To LocalRepo
            $ModulePackage = [IO.Path]::Combine($RepoPath.FullName, "${ModuleName}.$([Environment]::GetEnvironmentVariable($env:RUN_ID + 'BuildNumber')).nupkg")
            if ([IO.File]::Exists($ModulePackage)) {
                Remove-Item -Path $ModulePackage -ErrorAction 'SilentlyContinue'
            }
            Write-Heading "Publish to Local PsRepository"
            $RequiredModules = Get-ModuleManifest ([IO.Path]::Combine($ModulePath, "$([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName')).psd1")) RequiredModules -Verbose:$false
            foreach ($Module in $RequiredModules) {
                $md = Get-Module $Module -Verbose:$false; $mdPath = $md.Path | Split-Path
                Write-Verbose "Publish RequiredModule $Module ..."
                Publish-Module -Path $mdPath -Repository LocalPSRepo -Verbose:$false
            }
            Invoke-CommandWithLog { Publish-Module -Path $ModulePath -Repository LocalPSRepo } -Verbose:$false
            # Install Module
            Install-Module $ModuleName -Repository LocalPSRepo
            # Import Module
            if ($Task -contains 'Import' -and $psake.build_success) {
                Write-Heading "Importing $([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName')) to local scope"
                Invoke-CommandWithLog { Import-Module $ModuleName }
            }
            Write-Heading "CleanUp: Uninstall the test module, and delete the LocalPSRepo"
            if ($Task -notcontains 'Import') {
                Uninstall-Module $ModuleName
            }
            $Local_PSRepo = [IO.DirectoryInfo]::new([IO.Path]::Combine($Env:USERPROFILE, 'LocalPSRepo'))
            if ($Local_PSRepo.Exists) {
                Remove-Item "$Local_PSRepo" -Force -Recurse
                if ($null -ne (Get-PSRepository -Name 'LocalPSRepo' -ErrorAction Ignore)) {
                    Unregister-PSRepository 'LocalPSRepo' -Verbose
                }
            }
        }
        Write-EnvironmentSummary "Build finished"
    }
}
End {
    if (![bool][int]$env:IsAC) {
        Invoke-Command $Clean_EnvBuildvariables -ArgumentList $env:RUN_ID
    }
    [Environment]::SetEnvironmentVariable('RUN_ID', $null)
    exit ( [int](!$psake.build_success) )
}