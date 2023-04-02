<#
.SYNOPSIS
    Run Tests
.NOTES
    It is not included in the module.
#>
param (
    [Parameter(Mandatory = $false, Position = 0)]
    [Alias('Module')][string]$ModulePath = $PSScriptRoot,
    # Path Containing Tests
    [Parameter(Mandatory = $false, Position = 1)]
    [Alias('Tests')][string]$TestsPath = [IO.Path]::Combine($PSScriptRoot, 'Tests'),
    [switch]$skipBuildOutputTest,
    [switch]$CleanUp
)
begin {
    $testResults = $null
    $BuildOutDir = [IO.DirectoryInfo]::New([IO.Path]::Combine($PSScriptRoot, 'BuildOutput'))
    $manifestFile = [IO.FileInfo]::New([IO.Path]::Combine($BuildOutDir.FullName, "devHelper.PsImport.psd1"))
    # if (![IO.FileInfo]::New([IO.Path]::Combine($PSScriptRoot, "devHelper.PsImport.psd1")).Exists) { throw [System.IO.FileNotFoundException]::New('Module manifest file Was not Found!') }
    $Resources = [System.IO.DirectoryInfo]::new([IO.Path]::Combine($TestsPath, 'Resources'))
    $resRlPath = [IO.Path]::GetRelativePath($PSScriptRoot, $Resources.FullName)
    $script:fnNames = [System.Collections.Generic.List[string]]::New(); $testFiles = [System.Collections.Generic.List[IO.FileInfo]]::New()
    [void]$testFiles.Add([IO.FileInfo]::New([IO.Path]::Combine($PSScriptRoot, 'Tests', 'devHelper.PsImport.Intergration.Tests.ps1')))
    [void]$testFiles.Add([IO.FileInfo]::New([IO.Path]::Combine($PSScriptRoot, 'Tests', 'devHelper.PsImport.Features.Tests.ps1')))
    [void]$testFiles.Add([IO.FileInfo]::New([IO.Path]::Combine($PSScriptRoot, 'Tests', 'devHelper.PsImport.Module.Tests.ps1')))
    $create_Random_functions = [scriptblock]::Create({
            param ([ValidateRange(1, 10)][int]$Count)
            $prefixes = @('Test-Function', 'Test-Func', 'Test-UtilFunc', 'Test-HelperFunc')
            $suffixes = @('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', 'A', 'B', 'C')
            $result = @(); for ($i = 1; $i -le $Count; $i++) {
                do {
                    $prefix = $prefixes | Get-Random
                    $suffix = $suffixes | Get-Random
                    $functionName = $prefix + $suffix
                } until ($functionName -notin $script:fnNames); [void]$fnNames.Add($functionName)
                $result += [PSCustomObject]@{
                    Name = $functionName
                    code = "function $functionName() {`n    return 'Hello from $functionName'`n}"
                }
            }
            Write-Output $result
        }
    )
}

process {
    # Import-Module $manifestFile
    Write-Host "[+] Generating test files ..." -ForegroundColor Green
    $testFiles | ForEach-Object {
        if ($_.Exists) { Remove-Item -Path $_.FullName -Force };
        New-Item -Path $_.FullName -ItemType File -Force | Out-Null
    }
    if ($Resources.Exists) {
        $Resources.GetFiles().ForEach({ Remove-Item -Path $_.FullName -Force })
    } else {
        New-Item -Path $Resources.FullName -ItemType Directory | Out-Null
    }
    $create_Random_functions.Invoke(4) | ForEach-Object {
        $FileName = $_.Name + '.ps1';
        $FilePath = [IO.Path]::Combine($Resources.FullName, $FileName)
        [void]$testFiles.Add([IO.FileInfo]::New($FilePath))
        Set-Content -Value $_.code -Path $FilePath -Encoding utf8
        Write-Host "    Created $FileName" -ForegroundColor Gray
    }
    1..3 | ForEach-Object {
        $FileName = 'ModuleFile' + $_ + '.psm1'; $code = [string]::Join("`n", $create_Random_functions.Invoke(3).code)
        $FilePath = [IO.Path]::Combine($Resources.FullName, $FileName)
        [void]$testFiles.Add([IO.FileInfo]::New($FilePath))
        Set-Content -Value $code -Path $FilePath -Encoding utf8
        Write-Host "    Created $FileName" -ForegroundColor Gray
    }
    Write-Host "[+] Writing tests ..." -ForegroundColor Green
    $ntTestsPath = $testFiles.Where({ $_.BaseName -eq 'devHelper.PsImport.Intergration.Tests' }).FullName
    $ftTestsPath = $testFiles.Where({ $_.BaseName -eq 'devHelper.PsImport.Features.Tests' }).FullName
    $mtTestsPath = $testFiles.Where({ $_.BaseName -eq 'devHelper.PsImport.Module.Tests' }).FullName
    $scriptNames = $testFiles.Where({ $_.Extension -eq '.ps1' -and $_.BaseName.Contains('-') }).BaseName
    $ftTestScrpt = [scriptblock]::Create({
            function Assert-LoadedFunctions {
                param ([Parameter(Mandatory)][string[]]$Names)
                $f = Get-Command -CommandType Function | Select-Object -ExpandProperty Name
                $s = $true; $Names.ForEach({ $s = $s -and $f.Contains($_) })
                return $s
            }
            #1. Test feature: Support for wildcards
            Describe "Importing functions with wildcards" {
                Context "When importing functions with a wildcard in the filename" {
                    It "should import all functions matching the pattern from file" {
                        $expectedFunctions = @(Get-Content "./relative/path/to/script_File.psm1" | Select-String -Pattern "^function\s+([a-zA-Z0-9_-]+)\s*\(" | ForEach-Object { $_.Matches.Groups[1].Value })
                        Import * -from "./relative/path/to/script_File.psm1"
                        Assert-LoadedFunctions $expectedFunctions | Should be $true
                    }
                }
            }

            #2. Test feature: Importing from many files at once
            Describe "Importing functions from multiple files" {
                Context "When importing functions from multiple files" {
                    It "should import all functions from all files" {
                        $expectedFunctions = @(Get-Content "./relative/path/to/fileNamedlikeabc*.ps1" | Select-String -Pattern "^function\s+([a-zA-Z0-9_-]+)\s*\(" | ForEach-Object { $_.Matches.Groups[1].Value })
                        Import * -from "./relative/path/to/fileNamedlikeabc*.ps1"
                        Assert-LoadedFunctions $expectedFunctions | Should be $true
                    }
                }
            }
            #3. Test feature: Importing a function(s) from same repo
            Describe "Importing specific functions from the same repo" {
                Context "When importing specific functions from the same repo" {
                    It "should import only the specified functions from the specified file" {
                        $expectedFunctions = @('funcName1', 'funcName2')
                        Import 'funcName1', 'funcName2' -from "./repo"
                        Assert-LoadedFunctions $expectedFunctions | Should be $true
                    }
                }
            }
            #4. Test feature: Importing a function(s) from a remote script
            Describe "Importing specific functions from a remote script" {
                Context "When importing specific functions from a remote script" {
                    It "should import only the specified function from the remote script" {
                        $expectedFunctions = @('funcName')
                        Import funcName -from 'https://example.com/MyRemote'
                        Assert-LoadedFunctions $expectedFunctions | Should be $true
                    }
                }
            }
        }
    ).ToString().Replace(
        './relative/path/to/',
        $resRlPath + [IO.Path]::DirectorySeparatorChar
    ).Replace(
        'script_File', (Get-Random -InputObject $testFiles.Where({ $_.Extension -eq '.psm1' }).BaseName)
    ).Replace(
        'fileNamedlikeabc', ($scriptNames.substring(0, 9) | Group-Object -NoElement | Sort-Object Count)[-1].Name
    ).Replace(
        "./repo", $resRlPath
    ).Replace(
        "funcName1', 'funcName2",
        [string]::Join("', '", (Get-Random -InputObject $scriptNames -Count 2))
    )
    [IO.File]::WriteAllLines($ftTestsPath, $ftTestScrpt.Split("`r").ForEach({ if ($_.Length -gt 12) { $_.Substring(13) } }), [System.Text.Encoding]::UTF8)
    [System.IO.DirectoryInfo]::new([IO.Path]::Combine($PSScriptRoot, 'Public')).GetFiles().ForEach({
            $n = [IO.Path]::GetFileNameWithoutExtension($_.FullName)
            $s = [System.Text.StringBuilder]::New(); [void]$s.AppendLine("Describe `"$n`" {`n    It `"should have command`" {`n        Get-Command $n | Should -Not -BeNullOrEmpty`n    }`n}")
            Add-Content -Path $ntTestsPath -Value $s.ToString() -Encoding utf8
        }
    )
    if ($BuildOutDir.Exists) {
        if (($BuildOutDir.EnumerateFiles().count | Measure-Object -Sum).Sum -gt 1) {
            $ModuleTestScript = [scriptblock]::Create({
                    $projectRoot = Resolve-Path ([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectPath'))
                    $ModulePath = Resolve-Path ([IO.Path]::Combine($projectRoot, 'BuildOutput', [Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName'))); # Decompiled ModulePath
                    $decomPath = [IO.DirectoryInfo]::New([IO.Path]::Combine($projectRoot, [Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName')));
                    $Publc_Dir = [IO.DirectoryInfo]::New([IO.Path]::Combine($decomPath.FullName, 'Public'));
                    $Privt_Dir = [IO.DirectoryInfo]::New([IO.Path]::Combine($decomPath.FullName, 'Private'));
                    ($decomPath, $Publc_Dir, $Privt_Dir).ForEach({ if (!$_.Exists) { Throw [System.IO.DirectoryNotFoundException]::New("Directory $($_.FullName) does not exist.") } })
                    # Verbose output for non-main builds on appveyor
                    # Handy for troubleshooting.
                    # Splat @Verbose against commands as needed (here or in pester tests)
                    $Verbose = @{}
                    if ($([Environment]::GetEnvironmentVariable($env:RUN_ID + 'BranchName')) -eq "development" -or $([Environment]::GetEnvironmentVariable($env:RUN_ID + 'CommitMessage')) -match "!verbose") {
                        $Verbose.add("Verbose", $True)
                    }

                    Import-Module $ModulePath -Force -Verbose:$false

                    Describe "Module tests: $($([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName')))" -Tag 'Module' {
                        Context "Confirm files are valid Powershell syntax" {
                            $_scripts = $decomPath.GetFiles("*", [System.IO.SearchOption]::AllDirectories).Where({ $_.Extension -in ('.ps1', '.psd1', '.psm1') })
                            $testCase = $_scripts | ForEach-Object { @{ file = $_ } }
                            It "Script <file> should be valid Powershell" -TestCases $testCase {
                                param($file)
                                $file.fullname | Should Exist
                                $contents = Get-Content -Path $file.fullname -ErrorAction Stop
                                $errors = $null
                                $null = [System.Management.Automation.PSParser]::Tokenize($contents, [ref]$errors)
                                $errors.Count | Should Be 0
                            }
                        }
                        Context "Confirm there are no duplicate function names in private and public folders" {
                            It 'Should have no duplicate functions' {
                                $funcNames = [System.Collections.generic.List[string]]::new()
                                $Publc_Dir.GetFiles("*", [System.IO.SearchOption]::AllDirectories).Where({ $_.Extension -eq '.ps1' }).BaseName.ForEach({ [void]$funcNames.Add($_) })
                                $Privt_Dir.GetFiles("*", [System.IO.SearchOption]::AllDirectories).Where({ $_.Extension -eq '.ps1' }).BaseName.ForEach({ [void]$funcNames.Add($_) })
                                $funcNames | Group-Object | Where-Object { $_.Count -gt 1 } | Select-Object -ExpandProperty Count | Should -BeLessThan 1
                            }
                        }
                    }
                }
            )
            [IO.File]::WriteAllLines($mtTestsPath, $ModuleTestScript.Tostring().Split("`r").ForEach({ if ($_.Length -gt 20) { $_.Substring(21) } }), [System.Text.Encoding]::UTF8)
        } else {
            if ($skipBuildOutputTest.IsPresent) {
                Write-Warning "Build OutPut is incomplete, moving on .."
            } else {
                throw 'Build is not Complete!'
            }
        }
    } else {
        Remove-Item $mtTestsPath -Force
        if ($skipBuildOutputTest.IsPresent) {
            Write-Warning "No Build OutPut, moving on .."
        } else {
            throw 'No Build OutPut!'
        }
    }
    Write-Host "[+] Running tests ..." -ForegroundColor Green
    if (!$skipBuildOutputTest.IsPresent) {
        if (!$manifestFile.Exists) {
            throw [System.IO.FileNotFoundException]::New("Could Not Find Module manifest File $([IO.Path]::GetRelativePath($PSScriptRoot, $manifestFile.FullName))")
        }
        Test-ModuleManifest -Path $manifestFile.FullName -ErrorAction Stop -Verbose
    }
    $testResults = Invoke-Pester -Path $TestsPath -OutputFormat NUnitXml -OutputFile "$TestsPath\results.xml" -PassThru
}

end {
    if ($CleanUp.IsPresent) {
        Write-Host "[+] Clean Up ..." -ForegroundColor Green
        $Resources.GetFiles().ForEach({
                Remove-Item -Path $_.FullName -Force
                Write-Host "    removed $($_.Name)" -ForegroundColor Gray
            }
        )
        $testFiles.ForEach({
                Remove-Item -Path $_.FullName -Force
                Write-Host "    removed $($_.Name)" -ForegroundColor White
            }
        )
    }
    return $testResults
}