<#
.SYNOPSIS
    Run Tests
.EXAMPLE
    .\Test-Module.ps1 -version 0.1.0
    Will test the module in .\BuildOutput\PsImport\0.1.0\
.EXAMPLE
    .\Test-Module.ps1
    Will test the latest  module version in .\BuildOutput\PsImport\
#>
param (
  [Parameter(Mandatory = $false, Position = 0)]
  [Alias('Module')][string]$ModulePath = $PSScriptRoot,
  # Path Containing Tests
  [Parameter(Mandatory = $false, Position = 1)]
  [Alias('Tests')][string]$TestsPath = [IO.Path]::Combine($PSScriptRoot, 'Tests'),

  # Version string
  [Parameter(Mandatory = $false, Position = 2)]
  [ValidateScript({
      if (($_ -as 'version') -is [version]) {
        return $true
      } else {
        throw [System.IO.InvalidDataException]::New('Please Provide a valid version')
      }
    }
  )][ArgumentCompleter({
      [OutputType([System.Management.Automation.CompletionResult])]
      param([string]$CommandName, [string]$ParameterName, [string]$WordToComplete, [System.Management.Automation.Language.CommandAst]$CommandAst, [System.Collections.IDictionary]$FakeBoundParameters)
      $CompletionResults = [System.Collections.Generic.List[System.Management.Automation.CompletionResult]]::new()
      $b_Path = [IO.Path]::Combine($PSScriptRoot, 'BuildOutput', 'PsImport')
      if ((Test-Path -Path $b_Path -PathType Container -ErrorAction Ignore)) {
        [IO.DirectoryInfo]::New($b_Path).GetDirectories().Name | Where-Object { $_ -like "*$wordToComplete*" -and $_ -as 'version' -is 'version' } | ForEach-Object { [void]$CompletionResults.Add([System.Management.Automation.CompletionResult]::new($_, $_, "ParameterValue", $_)) }
      }
      return $CompletionResults
    }
  )]
  [string]$version,
  [switch]$skipBuildOutputTest,
  [switch]$CleanUp
)
begin {
  $TestResults = $null
  # Get latest version
  if ([string]::IsNullOrWhiteSpace($version)) {
    $version = [version[]][IO.DirectoryInfo]::New([IO.Path]::Combine($PSScriptRoot, 'BuildOutput', 'PsImport')).GetDirectories().Name | Select-Object -Last 1
  }
  $BuildOutDir = [IO.DirectoryInfo]::New((Resolve-Path ([IO.Path]::Combine($PSScriptRoot, 'BuildOutput', 'PsImport', $version)) -ErrorAction Stop))
  $manifestFile = [IO.FileInfo]::New([IO.Path]::Combine($BuildOutDir.FullName, "PsImport.psd1"))
  Write-Host "[+] Checking Prerequisites ..." -ForegroundColor Green
  if (!$BuildOutDir.Exists) {
    $msg = 'Directory "{0}" Not Found' -f ([IO.Path]::GetRelativePath($PSScriptRoot, $BuildOutDir.FullName))
    if ($skipBuildOutputTest.IsPresent) {
      Write-Warning "$msg"
    } else {
      throw [System.IO.DirectoryNotFoundException]::New($msg)
    }
  }
  if (!$skipBuildOutputTest.IsPresent -and !$manifestFile.Exists) {
    throw [System.IO.FileNotFoundException]::New("Could Not Find Module manifest File $([IO.Path]::GetRelativePath($PSScriptRoot, $manifestFile.FullName))")
  }
  if (!(Test-Path -Path $([IO.Path]::Combine($PSScriptRoot, "PsImport.psd1")) -PathType Leaf -ErrorAction Ignore)) { throw [System.IO.FileNotFoundException]::New("Module manifest file Was not Found in '$($BuildOutDir.FullName)'.") }
  $Resources = [System.IO.DirectoryInfo]::new([IO.Path]::Combine("$TestsPath", 'Resources'))
  $resRlPath = [IO.Path]::GetRelativePath("$PSScriptRoot", "$($Resources.FullName)")
  $script:fnNames = [System.Collections.Generic.List[string]]::New(); $testFiles = [System.Collections.Generic.List[IO.FileInfo]]::New()
  [void]$testFiles.Add([IO.FileInfo]::New([IO.Path]::Combine("$PSScriptRoot", 'Tests', 'PsImport.Intergration.Tests.ps1')))
  [void]$testFiles.Add([IO.FileInfo]::New([IO.Path]::Combine("$PSScriptRoot", 'Tests', 'PsImport.Features.Tests.ps1')))
  [void]$testFiles.Add([IO.FileInfo]::New([IO.Path]::Combine("$PSScriptRoot", 'Tests', 'PsImport.Module.Tests.ps1')))
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
  $indentation_size = Get-ModuleManifest -Path "$PSScriptRoot/PSScriptAnalyzerSettings.psd1" -PropertyName IndentationSize
  function script:Assert-LoadedFunctions {
    param ([Parameter(Mandatory)][string[]]$Names)
    $f = Get-Command -CommandType Function | Select-Object -ExpandProperty Name
    $s = $true; $Names.ForEach({ $s = $s -and $f.Contains($_) })
    return $s
  }
}

process {
  Get-Module PsImport | Remove-Module
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
  Write-Host "[+] Writing test scripts ..." -ForegroundColor Green
  $ntTestsPath = $testFiles.Where({ $_.BaseName -eq 'PsImport.Intergration.Tests' }).FullName
  $ftTestsPath = $testFiles.Where({ $_.BaseName -eq 'PsImport.Features.Tests' }).FullName
  $mtTestsPath = $testFiles.Where({ $_.BaseName -eq 'PsImport.Module.Tests' }).FullName
  $scriptNames = $testFiles.Where({ $_.Extension -eq '.ps1' -and $_.BaseName.Contains('-') }).BaseName
  $ftTestScrpt = [scriptblock]::Create({
      $Modversion = '<Modversion>'
      $BuildOutpt = Get-Item -Path '<BuildOutpt_FullName>'
      if (![string]::IsNullOrWhiteSpace($Modversion)) {
        Import-Module $BuildOutpt.Parent.FullName -Version $Modversion
      } else {
        Import-Module $BuildOutpt.FullName
      }
      #1. Test feature: Support for wildcards
      Describe "Importing functions with wildcards" {
        Context " When importing functions with a wildcard in the filename" {
          It " should import all functions matching the pattern from file" {
            $expectedFunctions = @(Get-Content "./relative/path/to/script_File.psm1" | Select-String -Pattern "^function\s+([a-zA-Z0-9_-]+)\s*\(" | ForEach-Object { $_.Matches.Groups[1].Value })
            $(Import * -from "./relative/path/to/script_File.psm1").ForEach({ . $_.ScriptBlock })
            Assert-LoadedFunctions $expectedFunctions | Should -Be $true
          }
        }
      }
      #2. Test feature: Importing from many files at once
      Describe "Importing functions from multiple files" {
        Context " When importing functions from multiple files" {
          It " should import all functions from all files" {
            $expectedFunctions = @(Get-Content "./relative/path/to/fileNamedlikeabc*.ps1" | Select-String -Pattern "^function\s+([a-zA-Z0-9_-]+)\s*\(" | ForEach-Object { $_.Matches.Groups[1].Value })
            $(Import * -from "./relative/path/to/fileNamedlikeabc*.ps1").ForEach({ . $_.ScriptBlock })
            Assert-LoadedFunctions $expectedFunctions | Should -Be $true
          }
        }
      }
      #3. Test feature: Importing a function(s) from same repo
      Describe "Importing specific functions from the same repo" {
        Context " When importing functions from the same repo" {
          It " should import only the specified functions from the specified file" {
            $expectedFunctions = @('funcName1', 'funcName2')
            $(Import 'funcName1', 'funcName2' -from "./repo").ForEach({ . $_.ScriptBlock })
            Assert-LoadedFunctions $expectedFunctions | Should -Be $true
          }
        }
      }
      #4. Test feature: Importing a function(s) from a remote script
      Describe "Importing specific functions from a remote script" {
        Context " When importing functions from a remote script" {
          It " should import only the specified function from the remote script" {
            $expectedFunctions = @('Test-GitHubScript')
            $(Import Test-GitHubScript -from 'https://github.com/alainQtec/PsScriptsRepo/raw/main/Test-GitHubScript.ps1').ForEach({ . $_.ScriptBlock })
            Assert-LoadedFunctions $expectedFunctions | Should -Be $true
          }
        }
      }
    }
  ).ToString() `
    -replace "./relative/path/to/", ($resRlPath + [IO.Path]::DirectorySeparatorChar) `
    -replace "script_File", (Get-Random -InputObject $testFiles.Where({ $_.Extension -eq '.psm1' }).BaseName) `
    -replace "fileNamedlikeabc", ($scriptNames.substring(0, 9) | Group-Object -NoElement | Sort-Object Count)[-1].Name `
    -replace "./repo", $resRlPath -replace "<Modversion>", $version `
    -replace "funcName1', 'funcName2", [string]::Join("', '", (Get-Random -InputObject $scriptNames -Count 2)) `
    -replace "<BuildOutpt_FullName>", $BuildOutDir.FullName
  [IO.File]::WriteAllLines($ftTestsPath, $ftTestScrpt.Split("`r").ForEach({ if ($_.Length -gt ($indentation_size * 3)) { $_.Substring((($indentation_size * 3) + 1)) } }), [System.Text.Encoding]::UTF8)
  Write-Host "    Created $([IO.Path]::GetRelativePath($PSScriptRoot, $ftTestsPath))" -ForegroundColor White
  [System.IO.DirectoryInfo]::new([IO.Path]::Combine("$PSScriptRoot", 'Public')).GetFiles().ForEach({
      $n = [IO.Path]::GetFileNameWithoutExtension($_.FullName)
      $s = [System.Text.StringBuilder]::New(); [void]$s.AppendLine("Describe `"$n`" {`n  It `"should have command`" {`n    Get-Command $n | Should -Not -BeNullOrEmpty`n  }`n}")
      Add-Content -Path $ntTestsPath -Value $s.ToString() -Encoding utf8
      Write-Host "    Created $([IO.Path]::GetRelativePath($PSScriptRoot, $ntTestsPath))" -ForegroundColor White
    }
  )
  if ($BuildOutDir.Exists) {
    $ModuleTestScript = [scriptblock]::Create({
        Describe "Module tests: $($([Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName')))" -Tag 'Module' {
          Context " Confirm files are valid Powershell syntax" {
            $_scripts = $(Get-Item -Path "<BuildOutpt_FullName>").GetFiles(
              "*", [System.IO.SearchOption]::AllDirectories
            ).Where({ $_.Extension -in ('.ps1', '.psd1', '.psm1') })
            $testCase = $_scripts | ForEach-Object { @{ file = $_ } }
            It "Script <file> Should have valid Powershell sysntax" -TestCases $testCase {
              param($file) $contents = Get-Content -Path $file.fullname -ErrorAction Stop
              $errors = $null; [void][System.Management.Automation.PSParser]::Tokenize($contents, [ref]$errors)
              $errors.Count | Should -Be 0
            }
          }
          Context " Confirm there are no duplicate function names in private and public folders" {
            It ' Should have no duplicate functions' {
              $Publc_Dir = Get-Item -Path ([IO.Path]::Combine("<BuildOutpt_FullName>", 'Public'))
              $Privt_Dir = Get-Item -Path ([IO.Path]::Combine("<BuildOutpt_FullName>", 'Private'))
              $funcNames = @(); Test-Path -Path ([string[]]($Publc_Dir, $Privt_Dir)) -PathType Container -ErrorAction Stop
              $Publc_Dir.GetFiles("*", [System.IO.SearchOption]::AllDirectories) + $Privt_Dir.GetFiles("*", [System.IO.SearchOption]::AllDirectories) | Where-Object { $_.Extension -eq '.ps1' } | ForEach-Object { $funcNames += $_.BaseName }
              $($funcNames | Group-Object | Where-Object { $_.Count -gt 1 }).Count | Should -BeLessThan 1
            }
          }
        }
      }
    ).ToString() -replace "<BuildOutpt_FullName>", $BuildOutDir.FullName
    if (($BuildOutDir.EnumerateFiles().count | Measure-Object -Sum).Sum -gt 2) {
      [IO.File]::WriteAllLines($mtTestsPath, $ModuleTestScript.Split("`r").ForEach({ if ($_.Length -gt ($indentation_size * 4)) { $_.Substring((($indentation_size * 4) + 1)) } }), [System.Text.Encoding]::UTF8)
      Write-Host "    Created $([IO.Path]::GetRelativePath($PSScriptRoot, $mtTestsPath))" -ForegroundColor White
    }
  } else {
    Remove-Item $mtTestsPath -Force
  }
  Write-Host "[+] Testing Module ..." -ForegroundColor Green
  if (!$skipBuildOutputTest.IsPresent) {
    Test-ModuleManifest -Path $manifestFile.FullName -ErrorAction Stop -Verbose
  }
  $TestResults = Invoke-Pester -Path $TestsPath -OutputFormat NUnitXml -OutputFile "$TestsPath\results.xml" -PassThru
}

end {
  if ($CleanUp.IsPresent) {
    Write-Host "[+] Clean Up ..." -ForegroundColor Green
    $Resources.GetFiles() | ForEach-Object {
      Remove-Item -Path $_.FullName -Force
      Write-Host "    removed $($_.Name)" -ForegroundColor Gray
    }
    $testFiles.ForEach({
        Remove-Item -Path $_.FullName -Force
        Write-Host "    removed $($_.Name)" -ForegroundColor White
      }
    )
  }
  return $TestResults
}