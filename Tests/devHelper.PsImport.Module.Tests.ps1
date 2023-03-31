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
