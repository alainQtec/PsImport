# if ($Env:COMPUTERNAME -eq 'CODETRON' -and [string]::IsNullOrEmpty($Env:GITHUB_ACTION_PATH)) {
#     if (![regex]::IsMatch($Env:NUGETAPIKEY, "^[A-Fa-f0-9]{600,700}$")) {
#         $export = (Read-Host -AsSecureString -Prompt 'Enter your Nuget APIKEY') | ConvertFrom-SecureString
#         Add-EnvironmentVariable -Name NUGETAPIKEY -Value $export
#     }
#     $APIKEY = $(New-Object system.Management.Automation.PSCredential("test", $(ConvertTo-SecureString $Env:NUGETAPIKEY))).GetNetworkCredential().Password
# } else {
#     $APIKEY = $Env:NUGETAPIKEY
# }
# Publish-Module -Path "$PSScriptRoot\Module" -NuGetApiKey $APIKEY
& ([IO.Path]::Combine($PSScriptRoot, 'build.ps1')) -Task Deploy -UpdateModules