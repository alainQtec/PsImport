
<#PSScriptInfo

.VERSION 0.1.0

.GUID b5de19d4-ad3d-4761-a15e-07a194039770

.AUTHOR Alain Herve

.COMPANYNAME alainQtec

.COPYRIGHT alainQtec

.TAGS PowershelGallery

.LICENSEURI

.PROJECTURI https://github.com/alainQtec/PsImport

.ICONURI

.EXTERNALMODULEDEPENDENCIES

.REQUIREDSCRIPTS ./build.ps1

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES


.PRIVATEDATA

#>

<#

.DESCRIPTION
 Publish Script

#>
Param()

$BuildScript = [IO.Path]::Combine($PSScriptRoot, 'build.ps1')
& $BuildScript -Task Deploy -ApiKey $NugetApiKey
exit $?
