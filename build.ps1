﻿<#
.SYNOPSIS
    PsImport buildScript
.DESCRIPTION
    A custom Psake buildScript for the module PsImport.
.LINK
    https://github.com/alainQtec/PsImport/blob/main/build.ps1
.EXAMPLE
    Running ./build.ps1 will only "Init, Compile & Import" the module; That's it, no tests.
    To run tests Use:
    ./build.ps1 -Task Test
    This Will build the module, Import it and run tests using the ./Test-Module.ps1 script.
.EXAMPLE
    ./build.ps1 -Task deploy
    Will build the module, test it and deploy it to PsGallery (only if $psake.build_success)
#>
[cmdletbinding(DefaultParameterSetName = 'task')]
param(
  [parameter(Position = 0, ParameterSetName = 'task')]
  [ValidateScript({
      $task_seq = [string[]]$_; $IsValid = $true
      $Tasks = @('Init', 'Clean', 'Compile', 'Test', 'Deploy')
      foreach ($name in $task_seq) {
        $IsValid = $IsValid -and ($name -in $Tasks)
      }
      if ($IsValid) {
        return $true
      } else {
        throw [System.ArgumentException]::new('Task', "ValidSet: $($Tasks -join ', ').")
      }
    }
  )][ValidateNotNullOrEmpty()][Alias('t')]
  [string[]]$Task = @('Init', 'Clean', 'Compile'),

  # Module buildRoot
  [Parameter(Mandatory = $false, ParameterSetName = 'task')]
  [ValidateScript({
      if (Test-Path -Path $_ -PathType Container -ErrorAction Ignore) {
        return $true
      } else {
        throw [System.ArgumentException]::new('Path', "Path: $_ is not a valid directory.")
      }
    })][Alias('p')]
  [string]$Path = (Get-Item -Path "." -Verbose:$false).FullName,

  [Parameter(Mandatory = $false, ParameterSetName = 'task')]
  [Alias('u')][ValidateNotNullOrWhiteSpace()]
  [string]$gitUser = { return $Iswindows ? $env:UserName : $env:USER }.Invoke(),

  [parameter(ParameterSetName = 'task')]
  [Alias('i')]
  [switch]$Import,

  [parameter(ParameterSetName = 'help')]
  [Alias('h', '-help')]
  [switch]$Help
)

begin {
  function Register-PackageFeed ([switch]$ForceBootstrap) {
    if ($null -eq (Get-PSRepository -Name PSGallery -ErrorAction Ignore)) {
      Unregister-PSRepository -Name PSGallery -Verbose:$false -ErrorAction Ignore
      Register-PSRepository -Default -InstallationPolicy Trusted
    }
    if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne 'Trusted') {
      Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -Verbose:$false
    }
    Get-PackageProvider -Name Nuget -ForceBootstrap:($ForceBootstrap.IsPresent) -Verbose:$false
    if (!(Get-PackageProvider -Name Nuget)) {
      Install-PackageProvider -Name NuGet -Force | Out-Null
    }
  }
  function Read-ModulePsd1([IO.DirectoryInfo]$folder) {
    $p = [IO.Path]::Combine($folder.FullName, "$($folder.BaseName).psd1"); $d = [IO.File]::ReadAllText($p);
    return [scriptblock]::Create("$d").Invoke()
  }
  function Import-rmodule([string]$Name) {
    if (!(Get-Module $Name -ListAvailable -ErrorAction Ignore)) { Install-Module $Name -Verbose:$false };
    $(Get-InstalledModule $Name -ErrorAction Stop).InstalledLocation | Split-Path | Import-Module -Verbose:$false
  }
  function Import-RequiredModules ([IO.DirectoryInfo]$RootPath, [string[]]$Names, [switch]$UseSelf) {
    $self = [IO.Path]::Combine($RootPath.FullName, "$($RootPath.BaseName).psm1")
    if ([IO.File]::Exists($self) -and $UseSelf) {
      $Names.ForEach({ Import-rmodule $_ })
      Write-Host "<< Import current build of [$($RootPath.BaseName)] <<" -f Green # (done after requirements are imported)
      Import-Module ([IO.Path]::Combine($RootPath.FullName, "$($RootPath.BaseName).psd1"))
    } else {
      $Names.ForEach({ Import-rmodule $_ })
    }
  }
}
process {
  Register-PackageFeed -ForceBootstrap
  $data = Read-ModulePsd1 -folder ([IO.DirectoryInfo]::new($Path))
  Import-RequiredModules -RootPath $Path -Names $data.RequiredModules
  if ($PSCmdlet.ParameterSetName -eq 'help') {
    Build-Module -Help
  } else {
    Build-Module -Task $Task -Path $Path -gitUser $gitUser -Import:$Import
  }
}