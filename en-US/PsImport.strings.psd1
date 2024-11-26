@{
  ModuleName    = 'PsImport'
  ModuleVersion = [version]"0.1.4"
  ReleaseNotes  = @"
# Changelog`n`n

* Fixed import errors.
* Now returns FunctionDetails[]

`n`n***`n`n# Install guide:`n`n
1. [Click here](https://github.com/alainQtec/PsImport/releases/download/v<versionToDeploy>/PsImport.zip) to download the *PsImport.zip* file attached to the release.
2. **If on Windows**: Right-click the downloaded zip, select Properties, then unblock the file.
    > _This is to prevent having to unblock each file individually after unzipping._
3. Unzip the archive.
4. (Optional) Place the module folder somewhere in your ``PSModulePath``.
    > _You can view the paths listed by running the environment variable ```$Env:PSModulePath``_
5. Import the module, using the full path to the PSD1 file in place of ``PsImport`` if the unzipped module folder is not in your ``PSModulePath``:
    ``````powershell
    # In Env:PSModulePath
    Import-Module PsImport

    # Otherwise, provide the path to the manifest:
    Import-Module -Path Path\to\PsImport\<versionToDeploy>\PsImport.psd1
    ``````
"@
}