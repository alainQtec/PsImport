@{
    ModuleName    = 'devHelper.PsImport'
    ModuleVersion = [System.Management.Automation.SemanticVersion]::new(0, 1, 0)
    ReleaseNotes  = @"
1. [Click here](https://github.com/alainQtec/devHelper.PsImport/releases/download/v<versionToDeploy>/devHelper.PsImport.zip) to download the *devHelper.PsImport.zip* file attached to the release.
2. **If on Windows**: Right-click the downloaded zip, select Properties, then unblock the file.
    > _This is to prevent having to unblock each file individually after unzipping._
3. Unzip the archive.
4. (Optional) Place the module folder somewhere in your ``PSModulePath``.
    > _You can view the paths listed by running the environment variable ```$Env:PSModulePath``_
5. Import the module, using the full path to the PSD1 file in place of ``devHelper.PsImport`` if the unzipped module folder is not in your ``PSModulePath``:
    ``````powershell
    # In `$Env:PSModulePath
    Import-Module devHelper.PsImport

    # Otherwise, provide the path to the manifest:
    Import-Module -Path Path\to\devHelper.PsImport\<versionToDeploy>\devHelper.PsImport.psd1
    ``````
"@
}