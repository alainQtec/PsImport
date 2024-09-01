# [**PsImport**](https://www.powershellgallery.com/packages/PsImport)

A PowerShell module for importing functions.

>Note:
If you just want to import a nested module then add
`using module /relative/path/to/module.psm1`
at the top of your rootmodule; thats it!
This module is only useful when working with powershell projects where functions are spread across multiple folders or somewhere online.


[![CI](https://github.com/alainQtec/PsImport/actions/workflows/CI.yaml/badge.svg)](https://github.com/alainQtec/PsImport/actions/workflows/CI.yaml) ie: [v2 WIP](alainQtec.dev/projects/#workingOn)

[![Publish to PowerShell Gallery](https://github.com/alainQtec/PsImport/actions/workflows/Publish.yaml/badge.svg?branch=main)](https://github.com/alainQtec/PsImport/actions/workflows/Publish.yaml)

## **Installation**

```PowerShell
Install-Module PsImport
```

## **Features**

* **Supports wildcards**:

    ```PowerShell
    (Import * -from '/relative/path/to/script.ps1').ForEach({ . $_ })
    ```

    Will load functions from the file into current script scope.

* **Importing from many files at once**:

    ```PowerShell
    (Import * -from '/relative/path/to/fileNamedlikeabc*.ps1').ForEach({ . $_ })
    ```

    Will load all functions from .ps1 files that look like fileNamedlikeabc

* **Import a function(s) from same repo**

    ```PowerShell
    Cd GitHubRepo
    (Import funcName1, funcName2).ForEach({ . $_ })
    ```

    Will only load functions funcName1 and funcName2 from fileNameb.

    *if you are sure no other file is named fileNameb is in the repo.

* **Import a function(s) from a remote script**

    ```PowerShell
    (Import funcName -from https://example.com/MyRemoteScript.ps1).ForEach({ . $_ })
    ```

## **Todos**

* Fix edge cases when parsing files.

    Sometimes it does not find all function declarations in file $filepath.

    ```PowerShell
    [PsImport]::ParseFile($Filepath)
    ```

    For now it Works as expected only when there is a clear newline char (ie: "`n") between each function in the file.

* Remove (/ Find a workarround) for the '.ForEach({ . $_ })' that is used in the import syntax.

## **Contributions**

![Alt](https://repobeats.axiom.co/api/embed/c7f1a37fb73368e4265faca921b76e3d4448defb.svg "Repobeats analytics image")

If you would like to contribute to psimport, please feel free to submit a pull request on GitHub. We welcome contributions of all kinds, from bug fixes to new features.

## **License**

This module is licensed under the MIT [License](https://alainQtec.MIT-license.org).
