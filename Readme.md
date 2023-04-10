# [**PsImport**](https://github.com/alainQtec/PsImport)

A PowerShell module for dot-sourcing functions from scripts.

Pretty handy when working with complex powershell Projects with many functions spread across multiple files.

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
    (Import funcName1, funcName2 -from fileNameb).ForEach({ . $_ })
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

This module is licensed under the MIT [License](LICENSE).
