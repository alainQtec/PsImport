# [**PsImport**](https://github.com/alainQtec/devHelper.PsImport)

A module to **import functions** from PowerShell scripts in your project, and "remote scripts"* making it easier to organize and reuse your code.

The remote scripts part **is a somehow similar functionality to JavaScript's ES module import feature* but this is still is security concerns. (ideas are welcome!)

## **Installation**

```PowerShell
Install-Module devHelper.PsImport
```

## **Features**

* **Supports wildcards**:

    ```PowerShell
    Import * -from '/relative/path/to/script.ps1'
    ```

    Will load functions from the file into current script scope.

* **Importing from many files at once**:

    ```PowerShell
    Import * -from '/relative/path/to/fileNamedlikeabc*.ps1'
    ```

    Will load all functions from .ps1 files that look like fileNamedlikeabc

* **Import a function(s) from same repo**

    ```PowerShell
    Import funcName1, funcName2 -from fileNameb
    ```

    Will only load functions funcName1 and funcName2 from fileNameb.

    *if you are sure no other file is named fileNameb is in the repo.

* **Import a function(s) from a remote script**

    ```PowerShell
    Import funcName -from https://example.com/MyRemoteScript.ps1
    ```

## **Todos**

Here are features currently being built:

* Securely import remote scripts.

* Fix edge cases when parsing files.

ie: Sometimes it does not find all function declarations in file $filepath.

```PowerShell
[PsImport]::ParseFile($Filepath)
```

For now it Works as expected only when there is a clear newline char (ie: "`n") between each function in the file.

* Add "Import a function from a module" feature

## **Contributing**

If you would like to contribute to psimport, please feel free to submit a pull request on GitHub. We welcome contributions of all kinds, from bug fixes to new features.

## **License**

This module is licensed under the MIT [License](LICENSE).
