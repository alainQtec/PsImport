# [**PsImport**](https://github.com/alainQtec/devHelper.PsImport)

A module to **import functions** from PowerShell scripts in your project, and `remote scripts`* making it easier to organize and reuse your code.

**Its a somehow similar functionality to JavaScript's ES module import feature* but this still has security concerns.

## **Installation**

```PowerShell
Install-Module devHelper.PsImport
```

## **Features**

`1.` **Supports wildcards**:

```PowerShell
Import * -from '/relative/path/to/script.ps1'
```

Will load functions in the file get loaded in current script scope.

`2.` **Importing from many files at once**:

```PowerShell
Import * -from '/relative/path/to/fileNamedlikeabc*.ps1'
```

Will load all functions from in files that look kike ileNamedlikeabc


`3.` **Import a function(s) from same repo**

```PowerShell
Import funcName1, funcName2 -from fileNameb
```
Will load all functions funcName1 and funcName2

*if you are sure no other file is named fileNameb is in the repo.

`4.` **Import a function(s) from a remote script**

```PowerShell
Import funcName -from https://example.com/MyRemoteScript.ps1
```

## **Todos**

Here are features currently being built:

`1.` Add build scripts

`2.` Securely import remote scripts.

`3.` Fix edge cases when parsing files.

ie: Sometimes it does not find all function declarations in file $filepath.

```PowerShell
[PsImport]::ParseFile($Filepath)
```

For now it Works as expected only when there is a clear newline char (ie: "`n") between each function in the file.

`4.` Add "Import a function from a module" feature


## **Contributing**

If you would like to contribute to psimport, please feel free to submit a pull request on GitHub. We welcome contributions of all kinds, from bug fixes to new features.

## **License**

This module is licensed under the MIT License.