# PsImport

A module to help with importing powershell functions from other scripts in your project

## Notes
1.
    ```PowerShell
    [PsImport]::ParseFile($Filepath)
    ```
    Finds all function declarations in file $filepath.
    >This will Work better if there is a clear newline char (ie: "`n") between each function in the file.