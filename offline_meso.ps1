Param (
    [Parameter(Mandatory=$true)][string]$TargetPid,
    [string]$OutputZip = "meso_deps.zip"
)

function is64bit($a) {
    try {
        Add-Type -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, 
 CallingConvention = CallingConvention.Winapi)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool IsWow64Process(
 [In] System.IntPtr hProcess,
 [Out, MarshalAs(UnmanagedType.Bool)] out bool wow64Process);
'@ -Name NativeMethods -Namespace Kernel32
    }
    catch {}
    $is32Bit = [int]0
    if (!$a.Handle) {
        echo "Unable to open handle for process: Does the proceses exist? Do you have adequate permissions?"
        exit
    }
    if ([Kernel32.NativeMethods]::IsWow64Process($a.Handle, [ref]$is32Bit)) {
        $(if ($is32Bit) {$false} else {$true})
    } else {
        "IsWow64Process call failed"
        exit
    }
}

# Create a new temp directory based on a random GUID
function New-TemporaryDirectory {
    $parent = [System.IO.Path]::GetTempPath()
    [string] $name = [System.Guid]::NewGuid()
    $name = "mesotmp_" + $name
    New-Item -ItemType Directory -Path (Join-Path $parent $name)
}

$pshell_bitness = (is64bit(Get-Process -Id $PID))
echo "Powershell is 64-bit: $pshell_bitness"

$target_bitness = (is64bit(Get-Process -Id $TargetPid))
echo "Target     is 64-bit: $target_bitness"

# Validate bitnesses match
if ($pshell_bitness -ne $target_bitness) {
    echo "Your Powershell bitness does not match the target bitness"
    echo "Use 32-bit Powershell for 32-bit processes or 64-bit Powershell for 64-bit processes"
    echo "This is to get around pathing issues between things like C:\windows\system32 and C:\windows\syswow64"
    exit
}

# Get all the module/executable paths from a running process
$paths = (Get-Process -Id $TargetPid -Module -FileVersionInfo).FileName

# Create a new temporary directory
$dirname = New-TemporaryDirectory

ForEach ($path in $paths) {
    # Convert the path to not have a ":" in it by replacing it with a "_" and
    # then convert it to a lowercase string
    $lowerpath = ([string](Get-ChildItem -Path $path)).replace(":", "_").ToLower()

    # Prepend a root-level folder "cache" to all paths that will go in the zip
    $lowerpath = (Join-Path "cache" $lowerpath)

    # Compute this path in the temp folder
    $hirearchy = (Join-Path $dirname $lowerpath)

    # Get the parent directory from this filename
    $parent = (Split-Path $hirearchy -Parent)

    # Create the directory if it doesn't exist
    if (!(Test-Path -path $parent)) { New-Item -ItemType Directory -Path $parent | Out-Null }

    # Copy the file :)
    Copy-Item -Path $path -Destination $hirearchy
}

# Create zip from all the files in the temp folder
Compress-Archive -Force -Path (Join-Path $dirname *) -DestinationPath $OutputZip

# Remove temp directory
Remove-Item -Recurse -Force $dirname

