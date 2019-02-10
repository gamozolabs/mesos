![Bag of Mesos][meso]![Bag of Mesos][meso]![Bag of Mesos][meso]![Bag of Mesos][meso]![Bag of Mesos][meso]![Bag of Mesos][meso]![Bag of Mesos][meso]![Bag of Mesos][meso]![Bag of Mesos][meso]![Bag of Mesos][meso]![Bag of Mesos][meso]![Bag of Mesos][meso]![Bag of Mesos][meso]

# Summary

Mesos is a tool to gather binary code coverage on all user-land Windows targets without need for source or recompilation. It also provides an automatic mechanism to save a full minidump of a process if it crashes under mesos.

Mesos is technically just a really fast debugger, capable of handling tens of millions of breakpoints. Using this debugger, we apply breakpoints to every single basic block in a program. These breakpoints are removed as they are hit. Thus, mesos converges to 0-cost coverage as gathering coverage only has a cost the first time the basic block is hit.

# Why?

This is effectively the successor of my 5+ year old Chrome IPC fuzzer. It doesn't have any fuzz components in it, but it is a high-performance debugger. This debugger can apply millions of breakpoints to gather coverage, and handle thousands of breakpoints per second to modify memory to inject inputs.

This strategy has worked out well for me historically and still is my go-to tooling for fuzzing targets on live systems.

Out of the box it can be used to gather simple code coverage but it's designed to be easily modified to add fast breakpoint handlers to inject inputs. For example, put a breakpoint after `NtReadFile()` returns and modify the buffer in flight. I used this in Chrome to modify inbound IPC traffic in the browser.

# Features

## Code coverage

![code coverage][code coverage]

## Automatic full minidump saving

![Crash being saved][crash saving]

## IDA Coloring

![IDA gettin colored up][ida coloring]

# Quick Usage Guide

Set `%PATH%` such that `idat64.exe` is in it:

```
path %PATH%;"C:\Program Files\IDA 7.2"
```

Generate mesos (the first time will be slow):

```
powershell .\offline_meso.ps1 <pid>
python generate_mesos.py process_ida
```

Gather coverage on target!

```
cargo build --release
target\release\mesos.exe <pid>
```

Applying 1.6 million breakpoints? No big deal.

```
C:\dev\mesos>target\release\mesos.exe 13828
mesos  is 64-bit: true
target is 64-bit: true
[      0.003783] Applied       5629 breakpoints (      5629 total breakpoints) notepad.exe
[      0.028071] Applied      61334 breakpoints (     66963 total breakpoints) ntdll.dll
[      0.035298] Applied      25289 breakpoints (     92252 total breakpoints) kernel32.dll
[      0.058815] Applied      55611 breakpoints (    147863 total breakpoints) kernelbase.dll
...
[      0.667417] Applied      11504 breakpoints (   1466344 total breakpoints) oleacc.dll
[      0.676151] Applied      19557 breakpoints (   1485901 total breakpoints) textinputframework.dll
[      0.705431] Applied      66650 breakpoints (   1552551 total breakpoints) coreuicomponents.dll
[      0.717276] Applied      25202 breakpoints (   1577753 total breakpoints) coremessaging.dll
[      0.720487] Applied       7557 breakpoints (   1585310 total breakpoints) ntmarta.dll
[      0.732045] Applied      28569 breakpoints (   1613879 total breakpoints) iertutil.dll
```

# Usage

To use mesos there are 3 major steps. First, the modules of a running process are saved. Second, these modules are loaded in IDA which then outputs a list of all basic blocks into the `meso` format. And finally, `mesos` is run against a target process to gather coverage!

## Creating meso_deps.zip

This step is the first thing we have to do. We create a ZIP file containing all of the modules loaded into a given PID.

This script requires no internet and is designed to be easily dropped onto new VMs so mesos can be generated for your target application. It depends on PowerShell v5.0 or later which is installed by default on Windows 10 and Windows Server 2016.

Run, with `<pid>` replaced with the process ID you want to gather coverage on:

```
C:\dev\mesos>powershell .\offline_meso.ps1 8484
Powershell is 64-bit: True
Target     is 64-bit: True

C:\dev\mesos>
```

_Optionally you can supply `-OutputZip <zipfile>` to change the output zip file name_

This will create a `meso_deps.zip` that if you look at contains all of the modules used in the process you ran the script targeting.

### Example output:

```
C:\dev\mesos>powershell .\offline_meso.ps1 8484 -OutputZip testing.zip
Powershell is 64-bit: True                                                                                                                                         Target     is 64-bit: True                                                                                                                                                                                                                                                                                                            C:\dev\mesos>powershell Expand-Archive testing.zip -DestinationPath example                                                                                        
C:\dev\mesos>powershell Get-ChildItem example -rec -File -Name
cache\c_\program files\common files\microsoft shared\ink\tiptsf.dll
cache\c_\program files\intel\optaneshellextensions\iastorafsserviceapi.dll
cache\c_\program files\widcomm\bluetooth software\btmmhook.dll
cache\c_\program files (x86)\common files\adobe\coresyncextension\coresync_x64.dll
...
```

## Generating meso files

To generate meso files we operate on the `meso_deps.zip` we created in the last step. It doesn't matter where this zip came from. This allows the zip to have come from a VM that the PowerShell script was run on.

Basic usage is:

```
python generate_mesos.py process_ida
```

This will use the `meso_deps.zip` file as an input, and use IDA to process all executables in the zip file and figure out where their basic blocks are.

This will create a cache folder with a bunch of files in it. These files are named based on the module name, the modules TimeDateStamp in the PE header, and the ImageSize field in the PE header. This is what DLLs are uniqued by in the PDB symbol store, so it should be good enough for us here too.

You'll see there are files with no extension (these are the original binaries), there are files with `.meso` extensions (the breakpoint lists), and `.i64` files (the cached IDA database for the original binary).

### Symbol resolution

There is no limitation on what can make these meso files. The quality of the symbol resolution depends on the tool you used to generate and it's ability to resolve symbols. For example with IDA if you have public/private symbols your `_NT_SYMBOL_PATH` should be configured correctly.

### More advanced usage

Check the programs usage for the most recent usage. But there are `_whitelist` and `_blacklist` options that allow you to use a list of strings to filter the amount of mesos generated.

This is helpful as coverage outside of your target module is probably not relevant and just introduces overheads and unnecessary processing.

```
C:\dev\mesos>python generate_mesos.py
Usage:
    generate_mesos.py process_ida
        Processes all files in the meso_deps.zip file

    generate_mesos.py process_ida_whitelist <str 1> <str 2> <str ...>
        Processes files only containing one of the strings provided

    generate_mesos.py process_ida_blacklist <str 1> <str 2> <str ...>
        Processes files all files except for those containing one of the provided strings

Examples:

    python generate_mesos.py process_ida_whitelist system32
        Only processes files in `system32`

    python generate_mesos.py process_ida_blacklist ntdll.dll
        Process all files except for `ntdll.dll`

Path requirements for process_ida_*: must have `idat64.exe` in your PATH
```

### Example usage

```
C:\dev\mesos>python generate_mesos.py process_ida_whitelist system32
Processing cache/c_/windows/system32/advapi32.dll
Processing cache/c_/windows/system32/bcryptprimitives.dll
Processing cache/c_/windows/system32/cfgmgr32.dll
...
Processing cache/c_/windows/system32/user32.dll
Processing cache/c_/windows/system32/uxtheme.dll
Processing cache/c_/windows/system32/win32u.dll
Processing cache/c_/windows/system32/windows.storage.dll
Processing cache/c_/windows/system32/wintypes.dll
```

## Meso usage

Now we're onto the actual debugger. We've created meso files to tell it where to put breakpoints in each module.

First we need to build it with Rust!

```
cargo build --release
```

And then we can simply run it with a PID!

```
target\release\mesos.exe <pid>
```

### Command-line options

Currently there are few options to mesos, run mesos without arguments to get the most recent list.

```
C:\dev\mesos>target\release\mesos.exe
Usage: mesos.exe <pid> [--freq | --verbose | --print] <explicit meso file 1> <explicit meso file ...>
    --freq               - Treats all breakpoints as frequency breakpoints
    --verbose            - Enables verbose prints for debugging
    --print              - Prints breakpoint info on every single breakpoint
    [explicit meso file] - Load a specific meso file regardless of loaded modules

Standard usage: mesos.exe <pid>
```

### Example usage

```
C:\dev\mesos>target\release\mesos.exe 13828
mesos  is 64-bit: true
target is 64-bit: true
[      0.004033] Applied       5629 breakpoints (      5629 total breakpoints) notepad.exe
[      0.029248] Applied      61334 breakpoints (     66963 total breakpoints) ntdll.dll
[      0.037032] Applied      25289 breakpoints (     92252 total breakpoints) kernel32.dll
[      0.062844] Applied      55611 breakpoints (    147863 total breakpoints) kernelbase.dll
...
[      0.739059] Applied      66650 breakpoints (   1552551 total breakpoints) coreuicomponents.dll
[      0.750266] Applied      25202 breakpoints (   1577753 total breakpoints) coremessaging.dll
[      0.754485] Applied       7557 breakpoints (   1585310 total breakpoints) ntmarta.dll
[      0.766119] Applied      28569 breakpoints (   1613879 total breakpoints) iertutil.dll
...
[     23.544097] Removed 5968 breakpoints in imm32.dll
[     23.551529] Syncing code coverage database...
[     23.675103] Sync complete (169694 total unique coverage entries)
Detached from process 13828
```

#### Why not use `cargo run`?

When running in `cargo run` the Ctrl+C handler does not work correctly, and does not allow us to detach from the target program cleanly.

# Limitations

Since this relies on a tool (IDA) to identify blocks, if the tool incorrectly identifies a block it could result in us inserting a breakpoint over data. Further it's possible to miss coverage if a block is not correctly found.

# Why doesn't it do more?

Well. It really just allows fast breakpoints. Feel free to rip it apart and add your own hooks to functions. It could easily be used to fuzz things :)

# Why IDA?

I tried a bunch of tools and IDA was the only one that seemed to work well. Binja probably would also work well but I don't have it installed and I'm not familiar with the API. I have a coworker who wrote a plugin for it and that'll probably get pull requested in soon.

_The meso files are just simple files, anyone can generate them from any tool_

# Technical Details

## Minidump autogenned filenames

The generated minidump filenames are designed to give a high-level of glance value at crashes. It includes things like the exception type, faulting address, and rough classification of the bug.

Currently if it's an access violation we apply the following classification:

- Determine the access type (read, write, execute)
    - For reads the filename contains: "read"
    - For writes the filename contains: "WRITE"
    - For execute the filename contains: "DEP"
- Determine if it's a non-canonical 64-bit address
    - For non-canonical addresses the filename contains: NONCANON
- Otherwise determine if it's a NULL dereference (within 32 KiB +- of NULL)
    - Will put "null" in the filename
- Otherwise it's considered a non-null deref and "HIGH" appears in the filename

It's intended that more severe things are in all caps to give higher glance value of prioritizing which crash dumps to look into more.

Example minidump filename for chrome:

```
crash_c0000005_chrome_child.dll+0x2c915c0_WRITE_null.dmp
```

## Meso file format

Coming soon (once it's stable)

[meso]: assets/meso_bag.png
[crash saving]: assets/crash_saving.png
[code coverage]: assets/code_coverage.png
[ida coloring]: assets/ida_coloring.png
