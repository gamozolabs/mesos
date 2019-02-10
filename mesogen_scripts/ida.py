from idautils import *
from idaapi import *
from idc import *
import struct

# Wait for auto analysis to complete
idaapi.auto_wait()

print("Analysis done, generating meso")

image_base = idaapi.get_imagebase()

input_name = GetInputFile()
if len(ARGV) >= 4 and ARGV[1] == "cmdline":
    input_name = ARGV[3]

filename = "%s/%s.meso" % (os.path.dirname(os.path.abspath(__file__)), input_name)
if len(ARGV) >= 4 and ARGV[1] == "cmdline":
    filename = ARGV[2]
filename += ".tmp"

with open(filename, "wb") as fd:
    # Write record type 0 (module)
    # unsigned 16-bit module name
    # And module name
    fd.write(struct.pack("<BH", 0, len(input_name)) + input_name)

    for funcea in Functions():
        funcname = get_func_off_str(funcea)

        # Write record type 1 (function)
        # Write unsigned 16-bit function name length and function name
        fd.write(struct.pack("<BH", 1, len(funcname)) + funcname)

        # Write unsigned 64-bit offset of the function WRT the module base
        fd.write(struct.pack("<Q", funcea - image_base))

        blockoffs = bytearray()
        for block in idaapi.FlowChart(idaapi.get_func(funcea)):
            if is_code(getFlags(block.startEA)):
                # Write signed 32-bit offset from base of function
                blockoffs += struct.pack("<i", block.startEA - funcea)
        
        # Unsigned 32-bit number of blocks
        fd.write(struct.pack("<I", len(blockoffs) / 4))
        fd.write(blockoffs)

# Rename .tmp file to actual name
os.rename(filename, filename[:-4])

print("Generated meso: %s" % filename[:-4])

# Exit only if we were invoked from the command line
if len(ARGV) >= 4 and ARGV[1] == "cmdline":
    idc.Exit(0)
