from idautils import *
from idaapi import *
from idc import *

# Wait for auto analysis to complete
idaapi.auto_wait()

print("Analysis done, generating meso")

image_base = idaapi.get_imagebase()

SEPARATOR = "\0"

input_name = GetInputFile()
if len(ARGV) >= 4 and ARGV[1] == "cmdline":
    input_name = ARGV[3]

filename = "%s/%s.meso" % (os.path.dirname(os.path.abspath(__file__)), input_name)
if len(ARGV) >= 4 and ARGV[1] == "cmdline":
    filename = ARGV[2]
filename += ".tmp"

with open(filename, "wb") as fd:
    fd.write("module%s%s\n" % (SEPARATOR, input_name))

    for funcea in Functions():
        fd.write("%s%s%x" % (get_func_off_str(funcea),
            SEPARATOR, funcea - image_base))

        for block in idaapi.FlowChart(idaapi.get_func(funcea)):
            if is_code(getFlags(block.startEA)):
                fd.write("%ss%x" % (SEPARATOR, block.startEA - funcea))
        
        fd.write("\n")

# Rename .tmp file to actual name
os.rename(filename, filename[:-4])

print("Generated meso: %s" % filename[:-4])

# Exit only if we were invoked from the command line
if len(ARGV) >= 4 and ARGV[1] == "cmdline":
    idc.Exit(0)
