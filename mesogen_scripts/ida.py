from idautils import *
from idaapi import *
from idc import *

# Wait for auto analysis to complete
idaapi.auto_wait()

print("Analysis done, generating meso")

image_base = idaapi.get_imagebase()

output = bytearray()

SEPERATOR = "~~ed6ed28d321bbdc8~~"

input_name = GetInputFile()

if len(ARGV) >= 4 and ARGV[1] == "cmdline":
    input_name = ARGV[3]

for funcea in Functions():
    f  = idaapi.get_func(funcea)
    fc = idaapi.FlowChart(f)

    for block in fc:
        if is_code(getFlags(block.startEA)):
            output += "%s%s%s%s%x%s%s\n" % \
                    ("single", SEPERATOR,
                     input_name, SEPERATOR,
                     block.startEA - image_base, SEPERATOR,
                     get_func_off_str(block.startEA))

filename = "%s/%s.meso" % (os.path.dirname(os.path.abspath(__file__)), input_name)
if len(ARGV) >= 4 and ARGV[1] == "cmdline":
    filename = ARGV[2]

open(filename, "wb").write(output)

print("Generated meso: %s" % filename)

# Exit only if we were invoked from the command line
if len(ARGV) >= 4 and ARGV[1] == "cmdline":
    idc.Exit(0)

