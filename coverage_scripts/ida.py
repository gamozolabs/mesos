import collections, re, math

def addr2block(addr):
    f = idaapi.get_func(addr)
    if not f:
        print "No function at 0x%x" % (addr)
        return None

    fc = idaapi.FlowChart(f)

    for block in fc:
        if (block.startEA <= addr) and (block.endEA > addr):
            return (block.startEA, block.endEA)
    return None

fft = re.compile("[0-9a-f]{16} \| Freq: +([0-9]+) \| +(.*?)\+0x([0-9a-f]+) \| (.*?)\n")

image_base  = idaapi.get_imagebase()
ida_modname = GetInputFile().lower()

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

inp = open(os.path.join(SCRIPT_DIR, "..", "coverage.txt"), "r").read()

# Reset all coloring in all functions
for funcea in Functions():
    f  = idaapi.get_func(funcea)
    fc = idaapi.FlowChart(f)

    for block in fc:
        ea = block.startEA
        while ea <= block.endEA:
            set_color(ea, CIC_ITEM, DEFCOLOR)
            ea = idc.NextHead(ea)

freqs = collections.Counter()

# Parse input coverage file
for thing in fft.finditer(inp):
    freq   = int(thing.group(1), 10)
    module = thing.group(2)
    offset = int(thing.group(3), 16)

    # Skip non-matching modules
    if module.lower() not in ida_modname:
        continue

    freqs[image_base + offset] = freq

# Apply coloring
for addr, freq in freqs.most_common()[::-1]:
    function_addr = get_func_attr(addr, FUNCATTR_START)
    func_entry_freq = freqs[function_addr]

    if func_entry_freq == 0:
        func_entry_freq = 1

    # Log value between [0.0, 1.0)
    dist = math.log(float(freq) / float(func_entry_freq) + 1.0)
    dist = min(dist, float(1.0))

    color = 0x808080 + (int((1 - dist) * 100.0) << 8) + (int(dist * 100.0) << 0)
    print("%10d | 0x%.16x | %s" % (freq, addr, get_func_off_str(addr)))

    blockbounds = addr2block(addr)
    if blockbounds == None:
        # Color just the single PC, we don't know what block it belongs to
        set_color(addr, CIC_ITEM, color)
    else:
        # Color in the entire block
        (ea, block_end) = blockbounds
        while ea < block_end:
            set_color(ea, CIC_ITEM, color)
            ea = idc.NextHead(ea)

    set_cmt(addr, "Freq: %d | Func entry: %.2f" % \
        (freq, float(freq) / float(func_entry_freq)), False)
