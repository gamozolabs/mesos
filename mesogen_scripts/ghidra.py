#Generates a Mesos file from the current program.
#@author marpie (Markus Piéton - marpie@a12d404.net)
#@category Mesos
#@keybinding
#@menupath
#@toolbar

import struct
import ghidra.program.model.block.SimpleBlockModel as SimpleBlockModel

def get_simple_blocks_by_function(image_base, listing):
    model = SimpleBlockModel(currentProgram)

    entries = {}
    block_iter = model.getCodeBlocks(monitor)
    while block_iter.hasNext() and (not monitor.isCancelled()):
        block = block_iter.next()
        for block_addr in block.getStartAddresses():
            if monitor.isCancelled():
                break
            block_offset = block_addr.getOffset() - image_base

            func_name = block.getName()
            func_offset = 0
            func_offset_rel = 0
            func_of_block = listing.getFunctionContaining(block_addr)
            if func_of_block:
                func_name = func_of_block.getName()
                func_offset = func_of_block.getEntryPoint().getOffset()
                func_offset_rel = func_offset - image_base
                block_offset = block_addr.getOffset() - func_offset
            
            try:
                entries["{}_{}".format(func_offset_rel,func_name)][2].append(block_offset)
            except KeyError:
                entries["{}_{}".format(func_offset_rel,func_name)] = [func_offset_rel, func_name, [block_offset]]
    
    return entries

ghidra_file = askFile("Please select the Mesos Output-File", "Save To File")

with open(ghidra_file.getAbsolutePath(), "wb") as fd:
    input_name = currentProgram.getName()
    image_base = currentProgram.getImageBase().getOffset()

    listing = currentProgram.getListing()

    # Write record type 0 (module)
    # unsigned 16-bit module name
    # And module name
    fd.write(struct.pack("<BH", 0, len(input_name)) + input_name)

    for func_offset, func_name, blocks in get_simple_blocks_by_function(image_base, listing).values():
        # Write record type 1 (function) and unsigned 16-bit function name length
        fd.write(struct.pack("<BH", 1, len(func_name)))
        # Write function name
        fd.write(func_name)

        # Write unsigned 64-bit offset of the function WRT the module base
        fd.write(struct.pack("<Q", func_offset))

        blocks = list(set(blocks))
        blocks.sort()

        blockoffs = bytearray()
        for offset in blocks:
            # Write signed 32-bit offset from base of function
            blockoffs += struct.pack("<i", offset)

        # Unsigned 32-bit number of blocks
        fd.write(struct.pack("<I", len(blockoffs) / 4))
        fd.write(blockoffs)
