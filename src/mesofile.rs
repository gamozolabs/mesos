use std::path::{Path, PathBuf};
use std::sync::Arc;
use debugger::{Debugger, BreakpointType};

/// Grab a native-endianness u32 from a slice of u8s
fn u32_from_slice(val: &[u8]) -> u32 {
    let mut tmp = [0u8; 4];
    tmp.copy_from_slice(&val[..4]);
    u32::from_ne_bytes(tmp)
}

/// Computes the path to the cached meso filename for a given module loaded
/// at `base`
pub fn compute_cached_meso_name(dbg: &mut Debugger, filename: &str,
        base: usize) -> PathBuf {    
    let mut image_header = [0u8; 4096];

    // Read the image header at `base`
    assert!(dbg.read_mem(base, &mut image_header) ==
        std::mem::size_of_val(&image_header),
        "Failed to read PE image header from target");

    // Validate this is a PE
    assert!(&image_header[0..2] == b"MZ", "File was not MZ");
    let pe_ptr = u32_from_slice(&image_header[0x3c..0x40]) as usize;
    assert!(&image_header[pe_ptr..pe_ptr+4] == b"PE\0\0");

    // Get TimeDateStamp and ImageSize from the PE header
    let timestamp = u32_from_slice(&image_header[pe_ptr+8..pe_ptr+0xc]);
    let imagesz   =
        u32_from_slice(&image_header[pe_ptr+0x50..pe_ptr+0x54]);

    // Compute the meso name
    format!("cache\\{}_{:x}_{:x}.meso", filename, timestamp, imagesz).into()
}

/// Load a meso file based on `meso_path` and apply breakpoints as requested to
/// the `Debugger` specified by `dbg`
pub fn load_meso(dbg: &mut Debugger, meso_path: &Path) {
    // Do nothing if the file doesn't exist
    if !meso_path.is_file() {
        return;
    }

    // Read the file
    let meso: Vec<u8> = std::fs::read(meso_path).expect("Failed to read meso");

    // Current module name we are processing
    let mut cur_modname: Option<Arc<String>> = None;

    // Pointer to the remainder of the file
    let mut ptr = &meso[..];

    // Read a `$ty` from the mesofile
    macro_rules! read {
        ($ty:ty) => {{
            let mut array = [0; std::mem::size_of::<$ty>()];
            array.copy_from_slice(&ptr[..std::mem::size_of::<$ty>()]);
            ptr = &ptr[std::mem::size_of::<$ty>()..];
            <$ty>::from_le_bytes(array)
        }};
    }

    while ptr.len() > 0 {        
        // Get record type
        let record = read!(u8);

        if record == 0 {
            // Module record
            let modname_len = read!(u16);

            // Convert name to Rust str
            let modname = std::str::from_utf8(&ptr[..modname_len as usize])
                .expect("Module name was not valid UTF-8");
            ptr = &ptr[modname_len as usize..];

            cur_modname = Some(Arc::new(modname.into()));
        } else if record == 1 {
            // Current module name state
            let module: &Arc<String> = cur_modname.as_ref().unwrap();

            // Function record
            let funcname_len = read!(u16);

            // Convert name to Rust str
            let funcname: Arc<String> =
                Arc::new(std::str::from_utf8(&ptr[..funcname_len as usize])
                    .expect("Function name was not valid UTF-8")
                    .to_string());
            ptr = &ptr[funcname_len as usize..];

            // Get function offset from module base
            let funcoff = read!(u64) as usize;

            // Get number of basic blocks
            let num_blocks = read!(u32) as usize;

            // Iterate over all block offsets
            for _ in 0..num_blocks {
                let blockoff = read!(i32) as isize as usize;

                // Add function offset from module base to offset
                let offset = funcoff.wrapping_add(blockoff);

                // Register this breakpoint
                dbg.register_breakpoint(module.clone(), offset,
                    funcname.clone(), blockoff, BreakpointType::Single, None);
            }
        } else {
            panic!("Unhandled record");
        }
    }
}
