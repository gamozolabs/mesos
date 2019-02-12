extern crate debugger;

pub mod mesofile;

use std::path::Path;
use debugger::Debugger;

/// Routine to invoke on module loads
fn modload_handler(dbg: &mut Debugger, modname: &str, base: usize) {
    // Calculate what the filename for a cached meso would be for this module
    let path = mesofile::compute_cached_meso_name(dbg, modname, base);

    // Attempt to load breakpoints from the meso file
    mesofile::load_meso(dbg, &path);
}

fn main() {
    // Usage and argument parsing
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print!("Usage: mesos.exe <pid> [--freq | --verbose | --print] \
               <explicit meso file 1> <explicit meso file ...>\n");
        print!("    --freq               - \
               Treats all breakpoints as frequency breakpoints\n");
        print!("    --verbose            - \
               Enables verbose prints for debugging\n");
        print!("    --print              - \
               Prints breakpoint info on every single breakpoint\n");
        print!("    [explicit meso file] - \
               Load a specific meso file regardless of loaded modules\n\n");

        print!("Standard usage: mesos.exe <pid>\n");
        return;
    }

    // Attach to process
    let mut dbg = Debugger::attach(args[1].parse().unwrap());

    // Register callback routine for module loads so we can attempt to apply
    // breakpoints to it from the meso file cache
    dbg.register_modload_callback(modload_handler);

    // Process arguments
    if args.len() > 2 {
        for meso in &args[2..] {
            if meso == "--freq" {
                // Always do frequency
                print!("Always frequency mode enabled\n");
                dbg.set_always_freq(true);
                continue;
            } else if meso == "--verbose" {
                // Enable verbose mode
                print!("Verbose mode enabled\n");
                dbg.set_verbose(true);
                continue;
            } else if meso == "--print" {
                // Enable breakpoint print mode
                print!("Breakpoint print mode enabled\n");
                dbg.set_bp_print(true);
                continue;
            }

            // Load explicit meso file
            mesofile::load_meso(&mut dbg, Path::new(meso));
        }
    }

    // Debug forever
    dbg.run();
}
