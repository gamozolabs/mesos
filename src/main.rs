extern crate winapi;

pub mod debugger;
pub mod minidump;
pub mod sedebug;
pub mod ffi_helpers;
pub mod handles;

use std::path::Path;
use debugger::Debugger;

fn main() {
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
            dbg.load_meso(Path::new(meso));
        }
    }

    // Debug forever
    dbg.run();
}
