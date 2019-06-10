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

    // mesos.exe -p pid mesos_file0 mesos_file1 mesos_file2 
    // or mesos.exe mesos_file0 mesos_file1 mesos_file2 -- ./exe arg0 arg1 arg2

    // Usage and argument parsing
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print!("Usage: mesos.exe -p <pid> <options> <mesos files>\n");
        print!("    or mesos.exe <options> <mesos files> -- program.exe <arguments>\n");
        print!("    --freq               - \
               Treats all breakpoints as frequency breakpoints\n");
        print!("    --verbose            - \
               Enables verbose prints for debugging\n");
        print!("    --print              - \
               Prints breakpoint info on every single breakpoint\n");
        print!("    --follow-fork        - \
               Capture coverage for child processes\n");
        print!("    [explicit meso file] - \
               Load a specific meso file regardless of loaded modules\n\n");

        return;
    }


    let mut pid: Option<u32> = None;
    let mut frequency_mode_enabled = false;
    let mut verbose_mode_enabled = false;
    let mut follow_fork_enabled = false;
    let mut print_breakpoints_enabled = false;
    let mut mesos: Vec<&Path> = Vec::new();

    let mut argv: Vec<String> = Vec::new();

    if args.len() > 2 {
        for (ii, arg) in args[1..].iter().enumerate() {
            if arg == "-p" {
                pid = Some(args.get(ii + 2)
                .expect("No PID specified with -p argument").parse().unwrap());
            }
            else if arg == "--verbose" {
                verbose_mode_enabled = true;
            }
            else if arg == "--print" { 
                print_breakpoints_enabled = true;
            }
            else if arg == "--freq" { 
                frequency_mode_enabled = true;
            }
            else if arg == "--follow-fork" {
                follow_fork_enabled = true;
            }
            else if arg == "--" {
                argv.extend_from_slice(&args[ii + 2..]);
                break;
            }
            else { // Has to be a mesofile
                //mesofile::load_meso(&mut dbg, Path::new(arg));
                mesos.push(Path::new(arg));
            }
        }
    }

    let mut dbg:Debugger;
    if pid.is_none() && argv.len() > 0 {
        dbg = Debugger::spawn_proc(&argv, follow_fork_enabled);
    }
    else {
        dbg = Debugger::attach(pid.unwrap() as u32);
    }

    // Attach to process

    dbg.set_always_freq(frequency_mode_enabled);
    dbg.set_verbose(verbose_mode_enabled);
    dbg.set_bp_print(print_breakpoints_enabled);

    for mesofile in mesos {
        mesofile::load_meso(&mut dbg, mesofile);
    }

    // Register callback routine for module loads so we can attempt to apply
    // breakpoints to it from the meso file cache
    dbg.register_modload_callback(Box::new(modload_handler));

    // Debug forever
    dbg.run();
}

