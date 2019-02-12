use std::process::Command;
use std::sync::Arc;
use std::time::Instant;
use debugger::{Debugger, BreakpointType};

const NUM_BREAKPOINTS_TO_HIT: u64 = 100000;

/// Get elapsed time in seconds
fn elapsed_from(start: &Instant) -> f64 {
    let dur = start.elapsed();
    dur.as_secs() as f64 + dur.subsec_nanos() as f64 / 1_000_000_000.0
}

fn bp_handler(_dbg: &mut Debugger, _tid: u32, _rip: usize, freq: u64) -> bool {
    if freq == NUM_BREAKPOINTS_TO_HIT {
        return false;
    }

    true
}

fn benchmark_bp_creation() {
    const BREAKPOINTS_TO_APPLY: usize = 1000000;

    // Create new fake process to test performance on
    let mut process = Command::new("fake_program\\program.exe").spawn()
        .expect("Failed to run program");

    // Attach to program process
    let mut dbg = Debugger::attach(process.id());

    let modname = Arc::new(String::from("program.exe"));
    let name    = Arc::new(String::from("wootboot"));

    // Register breakpoints
    let start = Instant::now();
    for offset in 0..BREAKPOINTS_TO_APPLY {
        // These breakpoints are just bogus and don't matter
        let offset = offset + 0x10000;
        dbg.register_breakpoint(modname.clone(), offset, name.clone(),
            offset, BreakpointType::Single, None);
    }
    let elapsed = elapsed_from(&start);

    print!("Registered {:10} breakpoints in {:10.6} seconds | {:10.1} / second\n",
        BREAKPOINTS_TO_APPLY, elapsed, BREAKPOINTS_TO_APPLY as f64 / elapsed);

    // Kill process
    let _ = process.kill();

    // Wait until process exits, which will require all breakpoints to be
    // applied
    let start = Instant::now();
    dbg.run();
    let elapsed = elapsed_from(&start);

    print!("Applied    {:10} breakpoints in {:10.6} seconds | {:10.1} / second\n",
        BREAKPOINTS_TO_APPLY, elapsed, BREAKPOINTS_TO_APPLY as f64 / elapsed);

    // Drop the debugger, clearing breakpoints and detaching
    let start = Instant::now();
    std::mem::drop(dbg);
    let elapsed = elapsed_from(&start);

    print!("Cleared    {:10} breakpoints in {:10.6} seconds | {:10.1} / second\n",
        BREAKPOINTS_TO_APPLY, elapsed, BREAKPOINTS_TO_APPLY as f64 / elapsed);
}

fn benchmark_bp_hit() {
    // Create new fake process to test performance on
    let process = Command::new("fake_program\\program.exe").spawn()
        .expect("Failed to run program");

    // Attach to program process
    let mut dbg = Debugger::attach(process.id());

    let modname = Arc::new(String::from("program.exe"));
    let name    = Arc::new(String::from("wootboot"));

    // Register a real breakpoint, this will get hit in a loop in the fake
    // program we made
    dbg.register_breakpoint(modname.clone(), 0x1000,
        name.clone(), 0, BreakpointType::Freq, Some(bp_handler));

    // Run
    let start = Instant::now();
    dbg.run();
    let elapsed = elapsed_from(&start);

    print!("Hit        {:10} breakpoints in {:10.6} seconds | {:10.1} / second\n",
        NUM_BREAKPOINTS_TO_HIT, elapsed,
        NUM_BREAKPOINTS_TO_HIT as f64 / elapsed);
}

fn main() {
    benchmark_bp_creation();
    benchmark_bp_hit();
}
