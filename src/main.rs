extern crate winapi;

use winapi::um::debugapi;
use winapi::um::winbase;
use winapi::um::fileapi;
use winapi::um::memoryapi;
use winapi::um::processthreadsapi;
use winapi::um::winnt::CONTEXT;
use winapi::um::winnt::DBG_CONTINUE;
use winapi::um::winnt::DBG_EXCEPTION_NOT_HANDLED;
use winapi::um::winnt::CONTEXT_ALL;
use winapi::um::winnt::HANDLE;
use winapi::um::winnt::TOKEN_PRIVILEGES;
use winapi::um::winnt::TOKEN_ADJUST_PRIVILEGES;
use winapi::um::winnt::TOKEN_QUERY;
use winapi::um::winnt::SE_PRIVILEGE_ENABLED;
use winapi::um::winnt::EXCEPTION_POINTERS;
use winapi::um::winnt::GENERIC_READ;
use winapi::um::winnt::GENERIC_WRITE;
use winapi::um::winnt::EXCEPTION_RECORD;
use winapi::um::fileapi::CREATE_NEW;
use winapi::um::errhandlingapi;
use winapi::um::handleapi;
use winapi::um::securitybaseapi;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::minwinbase::CREATE_PROCESS_DEBUG_EVENT;
use winapi::um::minwinbase::CREATE_THREAD_DEBUG_EVENT;
use winapi::um::minwinbase::EXCEPTION_DEBUG_EVENT;
use winapi::um::minwinbase::LOAD_DLL_DEBUG_EVENT;
use winapi::um::minwinbase::EXIT_THREAD_DEBUG_EVENT;
use winapi::um::minwinbase::EXIT_PROCESS_DEBUG_EVENT;
use winapi::um::minwinbase::UNLOAD_DLL_DEBUG_EVENT;
use winapi::um::minwinbase::OUTPUT_DEBUG_STRING_EVENT;
use winapi::um::minwinbase::RIP_EVENT;
use winapi::um::consoleapi::SetConsoleCtrlHandler;
use winapi::shared::winerror::ERROR_SEM_TIMEOUT;
use winapi::um::debugapi::DebugActiveProcessStop;
use winapi::um::winbase::InitializeContext;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::wow64apiset::IsWow64Process;
use winapi::um::winnt::PROCESS_QUERY_LIMITED_INFORMATION;
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::psapi::GetMappedFileNameW;

use std::time::{Duration, Instant};
use std::collections::{HashSet, HashMap};
use std::path::Path;
use std::sync::Arc;
use std::fs::File;
use std::io::Write;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::iter::once;
use std::sync::atomic::{AtomicBool, Ordering};
use std::io::BufWriter;

/// Separator used in mesos files
/// This is just a "random" string to allow us to not have to worry about
/// escaping strings that contain our separator. We just split on this
const SEPARATOR: &str = "\0";

/// Tracks if an exit has been requested via the Ctrl+C/Ctrl+Break handler
static EXIT_REQUESTED: AtomicBool = AtomicBool::new(false);

unsafe extern "system" fn ctrl_c_handler(_ctrl_type: u32) -> i32 {
    // Store that an exit was requested
    EXIT_REQUESTED.store(true, Ordering::SeqCst);

    // Sleep forever
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[repr(C)]
pub enum MinidumpType {
    MiniDumpNormal                         = 0x00000000,
    MiniDumpWithDataSegs                   = 0x00000001,
    MiniDumpWithFullMemory                 = 0x00000002,
    MiniDumpWithHandleData                 = 0x00000004,
    MiniDumpFilterMemory                   = 0x00000008,
    MiniDumpScanMemory                     = 0x00000010,
    MiniDumpWithUnloadedModules            = 0x00000020,
    MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
    MiniDumpFilterModulePaths              = 0x00000080,
    MiniDumpWithProcessThreadData          = 0x00000100,
    MiniDumpWithPrivateReadWriteMemory     = 0x00000200,
    MiniDumpWithoutOptionalData            = 0x00000400,
    MiniDumpWithFullMemoryInfo             = 0x00000800,
    MiniDumpWithThreadInfo                 = 0x00001000,
    MiniDumpWithCodeSegs                   = 0x00002000,
    MiniDumpWithoutAuxiliaryState          = 0x00004000,
    MiniDumpWithFullAuxiliaryState         = 0x00008000,
    MiniDumpWithPrivateWriteCopyMemory     = 0x00010000,
    MiniDumpIgnoreInaccessibleMemory       = 0x00020000,
    MiniDumpWithTokenInformation           = 0x00040000,
    MiniDumpWithModuleHeaders              = 0x00080000,
    MiniDumpFilterTriage                   = 0x00100000,
    MiniDumpWithAvxXStateContext           = 0x00200000,
    MiniDumpWithIptTrace                   = 0x00400000,
    MiniDumpValidTypeFlags                 = 0x007fffff,
}

#[link(name = "dbghelp")]
extern "system" {
    pub fn MiniDumpWriteDump(hProcess: HANDLE, processId: u32,
                             hFile: HANDLE, DumpType: u32,
                             exception: *const MinidumpExceptionInformation,
                             userstreamparam: usize,
                             callbackParam: usize) -> i32;
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct MinidumpExceptionInformation {
    thread_id:       u32,
    exception:       *const EXCEPTION_POINTERS,
    client_pointers: u32,
}

/// Different types of breakpoints
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BreakpointType {
    /// Keep the breakpoint in place and keep track of how many times it was
    /// hit
    Freq,

    /// Delete the breakpoint after it has been hit once
    Single,
}

/// Structure to represent breakpoints
#[derive(Clone, Debug)]
pub struct Breakpoint {
    /// Offset from module base
    offset: usize,

    /// Tracks if this breakpoint is currently active
    enabled: bool,

    /// Original byte that was at this location, only set if breakpoint was
    /// ever applied
    orig_byte: Option<u8>,

    /// Tracks if this breakpoint should stick around after it's hit once
    typ: BreakpointType,

    /// Name of the function this breakpoint is in
    funcname: Arc<String>,

    /// Offset into the function that this breakpoint addresses
    funcoff:  usize,

    /// Module name
    modname: Arc<String>,
}

pub struct Debugger<'a> {
    /// List of breakpoints we want to apply, keyed by module
    /// This is not the _active_ list of breakpoints, it only refers to things
    /// we would like to apply if we see this module show up
    target_breakpoints: HashMap<String, Vec<Breakpoint>>,

    /// List of potentially active breakpoints, keyed by linear address
    /// They may be optionally disabled via `Breakpoint.enabled`
    breakpoints: HashMap<usize, Breakpoint>,

    /// Tracks the minimum and maximum addresses for breakpoints per module
    minmax_breakpoint: HashMap<String, (usize, usize)>,

    /// Handle to the process, given by the first create process event so it
    /// is not present until `run()` is used
    process_handle: Option<HANDLE>,

    /// Thread ID to handle map
    thread_handles: HashMap<u32, HANDLE>,

    /// List of all PCs we hit during execution
    /// Keyed by PC
    /// Tuple is (module, offset, symbol+offset, frequency)
    coverage: HashMap<usize, (Arc<String>, usize, String, u64)>,

    /// Set of DLL names and the corresponding DLL base
    modules: HashSet<(String, usize)>,

    /// TIDs actively single stepping mapped to the PC they stepped from
    single_step: HashMap<u32, usize>,

    /// Always do frequency tracking. Disables printing to screen and updates
    /// the coverage database on an interval to decrease I/O
    always_freq: bool,

    /// Last time we saved the coverage database
    last_db_save: Instant,

    /// Prints some more status information during runtime
    verbose: bool,

    /// Process ID of the process we're debugging
    pid: u32,

    /// Time we attached to the target at
    start_time: Instant,

    /// Prints breakpoints as we hit them if set
    bp_print: bool,

    /// Pointer to aligned context structure
    context: &'a mut CONTEXT,
    _context_backing: Vec<u8>,
}

/// Get elapsed time in seconds
fn elapsed_from(start: &Instant) -> f64 {
    let dur = start.elapsed();
    dur.as_secs() as f64 + dur.subsec_nanos() as f64 / 1_000_000_000.0
}

fn u32_from_slice(val: &[u8]) -> u32 {
    assert!(val.len() == 4);
    ((val[0] as u32) <<  0) |
    ((val[1] as u32) <<  8) |
    ((val[2] as u32) << 16) |
    ((val[3] as u32) << 24)
}

// Mesos print with uptime prefix
macro_rules! mprint {
    ($x:ident, $($arg:tt)*) => {
        print!("[{:14.6}] ", elapsed_from(&$x.start_time));
        print!($($arg)*);
    }
}

impl<'a> Debugger<'a> {
    /// Create a new debugger and attach to `pid`
    pub fn attach(pid: u32) -> Debugger<'a> {
        let start_time = Instant::now();

        unsafe {
            let handle = 
                OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            assert!(handle != std::ptr::null_mut(), "OpenProcess() failed");

            let mut cur_is_wow64    = 0i32;
            let mut target_is_wow64 = 0i32;

            assert!(IsWow64Process(handle, &mut target_is_wow64) != 0,
                "IsWow64Process() failed");

            assert!(IsWow64Process(GetCurrentProcess(),
                &mut cur_is_wow64) != 0, "IsWow64Process() failed");

            print!("mesos  is 64-bit: {}\n", cur_is_wow64 == 0);
            print!("target is 64-bit: {}\n", target_is_wow64 == 0);

            // Validate target process is the same bitness as we are
            assert!(cur_is_wow64 == target_is_wow64,
                "Target process does not match mesos bitness");
            
            assert!(debugapi::DebugActiveProcess(pid) != 0,
                "Failed to attach to process, is your PID valid \
                 and do you have correct permissions?");
        }

        // Correctly initialize a context so it's aligned. We overcommit
        // with `buf` to give room for the CONTEXT to slide for alignment
        let mut cptr: *mut CONTEXT = std::ptr::null_mut();
        let mut context_backing =
            vec![0u8; std::mem::size_of::<CONTEXT>() + 4096];
        let mut clen: u32 = context_backing.len() as u32;

        unsafe {
            assert!(InitializeContext(
                context_backing.as_mut_ptr() as *mut _,
                CONTEXT_ALL, 
                &mut cptr, &mut clen) != 0,
                "InitializeContext() failed");
        }

        Debugger {
            target_breakpoints: HashMap::new(),
            breakpoints:        HashMap::new(),
            process_handle:     None,
            thread_handles:     HashMap::new(),
            coverage:           HashMap::new(),
            minmax_breakpoint:  HashMap::new(),
            modules:            HashSet::new(),
            single_step:        HashMap::new(),
            always_freq:        false,
            last_db_save:       Instant::now(),
            verbose:            false,
            bp_print:           false,
            pid, start_time,

            context:
                unsafe { &mut *(context_backing.as_mut_ptr() as *mut CONTEXT) },
            _context_backing:   context_backing, 
        }
    }

    /// Loads all breakpoints applicable to the mapped file at `base`
    pub fn load_breakpoints(&mut self, base: usize) {
        let path = self.compute_cached_meso_name(base);
        self.load_meso_from_cache(path);
    }

    /// Load a meso from the cache based on `path`
    pub fn load_meso_from_cache(&mut self, path: String) {
        // Create the cache file name
        let cache_path = Path::new(&path);

        if !cache_path.is_file() {
            if self.verbose {
                mprint!(self, "No meso in cache for {}, ignoring\n", path);
            }
            return;
        }

        // Load the meso
        self.load_meso(cache_path);
    }

    /// Load a meso file, declaring the breakpoints to apply
    pub fn load_meso(&mut self, meso_path: &Path) {
        // Read the file
        let meso = std::fs::read_to_string(meso_path)
            .expect("Failed to read meso");

        let mut added_breakpoints = 0;

        let start_time = Instant::now();

        // Current module name we are processing
        let mut cur_modname: Option<Arc<String>> = None;

        // Go through each line
        for line in meso.lines() {            
            // Parse the CSV
            let mut record: Vec<&str> =
                line.split(SEPARATOR).collect();

            // Module record
            if record.len() == 2 && record[0] == "module" {
                cur_modname = Some(Arc::new(record[1].to_string()));
            } else if record.len() >= 3 {
                let funcname = Arc::new(record[0].to_string());
                let bdiff    = usize::from_str_radix(record[1], 16).unwrap();

                let module: &Arc<String> = cur_modname.as_ref().unwrap();

                for ent in record[2..].iter() {
                    let typ = match &ent[0..1] {
                        "f" => BreakpointType::Freq,
                        "s" => BreakpointType::Single,
                        _   => panic!("Invalid breakpoint type"),
                    };

                    // Skip negative offsets. They can happen
                    if &ent[1..2] == "-" {
                        continue;
                    }

                    // Get offset in function for this breakpoint
                    let funcoff = usize::from_str_radix(&ent[1..], 16).unwrap();

                    // Add function offset from module base to offset
                    let offset  = bdiff + funcoff;

                    // Create a new entry if none exist
                    if !self.target_breakpoints.contains_key(&**module) {
                        self.target_breakpoints.insert(module.to_string(), Vec::new());
                    }

                    if !self.minmax_breakpoint.contains_key(&**module) {
                        self.minmax_breakpoint.insert(module.to_string(), (!0, 0));
                    }

                    let mmbp = self.minmax_breakpoint.get_mut(&**module).unwrap();
                    mmbp.0 = std::cmp::min(mmbp.0, offset);
                    mmbp.1 = std::cmp::max(mmbp.1, offset);

                    // Append this breakpoint
                    self.target_breakpoints.get_mut(&**module).unwrap().push(
                        Breakpoint {
                            offset:    offset,
                            enabled:   false,
                            typ:       typ,
                            orig_byte: None,
                            funcname:  funcname.clone(),
                            funcoff:   funcoff,
                            modname:   module.clone(),
                        }
                    );

                    added_breakpoints += 1;
                }
            } else {
                panic!("Unknown record in meso");
            }
        }

        if self.verbose {
            let ef = elapsed_from(&start_time);
            mprint!(self, "Loaded meso file {:?} in {:.6} seconds, requesting {} breakpoints when \
                   module is loaded [{:.0} bps/sec]\n",
                meso_path, ef, added_breakpoints,
                added_breakpoints as f64 / ef);
        }
    }

    /// Resolves the file name of a given memory mapped file in the target
    /// process
    pub fn filename_from_module_base(&self, base: usize) -> String {
        // Use GetMappedFileNameW() to get the mapped file name
        let mut buf = [0u16; 4096];
        let fnlen = unsafe {
            GetMappedFileNameW(self.process_handle.unwrap(),
                base as *mut _, buf.as_mut_ptr(), buf.len() as u32)
        };
        assert!(fnlen != 0 && (fnlen as usize) < buf.len(),
            "GetMappedFileNameW() failed");

        // Convert the name to utf-8 and lowercase it
        let path = String::from_utf16(&buf[..fnlen as usize]).unwrap()
            .to_lowercase();

        // Get the filename from the path
        Path::new(&path).file_name().unwrap().to_str().unwrap().into()
    }

    /// Computes the path to the cached meso filename for a given module loaded
    /// at `base`
    pub fn compute_cached_meso_name(&self, base: usize) -> String {
        // Get base filename
        let filename = self.filename_from_module_base(base);
        
        let mut image_header = [0u8; 4096];

        // Read the image header at `base`
        assert!(self.read_mem(base, &mut image_header) ==
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
        format!("cache\\{}_{:x}_{:x}.meso", filename, timestamp, imagesz)
    }

    /// Reads from `addr` in the process we're debugging into `buf`
    /// Returns number of bytes read
    pub fn read_mem(&self, addr: usize, buf: &mut [u8]) -> usize {
        let mut offset = 0;

        // Read until complete
        while offset < buf.len() {
            let mut bread = 0;

            unsafe {
                // Issue a read
                if memoryapi::ReadProcessMemory(
                        self.process_handle.unwrap(), (addr + offset) as *mut _,
                        buf.as_mut_ptr().offset(offset as isize) as *mut _,
                        buf.len() - offset, &mut bread) == 0 {
                    // Return out on error
                    return offset;
                }
                assert!(bread > 0);
            }

            offset += bread;
        }

        offset
    }

    /// Writes `buf` to `addr` in the process we're debugging
    /// Returns number of bytes written
    pub fn write_mem(&self, addr: usize, buf: &[u8]) -> usize {
        let mut offset = 0;

        // Write until complete
        while offset < buf.len() {
            let mut bread = 0;

            unsafe {
                // Issue a write
                if memoryapi::WriteProcessMemory(
                        self.process_handle.unwrap(), (addr + offset) as *mut _,
                        buf.as_ptr().offset(offset as isize) as *const _,
                        buf.len() - offset, &mut bread) == 0 {
                    // Return out on error
                    return offset;
                }
                assert!(bread > 0);
            }

            offset += bread;
        }

        offset
    }

    /// Flush all instruction caches in the target process
    pub fn flush_instruction_caches(&self) {
        unsafe {
            // Flush all instruction caches for the process
            assert!(processthreadsapi::FlushInstructionCache(
                    self.process_handle.unwrap(),
                    0 as *const _, 0) != 0);
        }
    }

    pub fn register_module(&mut self, base: usize) {
        let filename = self.filename_from_module_base(base);

        // Insert into the module list
        self.modules.insert((filename.into(), base));
    }

    pub fn unregister_module(&mut self, base: usize) {
        let mut to_remove = None;

        // Find the corresponding module to this base
        for module in self.modules.iter() {
            if module.1 == base {
                to_remove = Some(module.clone());
            }
        }

        if let Some(to_remove) = to_remove {
            // Remove the module and breakpoint info for the module
            self.modules.remove(&to_remove);
        } else {
            // Got unregister module for unknown DLL
            // Our database is out of sync with reality
            panic!("Unexpected DLL unload of base 0x{:x}\n", base);
        }
    }

    pub fn apply_breakpoints(&mut self, base: usize) {
        let filename = self.filename_from_module_base(base);

        // Bail if we don't have requested breakpoints for this module
        if !self.minmax_breakpoint.contains_key(&filename) {
            return;
        }

        // Save number of breakpoints at this function start
        let startbps = self.breakpoints.len();

        let mut minmax = self.minmax_breakpoint[&filename];

        // Convert this to a non-inclusive upper bound
        minmax.1 = minmax.1.checked_add(1).unwrap();

        // Compute the size of all memory between the minimum and maximum
        // breakpoint offsets
        let region_size = minmax.1.checked_sub(minmax.0).unwrap() as usize;

        let mut contents = vec![0u8; region_size];

        // Read all memory of this DLL that includes breakpoints
        // On partial reads that's fine, we'll only do a partial write later.
        let _ = self.read_mem(base + minmax.0, &mut contents);

        // Attempt to apply all requested breakpoints
        for breakpoint in self.target_breakpoints.get(&filename).unwrap() {
            let mut bp = breakpoint.clone();
            bp.enabled = true;

            let bufoff =
                (breakpoint.offset as usize)
                .checked_sub(minmax.0 as usize).unwrap();

            // Save the original byte
            bp.orig_byte = Some(contents[bufoff]);

            // Add in a breakpoint
            contents[bufoff] = 0xcc;

            if !self.breakpoints.contains_key(&(base + breakpoint.offset)) {
                self.breakpoints.insert(base + breakpoint.offset, bp);
            } else {
                // Silently ignore duplicate breakpoints
            }
        }

        // Write in all the breakpoints
        // If it partially writes then that's fine, we just apply the
        // breakpoints we can
        let _ = self.write_mem(base + minmax.0, &contents);
        self.flush_instruction_caches();

        mprint!(self, "Applied {:10} breakpoints ({:10} total breakpoints) {}\n",
            self.breakpoints.len() - startbps,
            self.breakpoints.len(), filename);

        return;
    }

    /// Remove all breakpoints, restoring the process to a clean state
    pub fn remove_breakpoints(&mut self) {
        for (module, base) in self.modules.iter() {
            if !self.minmax_breakpoint.contains_key(module) {
                // Ignore modules we have no applied breakpoints for
                continue;
            }

            // Get minimum and maximum offsets into the module where
            // breakpoints are applied
            let minmax = self.minmax_breakpoint[module];

            // Compute the size of all memory between the minimum and maximum
            // breakpoint offsets
            let region_size = minmax.1.checked_add(1).unwrap()
                .checked_sub(minmax.0).unwrap() as usize;

            let mut contents = vec![0u8; region_size];

            // Read all memory of this DLL that includes breakpoints
            // On partial reads that's fine, we'll only do a partial write
            // later.
            self.read_mem(base + minmax.0, &mut contents);

            let mut removed_bps = 0u64;

            // Restore all bytes that we applied breakpoints to
            for (_, bp) in self.breakpoints.iter_mut() {
                // Skip breakpoints not in this module
                if &*bp.modname != module {
                    continue;
                }

                let bufoff =
                    (bp.offset as usize)
                    .checked_sub(minmax.0 as usize).unwrap();

                // Restore original byte
                if let Some(byte) = bp.orig_byte {
                    contents[bufoff] = byte;
                    bp.enabled = false;
                    removed_bps += 1;
                }
            }

            // Remove all the breakpoints
            // On partial removes it's fine. If we can't write to the memory
            // it's not mapped in, so we can just ignore partial writes here.
            let _ = self.write_mem(base + minmax.0, &contents);
            self.flush_instruction_caches();

            mprint!(self, "Removed {} breakpoints in {}\n", removed_bps, module);
        }

        // Sanity check that all breakpoints have been removed
        for (_, bp) in self.breakpoints.iter() {
            assert!(!bp.enabled,
                "Unexpected breakpoint left enabled \
                 after remove_breakpoints()")
        }
    }

    /// Handle a breakpoint
    pub fn handle_breakpoint(&mut self, tid: u32, addr: usize) -> bool {
        if let Some(ref mut bp) = self.breakpoints.get_mut(&addr).cloned() {
            // If we apply a breakpoint over an actual breakpoint just exit
            // out now
            if bp.orig_byte == Some(0xcc) {
                return true;
            }
            
            // Sometimes this can race so we just don't assert this anymore
            //assert!(bp.enabled);

            let mut orig_byte = [0u8; 1];
            orig_byte[0] = bp.orig_byte.unwrap();

            assert!(self.write_mem(addr, &orig_byte) == 1);
            self.flush_instruction_caches();

            let funcoff = format!("{}+0x{:x}", bp.funcname, bp.funcoff);

            if !self.coverage.contains_key(&addr) {
                self.coverage.insert(addr,
                    (bp.modname.clone(), bp.offset, funcoff.clone(), 0));
            }
            let freq = {
                let bin = self.coverage.get_mut(&addr).unwrap();
                bin.3 += 1;
                bin.3
            };

            // Print coverage as we get it
            if self.bp_print {
                mprint!(self, "{:8} of {:8} hit | {:10} freq | 0x{:x} | \
                        {:>20}+0x{:08x} | {}\n",
                    self.coverage.len(), self.breakpoints.len(),
                    freq,
                    addr, bp.modname, bp.offset, funcoff);
            }

            self.get_context(tid);

            // Back up so we re-execute where the breakpoint was

            #[cfg(target_pointer_width = "64")]
            { self.context.Rip = addr as u64; }

            #[cfg(target_pointer_width = "32")]
            { self.context.Eip = addr as u32; }

            // Single step if this is a frequency instruction
            if self.always_freq || bp.typ == BreakpointType::Freq {
                // Set the trap flag
                self.context.EFlags |= 1 << 8;
                self.single_step.insert(tid, addr);
            } else {
                // Breakpoint no longer enabled
                bp.enabled = false;
            }

            self.set_context(tid);
        } else {
            // Hit unexpected breakpoint
            return false;
        }

        true
    }

    /// Get a thread context
    pub fn get_context(&mut self, tid: u32) {
        unsafe {
            assert!(processthreadsapi::GetThreadContext(
                    self.thread_handles[&tid], self.context) != 0);
        }
    }

    /// Set a thread context
    pub fn set_context(&mut self, tid: u32) {
        unsafe {
            assert!(processthreadsapi::SetThreadContext(
                    self.thread_handles[&tid], self.context) != 0);
        }
    }

    /// Get a filename to describe a given crash
    pub fn get_crash_filename(&self, context: &CONTEXT,
                              exception: &EXCEPTION_RECORD) -> String {
        let pc = {
            #[cfg(target_pointer_width = "64")]
            { context.Rip as usize }

            #[cfg(target_pointer_width = "32")]
            { context.Eip as usize }
        };

        // Search for the nearest module
        let mut nearest_module: Option<(&str, usize)> = None;
        for (module, base) in self.modules.iter() {
            if let Some(offset) = pc.checked_sub(*base) {
                if nearest_module.is_none() ||
                        nearest_module.unwrap().1 > offset {
                    nearest_module = Some((module, offset));
                }
            }
        }

        let code = exception.ExceptionCode;

        // Filename starts with exception code
        let mut filename = format!("crash_{:08x}_", code);

        // Filename then contains the module+offset, or if no suitable module
        // is detected then it just contains the absolute PC address
        if let Some((module, offset)) = nearest_module {
            filename += &format!("{}+0x{:x}", module, offset);
        } else {
            filename += &format!("0x{:x}", pc);
        }

        // If the crash is an access violation we also have the type of fault
        // (read or write) and whether it's a null deref, non-canon, or
        // other
        if code == 0xc0000005 {
            // This should never happen
            assert!(exception.NumberParameters == 2,
                    "Invalid c0000005 parameters");

            // Classify the type of exception
            if exception.ExceptionInformation[0] == 0 {
                filename += "_read";
            } else if exception.ExceptionInformation[0] == 1 {
                filename += "_WRITE";
            } else if exception.ExceptionInformation[0] == 8 {
                // DEP violation
                filename += "_DEP";
            }

            let fault_addr = exception.ExceptionInformation[1] as u64;

            let noncanon_bits = fault_addr & 0xffff_0000_0000_0000;

            if noncanon_bits != 0 && noncanon_bits != 0xffff_0000_0000_0000 {
                // Address is non-canon, can only happen on 64-bits and is
                // typically a _really_ bad sign (fully controlled address)
                filename += "_NONCANON";
            } else if (fault_addr as i64).abs() < 32 * 1024 {
                // Near-null, thus we consider it to be a null deref
                filename += "_null";
            } else {
                // Address is canon, but also not null, seems bad
                filename += "_HIGH";
            }
        }

        // All files are .dmp
        filename += ".dmp";

        filename
    }

    /// Sync the coverage database to disk
    pub fn flush_coverage_database(&mut self) {
        mprint!(self, "Syncing code coverage database...\n");

        let mut fd = BufWriter::with_capacity(
            2 * 1024 * 1024,
            File::create("coverage.txt")
                .expect("Failed to open freq coverage file"));

        for (pc, (module, offset, symoff, freq)) in self.coverage.iter() {
            write!(fd,
                   "{:016x} | Freq: {:10} | \
                   {:>20}+0x{:08x} | {}\n",
                   pc, freq, module, offset, symoff)
                .expect("Failed to write coverage info");
        }

        mprint!(self, "Sync complete ({} total unique coverage entries)\n",
            self.coverage.len());
    }

    /// Run the process forever
    pub fn run(&mut self) -> i32 {
        let mut event = unsafe { std::mem::zeroed() };

        let mut hit_initial_break = false;

        unsafe { loop {
            // Flush the coverage database on an intervals
            if Instant::now().duration_since(self.last_db_save) >=
                    Duration::from_secs(5) {
                self.flush_coverage_database();
                self.last_db_save = Instant::now();
            }
                                
            if EXIT_REQUESTED.load(Ordering::SeqCst) {
                // Exit out of the run loop
                return 0;
            }

            let der = debugapi::WaitForDebugEvent(&mut event, 10);
            if der == 0 {
                if errhandlingapi::GetLastError() == ERROR_SEM_TIMEOUT {
                    // Just drop timeouts
                    continue;
                }

                panic!("WaitForDebugEvent() returned error : {}",
                    errhandlingapi::GetLastError());
            }

            let pid = event.dwProcessId;
            let tid = event.dwThreadId;

            //mprint!(self, "{:?}\n", event);

            match event.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT => {
                    let create_process = event.u.CreateProcessInfo();

                    self.process_handle =
                        Some(create_process.hProcess);

                    self.thread_handles.insert(tid,
                        create_process.hThread);

                    self.register_module(
                        create_process.lpBaseOfImage as usize);

                    self.load_breakpoints(
                        create_process.lpBaseOfImage as usize);

                    self.apply_breakpoints(
                        create_process.lpBaseOfImage as usize);
                }
                CREATE_THREAD_DEBUG_EVENT => {
                    let create_thread = event.u.CreateThread();

                    self.thread_handles.insert(tid,
                        create_thread.hThread);
                }
                EXCEPTION_DEBUG_EVENT => {
                    let exception = event.u.Exception_mut();

                    if exception.ExceptionRecord.ExceptionCode == 0x80000003 {
                        if !hit_initial_break {
                            hit_initial_break = true;

                            // Handle the initial break
                            assert!(debugapi::ContinueDebugEvent(
                                pid, tid,
                                DBG_CONTINUE) != 0);
                            continue;
                        }

                        if !self.handle_breakpoint(tid,
                                exception.ExceptionRecord
                                .ExceptionAddress as usize) {
                            mprint!(self, 
                                "Warning: Continuing unexpected 0x80000003\n");
                        }
                    } else {
                        if exception.ExceptionRecord.ExceptionCode ==
                                0xc0000005 {
                            self.get_context(tid);

                            let filename = self.get_crash_filename(
                                &self.context, &mut exception.ExceptionRecord);

                            mprint!(self, "Got crash: {}\n", filename);

                            if !Path::new(&filename).is_file() {
                                // Remove all breakpoints in the program
                                // before minidumping
                                self.remove_breakpoints();

                                dump(&filename, pid, tid,
                                     self.process_handle.unwrap(),
                                     &mut exception.ExceptionRecord,
                                     &mut self.context);
                            }

                            // Exit out
                            return exception
                                .ExceptionRecord.ExceptionCode as i32;
                        } else if exception.ExceptionRecord
                                .ExceptionCode == 0x80000004 {
                            // Single step

                            if let Some(&pc) = self.single_step.get(&tid) {
                                // Disable trap flag
                                self.get_context(tid);
                                self.context.EFlags &= !(1 << 8);
                                self.set_context(tid);

                                // Write breakpoint back in
                                assert!(self.write_mem(pc, b"\xcc") == 1);
                                self.flush_instruction_caches();

                                // Remove that we're single stepping this TID
                                self.single_step.remove(&tid);
                            } else {
                                mprint!(self, "Unexpected single step, \
                                    continuing\n");
                            }

                            assert!(debugapi::ContinueDebugEvent(
                                    pid, tid, DBG_CONTINUE) != 0);
                            continue;
                        } else {
                            // Unhandled exception
                            print!("Unhandled exception {:x}\n",
                                exception.ExceptionRecord.ExceptionCode);

                            assert!(debugapi::ContinueDebugEvent(
                                    pid, tid, DBG_EXCEPTION_NOT_HANDLED) != 0);
                            continue;
                        }
                    }
                }
                LOAD_DLL_DEBUG_EVENT => {
                    let load_dll = event.u.LoadDll();

                    self.register_module(load_dll.lpBaseOfDll as usize);
                    self.load_breakpoints(load_dll.lpBaseOfDll as usize);
                    self.apply_breakpoints(load_dll.lpBaseOfDll as usize);
                }
                EXIT_THREAD_DEBUG_EVENT => {
                    self.thread_handles.remove(&tid);
                }
                EXIT_PROCESS_DEBUG_EVENT => {
                    mprint!(self, "Process exited, qutting!\n");
                    return 0;
                }
                UNLOAD_DLL_DEBUG_EVENT => {
                    let unload_dll = event.u.UnloadDll();
                    self.unregister_module(unload_dll.lpBaseOfDll as usize);
                }
                OUTPUT_DEBUG_STRING_EVENT => {
                }
                RIP_EVENT => {
                }
                _ => panic!("Unsupported event"),
            }

            assert!(debugapi::ContinueDebugEvent(
                    pid, tid, DBG_CONTINUE) != 0);
        }}
    }
}

/// Convert rust string to null-terminated UTF-16 Windows API string
fn win32_string(value : &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(once(0)).collect()
}

/// Create a full minidump of a given process
pub fn dump(filename: &str, pid: u32, tid: u32, process: HANDLE,
            exception: &mut EXCEPTION_RECORD, context: &mut CONTEXT) {
    // Don't overwrite existing dumps
    if Path::new(filename).is_file() {
        print!("Ignoring duplicate crash {}\n", filename);
        return;
    }

    unsafe {
        let filename = win32_string(filename);

        let ep = EXCEPTION_POINTERS {
            ExceptionRecord: exception,
            ContextRecord:   context,
        };
        
        let fd = fileapi::CreateFileW(filename.as_ptr(),
            GENERIC_READ | GENERIC_WRITE, 0,
            0 as *mut _, CREATE_NEW, 0, 0 as *mut _);
        assert!(fd != INVALID_HANDLE_VALUE, "Failed to create dump file");

        let mei = MinidumpExceptionInformation {
            thread_id:       tid,
            exception:       &ep,
            client_pointers: 0,
        };

        // Take a minidump!
        let res = MiniDumpWriteDump(process, pid, fd, 
            MinidumpType::MiniDumpWithFullMemory as u32 |
            MinidumpType::MiniDumpWithHandleData as u32 |
            MinidumpType::MiniDumpWithUnloadedModules as u32 |
            MinidumpType::MiniDumpWithProcessThreadData as u32 |
            MinidumpType::MiniDumpWithFullMemoryInfo as u32 |
            MinidumpType::MiniDumpWithThreadInfo as u32 |
            MinidumpType::MiniDumpWithFullAuxiliaryState as u32 |
            MinidumpType::MiniDumpWithTokenInformation as u32 |
            MinidumpType::MiniDumpWithModuleHeaders as u32 |
            MinidumpType::MiniDumpFilterTriage as u32,
            &mei, 0, 0);
        if res == 0 {
            print!("MiniDumpWriteDump error: {}\n",
                    errhandlingapi::GetLastError());
            assert!(res != 0);
        }
        assert!(handleapi::CloseHandle(fd) != 0);
    }
}

/// Enable SeDebugPrivilege so we can debug system services
pub fn sedebug() {
    unsafe {
        let mut token: HANDLE = 0 as *mut  _;
        let mut tkp: TOKEN_PRIVILEGES = std::mem::zeroed();

        assert!(processthreadsapi::OpenProcessToken(
                processthreadsapi::GetCurrentProcess(), 
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) != 0);

        let privname = win32_string("SeDebugPrivilege");
        assert!(winbase::LookupPrivilegeValueW(0 as *const _,
            privname.as_ptr(), &mut tkp.Privileges[0].Luid) != 0);

        tkp.PrivilegeCount           = 1;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        assert!(securitybaseapi::AdjustTokenPrivileges(token, 0, &mut tkp, 0,
            0 as *mut _, 0 as *mut _) != 0);
        assert!(handleapi::CloseHandle(token) != 0);
    }
}

impl<'a> Drop for Debugger<'a> {
    fn drop(&mut self) {
        // Remove all breakpoints
        self.remove_breakpoints();

        // Flush coverage database one last time
        self.flush_coverage_database();

        // Detach from the process
        unsafe {
            assert!(DebugActiveProcessStop(self.pid) != 0,
                "DebugActiveProcessStop() failed");
        }

        // All done, process is safely restored
        print!("Detached from process {}\n", self.pid);
    }
}

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

    // Enable ability to debug system services
    sedebug();

    // Register ctrl-c handler
    unsafe {
        assert!(SetConsoleCtrlHandler(Some(ctrl_c_handler), 1) != 0,
            "SetConsoleCtrlHandler() failed");
    }

    // Attach to process
    let mut dbg = Debugger::attach(args[1].parse().unwrap());
    if args.len() > 2 {
        for meso in &args[2..] {
            if meso == "--freq" {
                // Always do frequency
                print!("Always frequency mode enabled\n");
                dbg.always_freq = true;
                continue;
            } else if meso == "--verbose" {
                // Enable verbose mode
                print!("Verbose mode enabled\n");
                dbg.verbose = true;
                continue;
            } else if meso == "--print" {
                // Enable breakpoint print mode
                print!("Breakpoint print mode enabled\n");
                dbg.bp_print = true;
                continue;
            }

            // Load explicit meso file
            dbg.load_meso(Path::new(meso));
        }
    }

    // Debug forever
    dbg.run();
}
