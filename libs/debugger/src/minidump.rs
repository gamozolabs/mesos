/// Module containing utilities to create full minidumps of processes

use winapi::um::winnt::EXCEPTION_POINTERS;
use winapi::um::winnt::GENERIC_READ;
use winapi::um::winnt::GENERIC_WRITE;
use winapi::um::winnt::EXCEPTION_RECORD;
use winapi::um::fileapi::CREATE_NEW;
use winapi::um::winnt::HANDLE;
use winapi::um::fileapi::CreateFileW;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::winnt::CONTEXT;

use std::path::Path;
use crate::handles::Handle;
use crate::ffi_helpers::win32_string;

#[repr(C)]
#[allow(dead_code)]
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
        
        // Create the minidump file
        let fd = CreateFileW(filename.as_ptr(),
            GENERIC_READ | GENERIC_WRITE, 0,
            std::ptr::null_mut(), CREATE_NEW, 0, std::ptr::null_mut());
        assert!(fd != INVALID_HANDLE_VALUE, "Failed to create dump file");

        // Wrap up the HANDLE for drop tracking
        let fd = Handle::new(fd).expect("Failed to get handle to minidump");

        let mei = MinidumpExceptionInformation {
            thread_id:       tid,
            exception:       &ep,
            client_pointers: 0,
        };

        // Take a minidump!
        let res = MiniDumpWriteDump(process, pid, fd.raw(), 
            MinidumpType::MiniDumpWithFullMemory as u32 |
            MinidumpType::MiniDumpWithHandleData as u32,
            &mei, 0, 0);
        assert!(res != 0, "MiniDumpWriteDump error: {}\n", GetLastError());
    }
}
