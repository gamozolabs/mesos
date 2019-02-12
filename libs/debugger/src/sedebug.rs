use winapi::um::winnt::HANDLE;
use winapi::um::winnt::TOKEN_PRIVILEGES;
use winapi::um::winnt::TOKEN_ADJUST_PRIVILEGES;
use winapi::um::winnt::TOKEN_QUERY;
use winapi::um::winnt::SE_PRIVILEGE_ENABLED;
use winapi::um::processthreadsapi::OpenProcessToken;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::securitybaseapi::AdjustTokenPrivileges;
use winapi::um::winbase::LookupPrivilegeValueW;
use crate::ffi_helpers::win32_string;
use crate::handles::Handle;

/// Enable SeDebugPrivilege so we can debug system services
pub fn sedebug() {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        let mut tkp: TOKEN_PRIVILEGES = std::mem::zeroed();

        // Get the token for the current process
        assert!(OpenProcessToken(GetCurrentProcess(), 
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) != 0);
        
        // Wrap up the handle so it'll get Dropped correctly
        let token = Handle::new(token)
            .expect("Failed to get valid handle for token");

        // Lookup SeDebugPrivilege
        let privname = win32_string("SeDebugPrivilege");
        assert!(LookupPrivilegeValueW(std::ptr::null(),
            privname.as_ptr(), &mut tkp.Privileges[0].Luid) != 0);

        tkp.PrivilegeCount           = 1;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        // Set the privilege
        assert!(AdjustTokenPrivileges(token.raw(), 0, &mut tkp, 0,
            std::ptr::null_mut(), std::ptr::null_mut()) != 0);
    }
}
