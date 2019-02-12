/// Crate to provide a Drop wrapper for HANDLEs

use winapi::um::winnt::HANDLE;
use winapi::um::handleapi::CloseHandle;

/// Wrapper on a HANDLE to provide Drop support to clean up handles
pub struct Handle(HANDLE);

impl Handle {
    /// Wrap up a HANDLE
    pub fn new(handle: HANDLE) -> Option<Handle> {
        // Return None if the handle is null
        if handle == std::ptr::null_mut() { return None; }

        Some(Handle(handle))
    }

    /// Gets the raw HANDLE value this `Handle` represents
    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            // Close that handle!
            assert!(CloseHandle(self.0) != 0, "Failed to drop HANDLE");
        }
    }
}
