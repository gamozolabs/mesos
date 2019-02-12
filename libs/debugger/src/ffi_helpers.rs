/// Misc functions that help during various FFI activities

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::iter::once;

/// Convert rust string to null-terminated UTF-16 Windows API string
pub fn win32_string(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(once(0)).collect()
}
