//! Windows Named-Pipe transport with an **SDDL ACL bound to the current SID**.
//!
//! tokio's `ServerOptions` can't attach a custom security descriptor, so the
//! pipe is created with the raw `CreateNamedPipeW` (passing a `SECURITY_ATTRIBUTES`
//! whose descriptor is built from [`crate::sddl::owner_only_sddl`]) and then
//! wrapped into a tokio `NamedPipeServer` via `from_raw_handle`. The pipe is
//! opened `FILE_FLAG_OVERLAPPED` as tokio requires.
//!
//! **Runtime status:** this compiles for `*-pc-windows-*` and the SDDL logic is
//! unit-tested cross-platform, but the ACL's *enforcement* (that only the owner
//! SID + SYSTEM can connect) must be validated on real Windows — Wine does not
//! faithfully enforce security descriptors. Treat Wine as a functional smoke
//! test of the pipe/protocol only.
#![cfg(windows)]

use std::ptr;

use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer};
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::System::Pipes::CreateNamedPipeW;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::error::{HelperError, Result};
use crate::sddl::owner_only_sddl;

// Named-pipe ABI constants (stable Win32 values; defined locally to avoid
// windows-sys module-path churn across versions).
const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
const PIPE_TYPE_BYTE: u32 = 0x0000_0000;
const PIPE_READMODE_BYTE: u32 = 0x0000_0000;
const PIPE_WAIT: u32 = 0x0000_0000;
const PIPE_UNLIMITED_INSTANCES: u32 = 255;

fn last_error<T>(_what: &'static str) -> Result<T> {
    Err(HelperError::Unsupported("windows api call failed"))
}

/// NUL-terminated UTF-16 for a Rust string.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The current process user's string SID (`S-1-5-21-…`).
pub fn current_user_sid() -> Result<String> {
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return last_error("OpenProcessToken");
        }
        // Query the buffer size, then the TOKEN_USER.
        let mut len: u32 = 0;
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        let ok = GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr() as *mut _,
            len,
            &mut len,
        );
        CloseHandle(token);
        if ok == 0 {
            return last_error("GetTokenInformation");
        }
        let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut sid_w: *mut u16 = ptr::null_mut();
        if ConvertSidToStringSidW(token_user.User.Sid, &mut sid_w) == 0 {
            return last_error("ConvertSidToStringSidW");
        }
        let sid = widestr_to_string(sid_w);
        LocalFree(sid_w as *mut _);
        Ok(sid)
    }
}

unsafe fn widestr_to_string(p: *const u16) -> String {
    let mut len = 0usize;
    while *p.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
}

/// An owned Win32 security descriptor (LocalFree'd on drop) plus the
/// `SECURITY_ATTRIBUTES` that references it.
pub struct OwnedSecurity {
    sd: PSECURITY_DESCRIPTOR,
    attrs: SECURITY_ATTRIBUTES,
}

impl OwnedSecurity {
    /// Build owner-only security (current SID + SYSTEM) from the SDDL.
    pub fn owner_only() -> Result<OwnedSecurity> {
        let sid = current_user_sid()?;
        let sddl = wide(&owner_only_sddl(&sid));
        unsafe {
            let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                ptr::null_mut(),
            ) == 0
            {
                return last_error("ConvertStringSecurityDescriptor");
            }
            let attrs = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            };
            Ok(OwnedSecurity { sd, attrs })
        }
    }

    fn attrs_ptr(&self) -> *const SECURITY_ATTRIBUTES {
        &self.attrs
    }
}

impl Drop for OwnedSecurity {
    fn drop(&mut self) {
        if !self.sd.is_null() {
            unsafe { LocalFree(self.sd as *mut _) };
        }
    }
}

/// Create one named-pipe instance with the owner-only ACL, wrapped as a tokio
/// server. `first` marks the first instance (rejects a name squatter).
pub fn create_pipe_instance(
    name: &str,
    security: &OwnedSecurity,
    first: bool,
) -> Result<NamedPipeServer> {
    let name_w = wide(name);
    let mut open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
    if first {
        // Fail if the pipe name already exists (reject a squatter).
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }
    let handle = unsafe {
        CreateNamedPipeW(
            name_w.as_ptr(),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            64 * 1024,
            64 * 1024,
            0,
            security.attrs_ptr(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return last_error("CreateNamedPipeW");
    }
    // SAFETY: a valid overlapped pipe handle we just created and now transfer
    // ownership of to tokio. tokio's inherent `from_raw_handle` validates and
    // registers it with the reactor, returning an io::Result.
    unsafe { NamedPipeServer::from_raw_handle(handle as *mut _) }
        .map_err(|_| HelperError::Unsupported("named pipe handle registration"))
}

/// Connect a client to the helper pipe.
pub async fn connect(name: &str) -> Result<NamedPipeClient> {
    ClientOptions::new()
        .open(name)
        .map_err(|_| HelperError::Unsupported("named pipe connect failed"))
}
