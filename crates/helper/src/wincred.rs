//! Windows **Credential Manager** backend for the `OsKeystore` custody tier.
//!
//! Stores a secret as a generic credential (target `talkrypt-helper:<name>`),
//! which Windows protects at rest under the user's profile (DPAPI) — so, like
//! the macOS Keychain / Linux Secret Service tiers, there is no app-held
//! passphrase. Generic credentials need no special privilege.
//!
//! Like [`crate::winpipe`], this compiles + cross-compiles for Windows but its
//! runtime behaviour must be validated on real Windows.
#![cfg(windows)]

use std::ptr;

use windows_sys::Win32::Foundation::{GetLastError, ERROR_NOT_FOUND};
use windows_sys::Win32::Security::Credentials::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE,
    CRED_TYPE_GENERIC,
};

use crate::error::{HelperError, Result};

fn target(name: &str) -> Vec<u16> {
    format!("talkrypt-helper:{name}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}

/// Store (or replace) `secret` for `name`.
pub fn set(name: &str, secret: &[u8]) -> Result<()> {
    let target_w = target(name);
    let mut blob = secret.to_vec();
    let cred = CREDENTIALW {
        Flags: 0,
        Type: CRED_TYPE_GENERIC,
        TargetName: target_w.as_ptr() as *mut u16,
        Comment: ptr::null_mut(),
        LastWritten: unsafe { std::mem::zeroed() },
        CredentialBlobSize: blob.len() as u32,
        CredentialBlob: blob.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        AttributeCount: 0,
        Attributes: ptr::null_mut(),
        TargetAlias: ptr::null_mut(),
        UserName: ptr::null_mut(),
    };
    if unsafe { CredWriteW(&cred, 0) } == 0 {
        return Err(HelperError::Keychain);
    }
    Ok(())
}

/// Fetch the secret for `name`. `NotFound` if absent.
pub fn get(name: &str) -> Result<Vec<u8>> {
    let target_w = target(name);
    let mut pcred: *mut CREDENTIALW = ptr::null_mut();
    let ok = unsafe { CredReadW(target_w.as_ptr(), CRED_TYPE_GENERIC, 0, &mut pcred) };
    if ok == 0 {
        if unsafe { GetLastError() } == ERROR_NOT_FOUND {
            return Err(HelperError::NotFound);
        }
        return Err(HelperError::Keychain);
    }
    // SAFETY: CredReadW gave us a valid CREDENTIALW we must CredFree.
    let out = unsafe {
        let cred = &*pcred;
        let blob =
            std::slice::from_raw_parts(cred.CredentialBlob, cred.CredentialBlobSize as usize)
                .to_vec();
        CredFree(pcred as *const _ as *mut _);
        blob
    };
    Ok(out)
}

/// Delete `name` (no error if absent).
pub fn delete(name: &str) -> Result<()> {
    let target_w = target(name);
    let ok = unsafe { CredDeleteW(target_w.as_ptr(), CRED_TYPE_GENERIC, 0) };
    if ok == 0 && unsafe { GetLastError() } != ERROR_NOT_FOUND {
        return Err(HelperError::Keychain);
    }
    Ok(())
}
