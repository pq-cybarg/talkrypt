//! macOS **Keychain** backend for the `OsKeystore` custody tier.
//!
//! Stores a secret as a login-keychain *generic password* (service
//! `talkrypt-helper`, account = key name). The login keychain is encrypted at
//! rest by the OS and unlocked at user login — so unlike the `SoftwareSealed`
//! tier there is no app-held passphrase. Generic-password items need **no
//! entitlement** (only Secure Enclave / data-protection keychain would), so this
//! works from a plain binary and is testable natively.
//!
//! Secrets are passed to the Security framework directly (not via a CLI argv),
//! so they don't leak into the process table.

use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

use crate::error::{HelperError, Result};

const SERVICE: &str = "talkrypt-helper";

/// Store (or replace) `secret` for `account` in the login keychain.
pub fn set(account: &str, secret: &[u8]) -> Result<()> {
    set_generic_password(SERVICE, account, secret).map_err(|_| HelperError::Keychain)
}

/// Fetch the secret for `account`. `NotFound` if absent.
pub fn get(account: &str) -> Result<Vec<u8>> {
    match get_generic_password(SERVICE, account) {
        Ok(bytes) => Ok(bytes),
        // The framework returns errSecItemNotFound for a missing item.
        Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Err(HelperError::NotFound),
        Err(_) => Err(HelperError::Keychain),
    }
}

/// Delete `account` from the keychain (no error if already absent).
pub fn delete(account: &str) -> Result<()> {
    match delete_generic_password(SERVICE, account) {
        Ok(()) => Ok(()),
        Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
        Err(_) => Err(HelperError::Keychain),
    }
}

/// `errSecItemNotFound` (Security framework OSStatus).
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keychain_set_get_delete_roundtrip() {
        let acct = format!("tk-helper-test-{}", std::process::id());
        // Clean any leftover, then exercise the full cycle.
        let _ = delete(&acct);
        assert!(matches!(get(&acct), Err(HelperError::NotFound)));

        set(&acct, b"enclave-adjacent-secret").unwrap();
        assert_eq!(get(&acct).unwrap(), b"enclave-adjacent-secret");

        // Replace.
        set(&acct, b"rotated").unwrap();
        assert_eq!(get(&acct).unwrap(), b"rotated");

        delete(&acct).unwrap();
        assert!(matches!(get(&acct), Err(HelperError::NotFound)));
        // delete is idempotent
        delete(&acct).unwrap();
    }
}
