//! Windows security-descriptor (SDDL) construction for the helper Named Pipe.
//!
//! A default-DACL named pipe is connectable by **any** local user, which would
//! expose key custody to other accounts. The helper instead builds the pipe
//! with an explicit security descriptor that grants full access **only** to the
//! current user's SID and `SYSTEM`, and is *protected* (`P`) so it inherits no
//! permissive ACEs.
//!
//! This string-construction logic is pure and is unit-tested on every platform;
//! the actual SID lookup and pipe creation (which require Win32) live in
//! [`crate::endpoint`] behind `cfg(windows)`.

/// Build the SDDL for an owner-only pipe: owner+group = `sid`; a protected DACL
/// granting Full Access to `sid` and to `SYSTEM` (`SY`), and to no one else.
///
/// `sid` must be a string SID like `S-1-5-21-…`. The result is fed to
/// `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
pub fn owner_only_sddl(sid: &str) -> String {
    // O:<sid>  owner
    // G:<sid>  group
    // D:P      DACL, Protected (no inherited ACEs)
    //   (A;;FA;;;<sid>)  Allow Full Access to the user
    //   (A;;FA;;;SY)     Allow Full Access to SYSTEM
    format!("O:{sid}G:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;SY)")
}

/// The pipe name for the current user's SID, matching `docs/ROADMAP.md`:
/// `\\.\pipe\talkrypt-helper-<SID>`.
pub fn pipe_name_for_sid(sid: &str) -> String {
    format!(r"\\.\pipe\talkrypt-helper-{sid}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";

    #[test]
    fn sddl_grants_only_owner_and_system_and_is_protected() {
        let sddl = owner_only_sddl(SID);
        // Owner + group set to the user.
        assert!(sddl.starts_with(&format!("O:{SID}G:{SID}")));
        // DACL is protected.
        assert!(sddl.contains("D:P"));
        // Full access to the user and to SYSTEM.
        assert!(sddl.contains(&format!("(A;;FA;;;{SID})")));
        assert!(sddl.contains("(A;;FA;;;SY)"));
        // Crucially: no broad principals (Everyone=WD, Authenticated Users=AU,
        // Users=BU) are granted.
        for broad in ["(A;;FA;;;WD)", ";WD)", ";AU)", ";BU)"] {
            assert!(!sddl.contains(broad), "must not grant {broad}");
        }
    }

    #[test]
    fn pipe_name_includes_the_sid() {
        let name = pipe_name_for_sid(SID);
        assert_eq!(name, format!(r"\\.\pipe\talkrypt-helper-{SID}"));
        assert!(name.starts_with(r"\\.\pipe\talkrypt-helper-"));
    }
}
