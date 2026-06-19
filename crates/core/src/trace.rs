//! Temporary on-device diagnostic sink. Android doesn't surface Rust
//! stdout/stderr to logcat, so for hard-to-reproduce on-device bugs we append
//! structured lines to a file the host can pull with `run-as cat`. No-op unless
//! a path has been set (so it costs nothing in normal builds/runs).
//!
//! Set the path once (e.g. from the FFI, under the app's writable state dir):
//!   talkrypt_core::trace::set_path("/data/.../files/tor/shared/trace.log");
//! then call `trace::log("…")` from anywhere in the engine.
//!
//! This is debug instrumentation, not a shipping feature — remove once the
//! host→joiner receive bug is root-caused.

use std::fs::File;
use std::io::Write;
use std::sync::{Mutex, OnceLock};

static SINK: OnceLock<Mutex<File>> = OnceLock::new();

/// Point the trace at a writable file (append mode). Idempotent; first wins.
pub fn set_path(path: &str) {
    if SINK.get().is_some() {
        return;
    }
    if let Ok(f) = File::options().create(true).append(true).open(path) {
        let _ = SINK.set(Mutex::new(f));
    }
}

/// Append a line if a sink is set; otherwise a cheap no-op.
pub fn log(msg: &str) {
    if let Some(m) = SINK.get() {
        if let Ok(mut f) = m.lock() {
            let _ = writeln!(f, "{msg}");
            let _ = f.flush();
        }
    }
}
