//! Standalone uniffi binding generator for talkrypt-ffi.
//! Usage: cargo run -p talkrypt-ffi --bin uniffi-bindgen -- generate \
//!   --library target/release/libtalkrypt_ffi.dylib --language kotlin --out-dir out
fn main() {
    uniffi::uniffi_bindgen_main()
}
