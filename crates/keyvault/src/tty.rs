//! Controlling-terminal I/O: the keyvault reads the passphrase and shows the
//! recordable secret (mnemonic/hexseed) via **`/dev/tty`**, never stdin/stdout.
//!
//! This is the isolation boundary. `/dev/tty` is the process's CONTROLLING terminal
//! — the human's keyboard+screen. An automation agent that launches the keyvault
//! drives it through piped stdin/stdout and has **no controlling terminal**, so
//! every function here FAILS for such a caller: it cannot type the passphrase and
//! cannot read the secret. Only a human at a real terminal can.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::io::AsRawFd;

use zeroize::Zeroizing;

fn open_tty() -> std::io::Result<File> {
    OpenOptions::new().read(true).write(true).open("/dev/tty")
}

/// Read one line from `/dev/tty` with terminal echo DISABLED (so the passphrase is
/// not shown on screen and not recoverable from a screen scrape of the keystrokes).
/// Fails if there is no controlling terminal — the isolation guarantee.
pub fn read_passphrase(prompt: &str) -> std::io::Result<Zeroizing<String>> {
    let tty = open_tty()?;
    let fd = tty.as_raw_fd();

    // Save the current terminal attributes, then clear ECHO.
    let mut term: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut term) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let saved = term;
    term.c_lflag &= !libc::ECHO;
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &term) } != 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Prompt, read one line, then ALWAYS restore the saved attributes (even on error).
    {
        let mut w = &tty;
        let _ = write!(w, "{prompt}");
        let _ = w.flush();
    }
    let mut line = Zeroizing::new(String::new());
    let read_res = BufReader::new(&tty).read_line(&mut line);
    unsafe {
        libc::tcsetattr(fd, libc::TCSANOW, &saved);
    }
    let _ = writeln!(&tty); // the user's Enter wasn't echoed; move to a fresh line
    read_res?;

    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}

/// Read a passphrase twice and require the two to match (for key GENERATION, where a
/// typo would lock the key forever). Fails closed on mismatch.
pub fn read_new_passphrase() -> std::io::Result<Zeroizing<String>> {
    let a = read_passphrase("New passphrase (not echoed): ")?;
    if a.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "empty passphrase refused",
        ));
    }
    let b = read_passphrase("Confirm passphrase: ")?;
    if *a != *b {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "passphrases did not match",
        ));
    }
    Ok(a)
}

/// Print a line to `/dev/tty` (the human's screen), NOT stdout. Used for the
/// recordable secret (mnemonic/hexseed) so it can never be captured from a piped
/// stdout. Silently does nothing if there is no controlling terminal.
pub fn eprintln_tty(line: &str) {
    if let Ok(tty) = open_tty() {
        let _ = writeln!(&tty, "{line}");
    }
}
