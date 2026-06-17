//! Headless driver for the desktop client — the same `worker_loop` the egui app
//! runs, but driven by argv + stdin and reporting to stdout, with no window.
//!
//! This exists so the desktop client is scriptable and testable: a harness (or a
//! human) can host or join a chat, capture the invite, feed messages on stdin,
//! and observe events on stdout — exercising the identical networking code path
//! the GUI uses. It is also how we drive an emulator↔desktop test over a `.onion`
//! (Tor), which needs no LAN/NAT bridge at all.
//!
//! Usage:
//!   talkrypt-desktop --headless host [--channel '#general'] [--posture pq-pure]
//!                    [--access open] [--tor | --no-tor]
//!   talkrypt-desktop --headless join --uri 'talkrypt://…' [--tor | --no-tor]
//!
//! Output is line-oriented and stable for scripting:
//!   INVITE <uri>            the shareable invite (host only; print/scan this)
//!   STATUS <text>           lifecycle/status updates (bootstrap, hosting, …)
//!   CONNECTED <peer>        a peer completed the handshake
//!   DISCONNECTED <peer>     a peer left
//!   < <who>: <text>         an inbound message
//!   > me: <text>            our own echoed message
//! Each line of stdin is sent as a chat message once a session is up.

use std::io::{BufRead, Write};

use crate::{worker_loop, Cmd, UiEvt};

/// Entry point when `--headless` is present in argv. Returns the process exit
/// code. Never returns to the egui path.
pub fn run(args: &[String]) -> i32 {
    let cfg = match Config::parse(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("headless: {e}\n\n{USAGE}");
            return 2;
        }
    };

    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel::<Cmd>();
    let (ui_tx, ui_rx) = std::sync::mpsc::channel::<UiEvt>();

    // Multi-threaded runtime so the worker makes progress while the main thread
    // blocks on the (synchronous) event channel below.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.spawn(worker_loop(cmd_rx, ui_tx, || {}));

    // The driver manages exactly one session; this is its id.
    const SID: u64 = 1;

    // Kick off the requested action.
    let initial = match &cfg.action {
        Action::Host { channel, posture, access } => Cmd::Host {
            id: SID,
            channel: channel.clone(),
            posture: posture.clone(),
            access: access.clone(),
            use_tor: cfg.use_tor,
        },
        Action::Join { uri } => Cmd::Join {
            id: SID,
            uri: uri.clone(),
            use_tor: cfg.use_tor,
        },
    };
    if cmd_tx.send(initial).is_err() {
        eprintln!("headless: worker died before start");
        return 1;
    }

    // Forward each stdin line as a chat message. Runs until EOF; the session
    // stays alive afterward (a host keeps listening for peers).
    let send_tx = cmd_tx.clone();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            let Ok(line) = line else { break };
            let line = line.trim_end().to_string();
            if line.is_empty() {
                continue;
            }
            if send_tx.send(Cmd::Send { id: SID, text: line }).is_err() {
                break;
            }
        }
    });

    // Drain events to stdout until the worker (and thus the sender) is gone.
    let mut out = std::io::stdout();
    while let Ok(evt) = ui_rx.recv() {
        let line = match evt {
            UiEvt::Invite { uri, .. } => format!("INVITE {uri}"),
            UiEvt::Status { text, .. } => format!("STATUS {text}"),
            UiEvt::Connected { who, .. } => format!("CONNECTED {who}"),
            UiEvt::Disconnected { who, .. } => format!("DISCONNECTED {who}"),
            UiEvt::Line { mine, who, text, .. } => {
                if mine {
                    format!("> me: {text}")
                } else {
                    format!("< {who}: {text}")
                }
            }
        };
        let _ = writeln!(out, "{line}");
        let _ = out.flush();
    }
    0
}

const USAGE: &str = "\
usage:
  talkrypt-desktop --headless host [--channel '#general'] [--posture pq-pure] [--access open] [--tor|--no-tor]
  talkrypt-desktop --headless join --uri 'talkrypt://…' [--tor|--no-tor]";

#[derive(Debug)]
enum Action {
    Host { channel: String, posture: String, access: String },
    Join { uri: String },
}

#[derive(Debug)]
struct Config {
    action: Action,
    use_tor: bool,
}

impl Config {
    fn parse(args: &[String]) -> Result<Config, String> {
        // Skip everything up to and including the `--headless` marker.
        let mut it = args
            .iter()
            .skip_while(|a| a.as_str() != "--headless")
            .skip(1)
            .peekable();

        let verb = it.next().ok_or("expected `host` or `join`")?.as_str();

        let mut channel = "#general".to_string();
        let mut posture = "pq-pure".to_string();
        let mut access = "open".to_string();
        let mut uri: Option<String> = None;
        // Default to Tor whenever this build supports it (matches the GUI).
        let mut use_tor = cfg!(feature = "tor");

        while let Some(flag) = it.next() {
            match flag.as_str() {
                "--channel" => channel = it.next().ok_or("--channel needs a value")?.clone(),
                "--posture" => posture = it.next().ok_or("--posture needs a value")?.clone(),
                "--access" => access = it.next().ok_or("--access needs a value")?.clone(),
                "--uri" => uri = Some(it.next().ok_or("--uri needs a value")?.clone()),
                "--tor" => use_tor = true,
                "--no-tor" => use_tor = false,
                other => return Err(format!("unknown flag `{other}`")),
            }
        }

        let action = match verb {
            "host" => Action::Host { channel, posture, access },
            "join" => Action::Join {
                uri: uri.ok_or("`join` requires --uri")?,
            },
            other => return Err(format!("unknown action `{other}` (want `host` or `join`)")),
        };
        Ok(Config { action, use_tor })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn parses_host_with_defaults() {
        let c = Config::parse(&args(&["talkrypt-desktop", "--headless", "host"])).unwrap();
        match c.action {
            Action::Host { channel, posture, access } => {
                assert_eq!(channel, "#general");
                assert_eq!(posture, "pq-pure");
                assert_eq!(access, "open");
            }
            _ => panic!("expected host"),
        }
    }

    #[test]
    fn parses_join_uri_and_tor_override() {
        let c = Config::parse(&args(&[
            "--headless", "join", "--uri", "talkrypt://abc", "--no-tor",
        ]))
        .unwrap();
        assert!(!c.use_tor);
        match c.action {
            Action::Join { uri } => assert_eq!(uri, "talkrypt://abc"),
            _ => panic!("expected join"),
        }
    }

    #[test]
    fn join_without_uri_is_an_error() {
        let err = Config::parse(&args(&["--headless", "join"])).unwrap_err();
        assert!(err.contains("requires --uri"), "got: {err}");
    }

    #[test]
    fn unknown_flag_is_rejected() {
        let err = Config::parse(&args(&["--headless", "host", "--wat"])).unwrap_err();
        assert!(err.contains("unknown flag"), "got: {err}");
    }
}
