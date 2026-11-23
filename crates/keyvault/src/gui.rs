//! The eframe GUI popup front-end for the keyvault (feature `gui`).
//!
//! Same isolation idea as the TUI, via a different boundary: the passphrase is typed
//! into a SEPARATE OS WINDOW, so keystrokes go to the windowing system — not a stdin
//! an automation agent pipes. The recordable secret (mnemonic) is shown IN THE WINDOW,
//! which a terminal-scraping agent cannot read. Only public data (sealed file,
//! pubkey, address, signature path) leaves the process. The process is already
//! hardened (no-core-dump / non-dumpable / anti-ptrace) by `main::harden`.

use talkrypt_relsign::{hex, seal, seed, sign, Algo};
use zeroize::{Zeroize, Zeroizing};

pub fn run() -> Result<(), String> {
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([600.0, 560.0])
            .with_min_inner_size([520.0, 460.0])
            .with_title("talkrypt keyvault"),
        ..Default::default()
    };
    eframe::run_native(
        "talkrypt-keyvault",
        opts,
        Box::new(|_cc| Ok(Box::<VaultApp>::default())),
    )
    .map_err(|e| e.to_string())
}

#[derive(PartialEq)]
enum Mode {
    Keygen,
    Sign,
}

#[derive(PartialEq, Clone, Copy)]
enum KdfChoice {
    Desktop,
    Mobile,
    Embedded,
    Fips,
}

impl KdfChoice {
    fn kdf(self) -> seal::Kdf {
        match self {
            KdfChoice::Desktop => seal::Kdf::desktop(),
            KdfChoice::Mobile => seal::Kdf::mobile(),
            KdfChoice::Embedded => seal::Kdf::embedded(),
            KdfChoice::Fips => seal::Kdf::fips(),
        }
    }
    fn label(self) -> &'static str {
        match self {
            KdfChoice::Desktop => "desktop — Argon2id 256 MiB",
            KdfChoice::Mobile => "mobile — Argon2id 64 MiB",
            KdfChoice::Embedded => "embedded — Argon2id 16 MiB",
            KdfChoice::Fips => "fips — PBKDF2-HMAC-SHA384",
        }
    }
}

struct VaultApp {
    mode: Mode,
    algo: Algo,
    kdf: KdfChoice,
    out: String,      // keygen: .seed.enc output path
    manifest: String, // sign: manifest to sign
    keyfile: String,  // sign: .seed.enc input
    pw: String,
    pw2: String, // keygen passphrase confirmation
    status: String,
    result: String, // public result + (keygen) the in-window mnemonic backup
}

impl Default for VaultApp {
    fn default() -> Self {
        Self {
            mode: Mode::Keygen,
            algo: Algo::MlDsa,
            kdf: KdfChoice::Desktop,
            out: String::new(),
            manifest: String::new(),
            keyfile: String::new(),
            pw: String::new(),
            pw2: String::new(),
            status: String::new(),
            result: String::new(),
        }
    }
}

impl VaultApp {
    fn zeroize_pw(&mut self) {
        self.pw.zeroize();
        self.pw2.zeroize();
    }

    fn do_keygen(&mut self) {
        self.status.clear();
        if self.out.trim().is_empty() {
            self.status = "choose an output path for the sealed .seed.enc".into();
            return;
        }
        if std::path::Path::new(self.out.trim()).exists() {
            self.status = "refusing to overwrite an existing file".into();
            return;
        }
        if self.pw.is_empty() {
            self.status = "enter a passphrase".into();
            return;
        }
        if self.pw != self.pw2 {
            self.status = "passphrases do not match".into();
            return;
        }
        let gen = Zeroizing::new(talkrypt_crypto::IdentityKeyPair::generate().export_secret());
        let pubkey = talkrypt_relsign::pubkey_of(self.algo, *gen);
        let desc = seed::Descriptor::for_algo(self.algo);
        let address = seed::address(desc, &pubkey);
        match seal::seal_with_kdf(self.pw.as_bytes(), self.algo, &gen, &pubkey, self.kdf.kdf()) {
            Ok(blob) => {
                if let Err(e) = std::fs::write(self.out.trim(), blob.as_bytes()) {
                    self.status = format!("write failed: {e}");
                    self.zeroize_pw();
                    return;
                }
                set_owner_only(self.out.trim());
                let mnemonic = Zeroizing::new(seed::mnemonic(desc, &gen));
                let hexseed = Zeroizing::new(seed::hexseed(desc, &gen));
                self.result = format!(
                    "SEALED {} key written to:\n  {}\n\naddress: {address}\npubkey:  {}\n\n\
                     >>> WRITE THIS DOWN OFFLINE (shown only here) <<<\nmnemonic: {}\nhexseed:  {}\n\n\
                     Keep the .seed.enc + passphrase to sign; the mnemonic is your offline recovery.",
                    self.algo.label(),
                    self.out.trim(),
                    hex::encode(&pubkey),
                    mnemonic.as_str(),
                    hexseed.as_str(),
                );
                self.status = "key generated.".into();
            }
            Err(e) => self.status = e.to_string(),
        }
        self.zeroize_pw();
    }

    fn do_sign(&mut self) {
        self.status.clear();
        let blob = match std::fs::read_to_string(self.keyfile.trim()) {
            Ok(b) => b,
            Err(e) => {
                self.status = format!("read key file: {e}");
                return;
            }
        };
        if !seal::is_sealed(&blob) {
            self.status = "that file is not a sealed .seed.enc".into();
            return;
        }
        let data = match std::fs::read(self.manifest.trim()) {
            Ok(d) => d,
            Err(e) => {
                self.status = format!("read manifest: {e}");
                return;
            }
        };
        if self.pw.is_empty() {
            self.status = "enter the passphrase".into();
            return;
        }
        match seal::unseal(self.pw.as_bytes(), &blob) {
            Ok(recovered) => {
                let algo = seal::read_public(&blob).map(|(a, _)| a).unwrap_or(self.algo);
                let sig = sign(algo, *recovered, &data);
                let sig_path = format!("{}.{}", self.manifest.trim(), algo.sig_suffix());
                match std::fs::write(&sig_path, hex::encode(&sig)) {
                    Ok(_) => {
                        self.result = format!("signed {} ({})\n-> {sig_path}", self.manifest.trim(), algo.label());
                        self.status = "signed.".into();
                    }
                    Err(e) => self.status = format!("write signature: {e}"),
                }
            }
            Err(e) => self.status = e.to_string(),
        }
        self.zeroize_pw();
    }
}

impl eframe::App for VaultApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("talkrypt keyvault");
            ui.label("Secrets stay in this window — never the terminal or an automation agent.");
            ui.separator();

            ui.horizontal(|ui| {
                ui.radio_value(&mut self.mode, Mode::Keygen, "Generate sealed key");
                ui.radio_value(&mut self.mode, Mode::Sign, "Sign a manifest");
            });
            ui.horizontal(|ui| {
                ui.label("Scheme:");
                ui.radio_value(&mut self.algo, Algo::MlDsa, "ML-DSA-87");
                ui.radio_value(&mut self.algo, Algo::SlhDsa, "SLH-DSA");
            });
            ui.separator();

            match self.mode {
                Mode::Keygen => {
                    path_row(ui, "Output .seed.enc:", &mut self.out);
                    ui.horizontal(|ui| {
                        ui.label("KDF:");
                        egui::ComboBox::from_id_salt("kdf")
                            .selected_text(self.kdf.label())
                            .show_ui(ui, |ui| {
                                for c in [KdfChoice::Desktop, KdfChoice::Mobile, KdfChoice::Embedded, KdfChoice::Fips] {
                                    ui.selectable_value(&mut self.kdf, c, c.label());
                                }
                            });
                    });
                    pw_row(ui, "Passphrase:", &mut self.pw);
                    pw_row(ui, "Confirm:", &mut self.pw2);
                    if ui.button("Generate sealed key").clicked() {
                        self.do_keygen();
                    }
                }
                Mode::Sign => {
                    path_row(ui, "Sealed key (.seed.enc):", &mut self.keyfile);
                    path_row(ui, "Manifest to sign:", &mut self.manifest);
                    pw_row(ui, "Passphrase:", &mut self.pw);
                    if ui.button("Sign").clicked() {
                        self.do_sign();
                    }
                }
            }

            ui.separator();
            if !self.status.is_empty() {
                ui.colored_label(egui::Color32::from_rgb(0xff, 0x55, 0x55), &self.status);
            }
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.monospace(&self.result);
            });
        });
    }
}

fn path_row(ui: &mut egui::Ui, label: &str, val: &mut String) {
    ui.horizontal(|ui| {
        ui.label(label);
        ui.add(egui::TextEdit::singleline(val).desired_width(380.0));
    });
}

fn pw_row(ui: &mut egui::Ui, label: &str, val: &mut String) {
    ui.horizontal(|ui| {
        ui.label(label);
        ui.add(egui::TextEdit::singleline(val).password(true).desired_width(380.0));
    });
}

fn set_owner_only(path: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}
