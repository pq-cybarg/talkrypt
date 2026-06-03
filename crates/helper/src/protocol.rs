//! The helper request/response protocol.
//!
//! Length-prefixed frames (see [`crate::frame`]) carry one [`Request`] or
//! [`Response`], each a tagged, length-prefixed encoding over `talkrypt-wire`.
//! Secrets and passphrases cross the local IPC channel in the clear *within the
//! OS* — the channel itself (owner-only Unix socket / ACL'd Named Pipe) is the
//! confidentiality boundary; secrets are sealed (Argon2id + AES-256-GCM) before
//! they ever touch disk.

use talkrypt_wire::{Reader, Writer};

use crate::error::{HelperError, Result};

/// Protocol version reported by `Ping`.
pub const PROTOCOL_VERSION: u32 = 1;

/// A request from the app to the helper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Liveness/version check.
    Ping,
    /// Seal `secret` under `passphrase`; returns the sealed blob (stateless).
    Seal { passphrase: Vec<u8>, secret: Vec<u8> },
    /// Unseal a blob produced by `Seal`.
    Unseal { passphrase: Vec<u8>, blob: Vec<u8> },
    /// Seal `secret` and persist it under `name` (replacing any existing).
    Put {
        name: String,
        passphrase: Vec<u8>,
        secret: Vec<u8>,
    },
    /// Load and unseal the secret stored under `name`.
    Get { name: String, passphrase: Vec<u8> },
    /// Delete the stored key `name` (no error if absent).
    Delete { name: String },
    /// Generate a fresh ML-DSA-87 identity (via the audited core), seal its
    /// seed under `name`, and return the fingerprint.
    GenerateIdentity { name: String, passphrase: Vec<u8> },
    /// Report the fingerprint of the stored identity `name`.
    IdentityFingerprint { name: String, passphrase: Vec<u8> },
    /// Parse a `talkrypt://` invite (via the audited core) and report its
    /// resolved scheme id and scheme fingerprint — no secret involved.
    ValidateInvite { uri: String },
}

/// A response from the helper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    Pong { version: u32 },
    Sealed(Vec<u8>),
    Unsealed(Vec<u8>),
    Ok,
    Secret(Vec<u8>),
    /// A 48-byte fingerprint.
    Fingerprint(Vec<u8>),
    /// `(resolved_suite_id, scheme_fingerprint)`.
    Invite { suite_id: String, scheme: Vec<u8> },
    Error(String),
}

fn str_bytes(b: &[u8]) -> Result<String> {
    String::from_utf8(b.to_vec()).map_err(|_| HelperError::Protocol("invalid utf-8"))
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Request::Ping => w.put_u8(0),
            Request::Seal { passphrase, secret } => {
                w.put_u8(1);
                w.put_bytes(passphrase);
                w.put_bytes(secret);
            }
            Request::Unseal { passphrase, blob } => {
                w.put_u8(2);
                w.put_bytes(passphrase);
                w.put_bytes(blob);
            }
            Request::Put {
                name,
                passphrase,
                secret,
            } => {
                w.put_u8(3);
                w.put_bytes(name.as_bytes());
                w.put_bytes(passphrase);
                w.put_bytes(secret);
            }
            Request::Get { name, passphrase } => {
                w.put_u8(4);
                w.put_bytes(name.as_bytes());
                w.put_bytes(passphrase);
            }
            Request::Delete { name } => {
                w.put_u8(5);
                w.put_bytes(name.as_bytes());
            }
            Request::GenerateIdentity { name, passphrase } => {
                w.put_u8(6);
                w.put_bytes(name.as_bytes());
                w.put_bytes(passphrase);
            }
            Request::IdentityFingerprint { name, passphrase } => {
                w.put_u8(7);
                w.put_bytes(name.as_bytes());
                w.put_bytes(passphrase);
            }
            Request::ValidateInvite { uri } => {
                w.put_u8(8);
                w.put_bytes(uri.as_bytes());
            }
        }
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Request> {
        let mut r = Reader::new(bytes);
        let req = match r.get_u8()? {
            0 => Request::Ping,
            1 => Request::Seal {
                passphrase: r.get_vec()?,
                secret: r.get_vec()?,
            },
            2 => Request::Unseal {
                passphrase: r.get_vec()?,
                blob: r.get_vec()?,
            },
            3 => Request::Put {
                name: str_bytes(r.get_bytes()?)?,
                passphrase: r.get_vec()?,
                secret: r.get_vec()?,
            },
            4 => Request::Get {
                name: str_bytes(r.get_bytes()?)?,
                passphrase: r.get_vec()?,
            },
            5 => Request::Delete {
                name: str_bytes(r.get_bytes()?)?,
            },
            6 => Request::GenerateIdentity {
                name: str_bytes(r.get_bytes()?)?,
                passphrase: r.get_vec()?,
            },
            7 => Request::IdentityFingerprint {
                name: str_bytes(r.get_bytes()?)?,
                passphrase: r.get_vec()?,
            },
            8 => Request::ValidateInvite {
                uri: str_bytes(r.get_bytes()?)?,
            },
            _ => return Err(HelperError::Protocol("unknown request tag")),
        };
        r.finish()?;
        Ok(req)
    }
}

impl Response {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Response::Pong { version } => {
                w.put_u8(0);
                w.put_u32(*version);
            }
            Response::Sealed(b) => {
                w.put_u8(1);
                w.put_bytes(b);
            }
            Response::Unsealed(b) => {
                w.put_u8(2);
                w.put_bytes(b);
            }
            Response::Ok => w.put_u8(3),
            Response::Secret(b) => {
                w.put_u8(4);
                w.put_bytes(b);
            }
            Response::Fingerprint(b) => {
                w.put_u8(5);
                w.put_bytes(b);
            }
            Response::Invite { suite_id, scheme } => {
                w.put_u8(6);
                w.put_bytes(suite_id.as_bytes());
                w.put_bytes(scheme);
            }
            Response::Error(m) => {
                w.put_u8(7);
                w.put_bytes(m.as_bytes());
            }
        }
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Response> {
        let mut r = Reader::new(bytes);
        let resp = match r.get_u8()? {
            0 => Response::Pong {
                version: r.get_u32()?,
            },
            1 => Response::Sealed(r.get_vec()?),
            2 => Response::Unsealed(r.get_vec()?),
            3 => Response::Ok,
            4 => Response::Secret(r.get_vec()?),
            5 => Response::Fingerprint(r.get_vec()?),
            6 => Response::Invite {
                suite_id: str_bytes(r.get_bytes()?)?,
                scheme: r.get_vec()?,
            },
            7 => Response::Error(str_bytes(r.get_bytes()?)?),
            _ => return Err(HelperError::Protocol("unknown response tag")),
        };
        r.finish()?;
        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrips() {
        let reqs = [
            Request::Ping,
            Request::Seal {
                passphrase: b"pw".to_vec(),
                secret: b"s".to_vec(),
            },
            Request::Unseal {
                passphrase: b"pw".to_vec(),
                blob: vec![1, 2, 3],
            },
            Request::Put {
                name: "id".into(),
                passphrase: b"pw".to_vec(),
                secret: b"s".to_vec(),
            },
            Request::Get {
                name: "id".into(),
                passphrase: b"pw".to_vec(),
            },
            Request::Delete { name: "id".into() },
            Request::GenerateIdentity {
                name: "id".into(),
                passphrase: b"pw".to_vec(),
            },
            Request::IdentityFingerprint {
                name: "id".into(),
                passphrase: b"pw".to_vec(),
            },
            Request::ValidateInvite {
                uri: "talkrypt://x".into(),
            },
        ];
        for req in reqs {
            assert_eq!(Request::decode(&req.encode()).unwrap(), req);
        }
    }

    #[test]
    fn response_roundtrips() {
        let resps = [
            Response::Pong { version: 1 },
            Response::Sealed(vec![9, 9]),
            Response::Unsealed(vec![8]),
            Response::Ok,
            Response::Secret(vec![7]),
            Response::Fingerprint(vec![0u8; 48]),
            Response::Invite {
                suite_id: "tk.dr".into(),
                scheme: vec![1u8; 32],
            },
            Response::Error("nope".into()),
        ];
        for resp in resps {
            assert_eq!(Response::decode(&resp.encode()).unwrap(), resp);
        }
    }

    #[test]
    fn trailing_bytes_rejected() {
        let mut b = Request::Ping.encode();
        b.push(0xFF);
        assert!(Request::decode(&b).is_err());
    }
}
