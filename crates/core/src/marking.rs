//! Classification **handling markings** (advisory metadata).
//!
//! A marking is a US-style classification banner — a level plus optional SCI
//! **compartments** and dissemination **caveats** (e.g. `TOP SECRET//SI/TK//NOFORN`).
//!
//! **A marking is advisory metadata, not a cryptographic control.** talkrypt's
//! crypto is uniform regardless of label (CNSA 2.0 covers every level up to TOP
//! SECRET), so a label never changes how strongly something is protected. Its
//! integrity, however, *is* protected: a marking rides inside the AEAD-encrypted
//! message payload, so it cannot be read or silently altered in transit by
//! anyone but the recipients. Access to a compartmented channel is enforced by
//! TreeKEM **group membership** (being in the group = holding the key); the
//! compartment names here are the advisory labels for that boundary.
//!
//! The marking *types and wire format are always compiled*, so any build can
//! **read and display** a received marking — important for safety. Whether a
//! build lets a user *originate* markings, and applies a channel policy by
//! default, is gated by the `markings` cargo feature (off in consumer builds,
//! on in builds for that audience).

use crate::error::{CoreError, Result};

/// US classification levels, ordered least→most sensitive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Classification {
    #[default]
    Unclassified,
    /// Controlled Unclassified Information.
    Cui,
    Confidential,
    Secret,
    TopSecret,
}

impl Classification {
    /// Canonical banner token.
    pub fn banner(self) -> &'static str {
        match self {
            Classification::Unclassified => "UNCLASSIFIED",
            Classification::Cui => "CUI",
            Classification::Confidential => "CONFIDENTIAL",
            Classification::Secret => "SECRET",
            Classification::TopSecret => "TOP SECRET",
        }
    }

    /// Short portion-marking token (as used inline, e.g. `(TS)`).
    pub fn portion(self) -> &'static str {
        match self {
            Classification::Unclassified => "U",
            Classification::Cui => "CUI",
            Classification::Confidential => "C",
            Classification::Secret => "S",
            Classification::TopSecret => "TS",
        }
    }

    fn tag(self) -> u8 {
        match self {
            Classification::Unclassified => 0,
            Classification::Cui => 1,
            Classification::Confidential => 2,
            Classification::Secret => 3,
            Classification::TopSecret => 4,
        }
    }

    fn from_tag(t: u8) -> Result<Self> {
        Ok(match t {
            0 => Classification::Unclassified,
            1 => Classification::Cui,
            2 => Classification::Confidential,
            3 => Classification::Secret,
            4 => Classification::TopSecret,
            _ => return Err(CoreError::Malformed("classification tag")),
        })
    }
}

/// A full handling marking: level + advisory compartments + caveats.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Marking {
    pub level: Classification,
    /// SCI compartments / codewords (advisory labels; access is by membership).
    pub compartments: Vec<String>,
    /// Dissemination controls (NOFORN, ORCON, REL TO …).
    pub caveats: Vec<String>,
}

impl Marking {
    /// A bare level with no compartments or caveats.
    pub fn level(level: Classification) -> Self {
        Self {
            level,
            compartments: Vec::new(),
            caveats: Vec::new(),
        }
    }

    /// The canonical banner string, e.g. `TOP SECRET//SI/TK//NOFORN`.
    pub fn banner(&self) -> String {
        let mut s = self.level.banner().to_string();
        if !self.compartments.is_empty() {
            s.push_str("//");
            s.push_str(&self.compartments.join("/"));
        }
        if !self.caveats.is_empty() {
            s.push_str("//");
            s.push_str(&self.caveats.join("/"));
        }
        s
    }

    /// Whether `self` is permitted under a channel `policy`: the message level
    /// must not exceed the policy's level, and every message compartment/caveat
    /// must be one the policy allows. (Advisory consistency check, not a
    /// cryptographic gate.)
    pub fn permitted_under(&self, policy: &Marking) -> bool {
        self.level <= policy.level
            && self.compartments.iter().all(|c| policy.compartments.contains(c))
            && self.caveats.iter().all(|c| policy.caveats.contains(c))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = talkrypt_wire::Writer::new();
        w.put_u8(self.level.tag());
        w.put_u32(self.compartments.len() as u32);
        for c in &self.compartments {
            w.put_bytes(c.as_bytes());
        }
        w.put_u32(self.caveats.len() as u32);
        for c in &self.caveats {
            w.put_bytes(c.as_bytes());
        }
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Marking> {
        let mut r = talkrypt_wire::Reader::new(bytes);
        let m = Self::read(&mut r)?;
        r.finish().map_err(|_| CoreError::Malformed("trailing marking bytes"))?;
        Ok(m)
    }

    fn read(r: &mut talkrypt_wire::Reader) -> Result<Marking> {
        let level = Classification::from_tag(r.get_u8()?)?;
        let compartments = read_strings(r)?;
        let caveats = read_strings(r)?;
        Ok(Marking {
            level,
            compartments,
            caveats,
        })
    }
}

const MAX_MARKING_ITEMS: u32 = 256;

fn read_strings(r: &mut talkrypt_wire::Reader) -> Result<Vec<String>> {
    let n = r.get_u32()?;
    if n > MAX_MARKING_ITEMS {
        return Err(CoreError::Malformed("too many marking items"));
    }
    let mut v = Vec::with_capacity(n as usize);
    for _ in 0..n {
        v.push(
            String::from_utf8(r.get_bytes()?.to_vec())
                .map_err(|_| CoreError::Malformed("marking item utf-8"))?,
        );
    }
    Ok(v)
}

/// Encode an optional marking with a present/absent flag (for embedding in a
/// message payload or descriptor).
pub(crate) fn put_opt(w: &mut talkrypt_wire::Writer, m: &Option<Marking>) {
    match m {
        Some(mk) => {
            w.put_u8(1);
            w.put_bytes(&mk.encode());
        }
        None => w.put_u8(0),
    }
}

/// Decode an optional marking written by [`put_opt`].
pub(crate) fn get_opt(r: &mut talkrypt_wire::Reader) -> Result<Option<Marking>> {
    Ok(match r.get_u8()? {
        0 => None,
        1 => Some(Marking::decode(r.get_bytes()?)?),
        _ => return Err(CoreError::Malformed("optional marking flag")),
    })
}

/// Encode a group-message payload — an optional marking plus the text — as the
/// plaintext that gets sealed under the group epoch (so the marking is
/// authenticated and confidential, just like the body).
pub(crate) fn encode_payload(marking: &Option<Marking>, text: &str) -> Vec<u8> {
    encode_payload_tagged(marking, text, None)
}

/// As [`encode_payload`], plus an optional 8-byte on-message name-id trailer
/// (SUB-SPEC A §4 mode 3). The trailer is length-prefixed so it is self-describing:
/// a payload without it decodes exactly as before, and a decoder that ignores the tag
/// still reads the marking + text. The whole payload is sealed under the group epoch,
/// so the tag is authenticated and confidential like the body.
pub(crate) fn encode_payload_tagged(
    marking: &Option<Marking>,
    text: &str,
    name_tag: Option<[u8; 8]>,
) -> Vec<u8> {
    let mut w = talkrypt_wire::Writer::new();
    put_opt(&mut w, marking);
    w.put_bytes(text.as_bytes());
    if let Some(t) = name_tag {
        w.put_bytes(&t);
    }
    w.into_vec()
}

/// Decode a group-message payload written by [`encode_payload`] /
/// [`encode_payload_tagged`]. Returns the marking and text, tolerating (and ignoring)
/// an optional on-message name-id trailer. Use [`decode_payload_tagged`] when the tag
/// is needed.
pub(crate) fn decode_payload(bytes: &[u8]) -> Option<(Option<Marking>, String)> {
    decode_payload_tagged(bytes).map(|(m, t, _)| (m, t))
}

/// As [`decode_payload`], additionally returning the optional on-message name-id
/// (SUB-SPEC A §4 mode 3). `None` for a payload without a trailer.
pub(crate) fn decode_payload_tagged(
    bytes: &[u8],
) -> Option<(Option<Marking>, String, Option<[u8; 8]>)> {
    let mut r = talkrypt_wire::Reader::new(bytes);
    let marking = get_opt(&mut r).ok()?;
    let text = String::from_utf8(r.get_bytes().ok()?.to_vec()).ok()?;
    let name_tag = if r.remaining() > 0 {
        let t: [u8; 8] = r.get_bytes().ok()?.try_into().ok()?;
        Some(t)
    } else {
        None
    };
    r.finish().ok()?;
    Some((marking, text, name_tag))
}

// NB: a Kani no-panic proof of `Marking::decode` is intentionally NOT included —
// it is CBMC-INTRACTABLE (its nested/looping structure did not converge in >500s),
// unlike the flat `Predicate::decode` (verified in ~3s). `Marking::decode` stays
// covered by the `beacon_body`/property/fuzz tests. See SECURITY-AUDIT R-6.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_without_tag_roundtrips_and_back_compat() {
        // A payload with no name-id trailer decodes the same via both decoders — the
        // trailer is optional, so the pre-mode-3 format is unchanged.
        let bytes = encode_payload(&None, "hello");
        assert_eq!(decode_payload(&bytes), Some((None, "hello".to_string())));
        assert_eq!(
            decode_payload_tagged(&bytes),
            Some((None, "hello".to_string(), None))
        );
    }

    #[test]
    fn payload_with_tag_roundtrips_and_tag_is_ignorable() {
        let tag = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let bytes = encode_payload_tagged(&None, "hi", Some(tag));
        // The tag-aware decoder recovers it...
        assert_eq!(
            decode_payload_tagged(&bytes),
            Some((None, "hi".to_string(), Some(tag)))
        );
        // ...and the plain decoder still reads marking+text, tolerating the trailer.
        assert_eq!(decode_payload(&bytes), Some((None, "hi".to_string())));
    }

    #[test]
    fn levels_are_ordered() {
        assert!(Classification::Unclassified < Classification::Secret);
        assert!(Classification::Secret < Classification::TopSecret);
        assert!(Classification::Cui < Classification::Confidential);
    }

    #[test]
    fn banner_formats_ic_style() {
        let m = Marking {
            level: Classification::TopSecret,
            compartments: vec!["SI".into(), "TK".into()],
            caveats: vec!["NOFORN".into()],
        };
        assert_eq!(m.banner(), "TOP SECRET//SI/TK//NOFORN");
        assert_eq!(Marking::level(Classification::Secret).banner(), "SECRET");
        assert_eq!(Marking::default().banner(), "UNCLASSIFIED");
    }

    #[test]
    fn wire_roundtrips() {
        for m in [
            Marking::default(),
            Marking::level(Classification::Secret),
            Marking {
                level: Classification::TopSecret,
                compartments: vec!["SI".into()],
                caveats: vec!["NOFORN".into(), "ORCON".into()],
            },
        ] {
            assert_eq!(Marking::decode(&m.encode()).unwrap(), m);
        }
    }

    #[test]
    fn opt_wire_roundtrips() {
        for m in [None, Some(Marking::level(Classification::Secret))] {
            let mut w = talkrypt_wire::Writer::new();
            put_opt(&mut w, &m);
            let bytes = w.into_vec();
            let mut r = talkrypt_wire::Reader::new(&bytes);
            assert_eq!(get_opt(&mut r).unwrap(), m);
        }
    }

    #[test]
    fn policy_permits_within_bounds_only() {
        let policy = Marking {
            level: Classification::Secret,
            compartments: vec!["SI".into()],
            caveats: vec!["NOFORN".into()],
        };
        // At or below the policy level with allowed compartments/caveats: ok.
        assert!(Marking::level(Classification::Confidential).permitted_under(&policy));
        assert!(Marking {
            level: Classification::Secret,
            compartments: vec!["SI".into()],
            caveats: vec![],
        }
        .permitted_under(&policy));
        // Above the level: not permitted.
        assert!(!Marking::level(Classification::TopSecret).permitted_under(&policy));
        // Unknown compartment: not permitted.
        assert!(!Marking {
            level: Classification::Secret,
            compartments: vec!["TK".into()],
            caveats: vec![],
        }
        .permitted_under(&policy));
    }
}
