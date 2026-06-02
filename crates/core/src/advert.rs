//! Scheme **advertisement** at a server.
//!
//! A chat's crypto scheme always lives in the (private) invite. *Advertising*
//! it at a server is a separate, **opt-in** act (default off): some users prefer
//! to communicate the scheme purely out of band. When enabled, the host
//! publishes an encrypted [`BeaconBody`] that a storage host keeps as opaque
//! ciphertext and serves to clients.
//!
//! **Trust boundary (stated honestly).** The advertisement is sealed under the
//! chat root (derived from the invite-token PSK) via the encrypted-beacon
//! broadcast path — post-quantum + AES-256-GCM. Therefore:
//!   * A **pure directory / blob host** that does not hold the invite token
//!     cannot read it — it stores opaque ciphertext. This is the intended
//!     "server advertisement, relay learns nothing" posture.
//!   * A **non-member relay** ([`crate::relay::RelayHub`]) *does* hold the chat
//!     root (it needs the PSK to run the pairwise handshake), so it **can**
//!     open the advertisement. That is acceptable precisely because advertising
//!     is opt-in: enabling it is a deliberate choice to reveal the scheme to the
//!     storing party. Don't advertise to a relay you don't want learning the
//!     posture.

use talkrypt_crypto::beacon::{open_broadcast, seal_broadcast, BeaconBody};
use std::collections::HashMap;

use crate::descriptor::ChatDescriptor;
use crate::error::Result;

/// Whether (and how) a chat publishes its scheme at a server.
///
/// Default is [`AdvertisePolicy::Off`] — the opt-in posture: the scheme is in
/// the private invite but never published at a server unless the creator turns
/// it on. `Fingerprint`/`Full` choose the beacon granularity when on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AdvertisePolicy {
    /// Opt-in default: do not advertise at any server.
    #[default]
    Off,
    /// Advertise only the scheme fingerprint (receiver must already hold a
    /// matching registered scheme).
    Fingerprint,
    /// Advertise the full scheme definition (adoptable by a receiver only after
    /// explicit confirmation).
    Full,
}

impl AdvertisePolicy {
    pub fn is_on(self) -> bool {
        !matches!(self, AdvertisePolicy::Off)
    }
}

/// Build the sealed advertisement blob for a chat under `policy`. Returns
/// `None` when the policy is `Off`. The blob is opaque to anyone lacking the
/// chat root (see the module trust-boundary note).
pub fn build_advertisement(desc: &ChatDescriptor, policy: AdvertisePolicy) -> Result<Option<Vec<u8>>> {
    let body = match policy {
        AdvertisePolicy::Off => return Ok(None),
        AdvertisePolicy::Fingerprint => BeaconBody::Fingerprint(desc.scheme_hash()),
        AdvertisePolicy::Full => BeaconBody::Full {
            suite_id: desc.resolved_suite_id().to_string(),
            params: desc.suite_params.clone(),
        },
    };
    Ok(Some(seal_broadcast(&desc.derive_root(), &body)?))
}

/// Open an advertisement blob using the chat's invite (descriptor). Yields the
/// advertised [`BeaconBody`]; match its `fingerprint()` against a local
/// registry to decide whether you can participate.
pub fn open_advertisement(desc: &ChatDescriptor, blob: &[u8]) -> Result<BeaconBody> {
    Ok(open_broadcast(&desc.derive_root(), blob)?)
}

/// An opaque advertisement store for a directory/relay host: maps a channel
/// name to a sealed blob the host cannot read (unless it holds the invite).
#[derive(Default)]
pub struct AdvertStore {
    map: HashMap<String, Vec<u8>>,
}

impl AdvertStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store (or replace) the sealed advertisement for a channel.
    pub fn put(&mut self, channel: &str, blob: Vec<u8>) {
        self.map.insert(channel.to_string(), blob);
    }

    /// Fetch the opaque advertisement blob for a channel, if present.
    pub fn get(&self, channel: &str) -> Option<&[u8]> {
        self.map.get(channel).map(|v| v.as_slice())
    }

    /// Number of stored advertisements.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor::{Persistence, TopologyKind};

    fn desc(suite_id: &str) -> ChatDescriptor {
        ChatDescriptor::new(
            TopologyKind::Hub,
            Persistence::Ephemeral,
            suite_id,
            vec!["relay".into()],
            "#general",
        )
    }

    #[test]
    fn off_policy_produces_no_advertisement() {
        let d = desc(talkrypt_crypto::DEFAULT_SUITE_ID);
        assert!(build_advertisement(&d, AdvertisePolicy::Off).unwrap().is_none());
        assert!(!AdvertisePolicy::Off.is_on());
        assert!(AdvertisePolicy::Full.is_on());
    }

    #[test]
    fn advertisement_roundtrips_for_invite_holder() {
        for (policy, want_full) in [(AdvertisePolicy::Fingerprint, false), (AdvertisePolicy::Full, true)] {
            let d = desc(talkrypt_crypto::DEFAULT_SUITE_ID);
            let blob = build_advertisement(&d, policy).unwrap().unwrap();
            let body = open_advertisement(&d, &blob).unwrap();
            // Either way, the advertised fingerprint matches the chat's scheme.
            assert_eq!(body.fingerprint(), d.scheme_hash());
            assert_eq!(body.is_full(), want_full);
        }
    }

    #[test]
    fn directory_without_the_invite_cannot_read_it() {
        // A pure directory holds a different (or no) invite token, so its
        // derived root differs and the sealed advertisement is opaque to it.
        let host = desc(talkrypt_crypto::DEFAULT_SUITE_ID);
        let blob = build_advertisement(&host, AdvertisePolicy::Full).unwrap().unwrap();
        let outsider = desc(talkrypt_crypto::DEFAULT_SUITE_ID); // fresh random invite token
        assert_ne!(host.invite_token, outsider.invite_token);
        assert!(open_advertisement(&outsider, &blob).is_err());
    }

    #[test]
    fn advert_store_put_get() {
        let mut store = AdvertStore::new();
        assert!(store.is_empty());
        store.put("#general", vec![1, 2, 3]);
        assert_eq!(store.get("#general"), Some(&[1, 2, 3][..]));
        assert_eq!(store.get("#other"), None);
        assert_eq!(store.len(), 1);
    }
}
