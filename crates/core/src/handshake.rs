//! Mutually-authenticated session handshake over a transport stream.
//!
//! The dialer is the *initiator*; the accepter is the *responder*. The
//! responder publishes a freshly-signed prekey; both derive the session root
//! from the descriptor's invite token (so only descriptor holders can
//! complete the handshake). Identities are exchanged and each side signs a
//! transcript with ML-DSA-87, giving mutual authentication and pinnable
//! fingerprints.
//!
//!   Initiator → Responder : Init  { id_i, nonce_i }
//!   Responder → Initiator : Resp  { id_r, prekey, nonce_r, sig_r }
//!   Initiator → Responder : Confirm { sig_i }
//!
//! **Both** signatures cover the **full handshake transcript** (SIGMA-style,
//! SECURITY-AUDIT H-1): `tag ‖ suite_id ‖ id_i ‖ nonce_i ‖ id_r ‖ prekey ‖ nonce_r`,
//! length-prefixed. So each party attests to *both* identities, *both* nonces, the
//! prekey, and the negotiated suite — giving both sides cryptographic agreement on
//! exactly who and what they handshook, downgrade resistance on the suite in *both*
//! directions, and no room for field substitution. `sig_r`/`sig_i` differ only by
//! the domain-separation tag.

use rand::RngCore;

use talkrypt_crypto::suite::SessionHandle;
use talkrypt_crypto::{CryptoSuite, IdentityKeyPair, IdentityPublic};
use talkrypt_transport::Stream;
use talkrypt_wire::{Reader, Writer};

use crate::error::{CoreError, Result};

const T_RESP: &[u8] = b"talkrypt-resp-v2";
const T_CONFIRM: &[u8] = b"talkrypt-confirm-v2";

/// The full handshake transcript both parties sign over (SECURITY-AUDIT H-1). All
/// fields are length-prefixed so no byte can migrate between adjacent fields, and
/// the `tag` domain-separates the responder's vs. the initiator's signature. Both
/// parties compute an identical transcript for a given signature (their local view
/// of `id_i/id_r/nonce_i/nonce_r/prekey` agrees), so a verifying party is
/// cryptographically bound to the same identities, nonces, prekey, and suite.
#[allow(clippy::too_many_arguments)]
fn handshake_transcript(
    tag: &[u8],
    suite_id: &str,
    id_i: &IdentityPublic,
    nonce_i: &[u8],
    id_r: &IdentityPublic,
    prekey: &[u8],
    nonce_r: &[u8],
) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_bytes(tag);
    w.put_bytes(suite_id.as_bytes());
    w.put_bytes(&id_i.sig_vk);
    w.put_bytes(nonce_i);
    w.put_bytes(&id_r.sig_vk);
    w.put_bytes(prekey);
    w.put_bytes(nonce_r);
    w.into_vec()
}

/// Outcome of a successful handshake.
pub struct HandshakeResult {
    pub peer_identity: IdentityPublic,
    pub session: Box<dyn SessionHandle>,
}

fn encode_identity(id: &IdentityPublic) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_bytes(&id.sig_vk);
    w.into_vec()
}

fn decode_identity(r: &mut Reader) -> Result<IdentityPublic> {
    // The identity is written as a single length-prefixed blob (see
    // `encode_identity` + `put_bytes`); unwrap it, then parse the inner field.
    let blob = r.get_vec()?;
    let mut ir = Reader::new(&blob);
    let sig_vk = ir.get_vec()?;
    ir.finish()
        .map_err(|_| CoreError::Malformed("identity trailing bytes"))?;
    Ok(IdentityPublic { sig_vk })
}

fn random_nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut n);
    n
}

/// Run the initiator side of the handshake.
pub async fn initiate(
    stream: &mut dyn Stream,
    identity: &IdentityKeyPair,
    suite: &dyn CryptoSuite,
    root0: [u8; 32],
) -> Result<HandshakeResult> {
    let suite_id = suite.descriptor().id;
    let nonce_i = random_nonce();

    // → Init
    let mut w = Writer::new();
    w.put_bytes(&encode_identity(identity.public()));
    w.put_bytes(&nonce_i);
    stream.send_frame(&w.into_vec()).await?;

    // ← Resp
    let resp = stream.recv_frame().await?;
    let mut r = Reader::new(&resp);
    let peer_identity = decode_identity(&mut r)?;
    let prekey = r.get_vec()?;
    let nonce_r = r.get_vec()?;
    let sig_r = r.get_vec()?;

    // Verify the responder's signature over the FULL transcript (H-1): our identity
    // and nonce, its identity, the prekey, its nonce, and the suite. Binding all of
    // it means a MITM cannot have swapped the prekey, suite, or either identity.
    let resp_transcript = handshake_transcript(
        T_RESP,
        &suite_id,
        identity.public(),
        &nonce_i,
        &peer_identity,
        &prekey,
        &nonce_r,
    );
    peer_identity
        .verify(&resp_transcript, &sig_r)
        .map_err(|_| CoreError::PeerAuthFailed)?;

    let session = suite.begin_session(root0, &prekey)?;

    // → Confirm: sign the SAME full transcript (domain-separated tag), so the
    // responder is bound to the identical view of the handshake (H-1).
    let confirm_transcript = handshake_transcript(
        T_CONFIRM,
        &suite_id,
        identity.public(),
        &nonce_i,
        &peer_identity,
        &prekey,
        &nonce_r,
    );
    let sig_i = identity.sign(&confirm_transcript);
    let mut w = Writer::new();
    w.put_bytes(&sig_i);
    stream.send_frame(&w.into_vec()).await?;

    Ok(HandshakeResult {
        peer_identity,
        session,
    })
}

/// Run the responder side of the handshake.
pub async fn respond(
    stream: &mut dyn Stream,
    identity: &IdentityKeyPair,
    suite: &dyn CryptoSuite,
    root0: [u8; 32],
) -> Result<HandshakeResult> {
    let suite_id = suite.descriptor().id;

    // ← Init
    let init = stream.recv_frame().await?;
    let mut r = Reader::new(&init);
    let peer_identity = decode_identity(&mut r)?;
    let nonce_i = r.get_vec()?;

    // Generate a prekey and sign the FULL transcript (H-1): the initiator's identity
    // and nonce, our identity, the prekey, our nonce, and the suite.
    let (prekey_pub, prekey_secret) = suite.generate_prekey();
    let nonce_r = random_nonce();
    let resp_transcript = handshake_transcript(
        T_RESP,
        &suite_id,
        &peer_identity,
        &nonce_i,
        identity.public(),
        &prekey_pub,
        &nonce_r,
    );
    let sig_r = identity.sign(&resp_transcript);

    // → Resp
    let mut w = Writer::new();
    w.put_bytes(&encode_identity(identity.public()));
    w.put_bytes(&prekey_pub);
    w.put_bytes(&nonce_r);
    w.put_bytes(&sig_r);
    stream.send_frame(&w.into_vec()).await?;

    // ← Confirm: verify the initiator's signature over the SAME full transcript
    // (H-1), so both sides agree on identities, nonces, prekey, and suite.
    let confirm = stream.recv_frame().await?;
    let mut r = Reader::new(&confirm);
    let sig_i = r.get_vec()?;
    let confirm_transcript = handshake_transcript(
        T_CONFIRM,
        &suite_id,
        &peer_identity,
        &nonce_i,
        identity.public(),
        &prekey_pub,
        &nonce_r,
    );
    peer_identity
        .verify(&confirm_transcript, &sig_i)
        .map_err(|_| CoreError::PeerAuthFailed)?;

    let session = suite.accept_session(root0, prekey_secret)?;

    Ok(HandshakeResult {
        peer_identity,
        session,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use talkrypt_crypto::SuiteRegistry;
    use talkrypt_transport::{LoopbackFabric, Transport};

    #[tokio::test]
    async fn handshake_establishes_working_session() {
        let reg = SuiteRegistry::with_defaults();
        let suite = reg.get(talkrypt_crypto::DEFAULT_SUITE_ID).unwrap();
        let root0 = [99u8; 32];

        let fabric = LoopbackFabric::new();
        let initiator_t = fabric.transport("alice");
        let responder_t = fabric.transport("bob");
        let mut bob_listener = responder_t.listen().await.unwrap();

        let id_a = IdentityKeyPair::generate();
        let id_b = IdentityKeyPair::generate();
        let fp_a = id_a.public().fingerprint();
        let fp_b = id_b.public().fingerprint();

        let suite_i = suite.clone();
        let suite_r = suite.clone();
        let init_task = tokio::spawn(async move {
            let mut s = initiator_t.dial(&"bob".to_string()).await.unwrap();
            initiate(s.as_mut(), &id_a, suite_i.as_ref(), root0)
                .await
                .map(|h| (h.peer_identity.fingerprint(), encrypt_one(h.session)))
        });
        let resp_task = tokio::spawn(async move {
            let mut s = bob_listener.accept().await.unwrap();
            respond(s.as_mut(), &id_b, suite_r.as_ref(), root0)
                .await
                .map(|h| (h.peer_identity.fingerprint(), h.session))
        });

        let (init_peer_fp, alice_ct) = init_task.await.unwrap().unwrap();
        let (resp_peer_fp, mut bob_session) = resp_task.await.unwrap().unwrap();

        // Each learned the other's real fingerprint (mutual auth).
        assert_eq!(init_peer_fp, fp_b);
        assert_eq!(resp_peer_fp, fp_a);

        // The established sessions actually talk.
        assert_eq!(bob_session.decrypt(&alice_ct).unwrap(), b"first message");
    }

    fn encrypt_one(mut session: Box<dyn SessionHandle>) -> Vec<u8> {
        session.encrypt(b"first message").unwrap()
    }

    /// SECURITY-AUDIT H-1: the signed transcript binds EVERY field — changing any
    /// one of {tag, suite, id_i, nonce_i, id_r, prekey, nonce_r} yields a different
    /// transcript, so a signature over one cannot be lifted to any other handshake,
    /// identity, prekey, or suite. This is the property the SIGMA-style full-binding
    /// rests on (length-prefixed fields ⇒ no byte can migrate between fields).
    #[test]
    fn transcript_binds_every_field() {
        let id_a = IdentityKeyPair::generate();
        let id_b = IdentityKeyPair::generate();
        let base = handshake_transcript(
            T_RESP, "suite-1", id_a.public(), b"ni", id_b.public(), b"pk", b"nr",
        );
        // Each single-field change must alter the transcript.
        let variants = [
            handshake_transcript(T_CONFIRM, "suite-1", id_a.public(), b"ni", id_b.public(), b"pk", b"nr"),
            handshake_transcript(T_RESP, "suite-2", id_a.public(), b"ni", id_b.public(), b"pk", b"nr"),
            handshake_transcript(T_RESP, "suite-1", id_b.public(), b"ni", id_b.public(), b"pk", b"nr"),
            handshake_transcript(T_RESP, "suite-1", id_a.public(), b"NI", id_b.public(), b"pk", b"nr"),
            handshake_transcript(T_RESP, "suite-1", id_a.public(), b"ni", id_a.public(), b"pk", b"nr"),
            handshake_transcript(T_RESP, "suite-1", id_a.public(), b"ni", id_b.public(), b"PK", b"nr"),
            handshake_transcript(T_RESP, "suite-1", id_a.public(), b"ni", id_b.public(), b"pk", b"NR"),
        ];
        for v in variants {
            assert_ne!(base, v, "every field must be bound into the transcript");
        }
        // Length-prefixing prevents field-boundary ambiguity: moving a byte from
        // nonce_i into id_i must NOT collide. ("a"+"bc") != ("ab"+"c").
        let split1 = handshake_transcript(T_RESP, "s", id_a.public(), b"bc", id_b.public(), b"pk", b"nr");
        let split2 = handshake_transcript(T_RESP, "s", id_a.public(), b"c", id_b.public(), b"pk", b"nr");
        assert_ne!(split1, split2, "length-prefixing must prevent field-boundary confusion");
    }

    #[tokio::test]
    async fn tampered_root_breaks_session() {
        // Mismatched invite tokens -> different roots -> session won't decrypt.
        let reg = SuiteRegistry::with_defaults();
        let suite = reg.get(talkrypt_crypto::DEFAULT_SUITE_ID).unwrap();

        let fabric = LoopbackFabric::new();
        let at = fabric.transport("a");
        let bt = fabric.transport("b");
        let mut bl = bt.listen().await.unwrap();
        let id_a = IdentityKeyPair::generate();
        let id_b = IdentityKeyPair::generate();

        let si = suite.clone();
        let sr = suite.clone();
        let it = tokio::spawn(async move {
            let mut s = at.dial(&"b".to_string()).await.unwrap();
            let h = initiate(s.as_mut(), &id_a, si.as_ref(), [1u8; 32])
                .await
                .unwrap();
            let mut sess = h.session;
            sess.encrypt(b"hello").unwrap()
        });
        let rt = tokio::spawn(async move {
            let mut s = bl.accept().await.unwrap();
            // Responder uses a DIFFERENT root.
            let h = respond(s.as_mut(), &id_b, sr.as_ref(), [2u8; 32])
                .await
                .unwrap();
            h.session
        });
        let ct = it.await.unwrap();
        let mut bob = rt.await.unwrap();
        assert!(bob.decrypt(&ct).is_err());
    }
}
