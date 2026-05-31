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
//!   Responder → Initiator : Resp  { id_r, prekey, nonce_r, sig_r }   sig_r over (nonce_i ‖ prekey ‖ suite_id)
//!   Initiator → Responder : Confirm { sig_i }                        sig_i over (nonce_r ‖ fingerprint(id_r))

use rand::RngCore;

use talkrypt_crypto::suite::SessionHandle;
use talkrypt_crypto::{CryptoSuite, IdentityKeyPair, IdentityPublic};
use talkrypt_transport::Stream;
use talkrypt_wire::{Reader, Writer};

use crate::error::{CoreError, Result};

const T_RESP: &[u8] = b"talkrypt-resp-v1";
const T_CONFIRM: &[u8] = b"talkrypt-confirm-v1";

/// Outcome of a successful handshake.
pub struct HandshakeResult {
    pub peer_identity: IdentityPublic,
    pub session: Box<dyn SessionHandle>,
}

fn encode_identity(id: &IdentityPublic) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_bytes(&id.sig_vk);
    w.put_bytes(&id.x25519_pub);
    w.into_vec()
}

fn decode_identity(r: &mut Reader) -> Result<IdentityPublic> {
    // The identity is written as a single length-prefixed blob (see
    // `encode_identity` + `put_bytes`); unwrap it, then parse the inner fields.
    let blob = r.get_vec()?;
    let mut ir = Reader::new(&blob);
    let sig_vk = ir.get_vec()?;
    let x = ir.get_bytes()?;
    if x.len() != 32 {
        return Err(CoreError::Malformed("identity x25519 length"));
    }
    let mut x25519_pub = [0u8; 32];
    x25519_pub.copy_from_slice(x);
    ir.finish()
        .map_err(|_| CoreError::Malformed("identity trailing bytes"))?;
    Ok(IdentityPublic { sig_vk, x25519_pub })
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

    // Verify responder's signature over (nonce_i ‖ prekey ‖ suite_id).
    let mut transcript = Vec::new();
    transcript.extend_from_slice(T_RESP);
    transcript.extend_from_slice(&nonce_i);
    transcript.extend_from_slice(&prekey);
    transcript.extend_from_slice(suite_id.as_bytes());
    peer_identity
        .verify(&transcript, &sig_r)
        .map_err(|_| CoreError::PeerAuthFailed)?;

    let session = suite.begin_session(root0, &prekey)?;

    // → Confirm: sign (nonce_r ‖ fingerprint(responder)).
    let mut ct = Vec::new();
    ct.extend_from_slice(T_CONFIRM);
    ct.extend_from_slice(&nonce_r);
    ct.extend_from_slice(&peer_identity.fingerprint());
    let sig_i = identity.sign(&ct);
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

    // Generate a prekey and sign (nonce_i ‖ prekey ‖ suite_id).
    let (prekey_pub, prekey_secret) = suite.generate_prekey();
    let nonce_r = random_nonce();
    let mut transcript = Vec::new();
    transcript.extend_from_slice(T_RESP);
    transcript.extend_from_slice(&nonce_i);
    transcript.extend_from_slice(&prekey_pub);
    transcript.extend_from_slice(suite_id.as_bytes());
    let sig_r = identity.sign(&transcript);

    // → Resp
    let mut w = Writer::new();
    w.put_bytes(&encode_identity(identity.public()));
    w.put_bytes(&prekey_pub);
    w.put_bytes(&nonce_r);
    w.put_bytes(&sig_r);
    stream.send_frame(&w.into_vec()).await?;

    // ← Confirm: verify initiator's signature over (nonce_r ‖ our fingerprint).
    let confirm = stream.recv_frame().await?;
    let mut r = Reader::new(&confirm);
    let sig_i = r.get_vec()?;
    let mut ct = Vec::new();
    ct.extend_from_slice(T_CONFIRM);
    ct.extend_from_slice(&nonce_r);
    ct.extend_from_slice(&identity.public().fingerprint());
    peer_identity
        .verify(&ct, &sig_i)
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
