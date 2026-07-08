//! Empirical spike: does OpenMLS's pure-PQ ciphersuite
//! `MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87` (ML-KEM-1024 + ML-DSA-87) actually
//! run a full group lifecycle end-to-end? Verifies talkrypt's needed features:
//! create, add, application messages (both ways), member self-update (PCS), remove.

use openmls::prelude::tls_codec::{Deserialize, Serialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

/// Round-trip an outbound MLS message through the wire into an inbound one — models
/// the message actually crossing the (untrusted) delivery service.
fn to_in(m: &MlsMessageOut) -> MlsMessageIn {
    let bytes = m.tls_serialize_detached().expect("serialize");
    MlsMessageIn::tls_deserialize(&mut bytes.as_slice()).expect("deserialize")
}

const CS: Ciphersuite = Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87;

fn party(
    name: &str,
    provider: &impl OpenMlsProvider,
) -> (CredentialWithKey, SignatureKeyPair) {
    let credential = BasicCredential::new(name.as_bytes().to_vec());
    let signer = SignatureKeyPair::new(CS.signature_algorithm())
        .expect("sig keygen");
    signer.store(provider.storage()).expect("store signer");
    let cwk = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.public().into(),
    };
    (cwk, signer)
}

fn key_package(
    provider: &impl OpenMlsProvider,
    signer: &SignatureKeyPair,
    cwk: CredentialWithKey,
) -> KeyPackageBundle {
    KeyPackage::builder()
        .build(CS, provider, signer, cwk)
        .expect("kp build")
}

fn main() {
    // Confirms the git-main dep + draft feature actually expose the PQ suite.
    println!("ciphersuite = {CS:?}");
    println!("signature_algorithm = {:?}", CS.signature_algorithm());

    let alice_p = OpenMlsRustCrypto::default();
    let bob_p = OpenMlsRustCrypto::default();

    let (alice_cwk, alice_signer) = party("alice", &alice_p);
    let (bob_cwk, bob_signer) = party("bob", &bob_p);

    // Bob publishes a KeyPackage.
    let bob_kpb = key_package(&bob_p, &bob_signer, bob_cwk.clone());
    let bob_kp = bob_kpb.key_package().clone();

    // Alice creates the group.
    let mut alice = MlsGroup::builder()
        .ciphersuite(CS)
        .use_ratchet_tree_extension(true)
        .build(&alice_p, &alice_signer, alice_cwk.clone())
        .expect("create group");
    println!("[ok] created group under PQ ciphersuite, epoch {}", alice.epoch().as_u64());

    // Alice adds Bob.
    let (commit, welcome, _group_info) = alice
        .add_members(&alice_p, &alice_signer, &[bob_kp])
        .expect("add_members");
    alice.merge_pending_commit(&alice_p).expect("merge add");
    println!("[ok] added bob, epoch {}", alice.epoch().as_u64());
    let _ = commit;

    // Bob joins from the Welcome.
    let welcome_in = to_in(&welcome);
    let welcome = match welcome_in.extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        other => panic!("expected welcome, got {other:?}"),
    };
    let join_config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();
    let mut bob = StagedWelcome::new_from_welcome(&bob_p, &join_config, welcome, None)
        .expect("staged welcome")
        .into_group(&bob_p)
        .expect("into group");
    println!("[ok] bob joined, epoch {}", bob.epoch().as_u64());
    assert_eq!(alice.epoch(), bob.epoch(), "epochs converge after join");

    // Alice -> Bob application message.
    let msg = alice
        .create_message(&alice_p, &alice_signer, b"hello bob (pq)")
        .expect("create_message");
    let protocol_msg = to_in(&msg).try_into_protocol_message().expect("protocol msg");
    let processed = bob
        .process_message(&bob_p, protocol_msg)
        .expect("process_message");
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => {
            let text = String::from_utf8(app.into_bytes()).unwrap();
            println!("[ok] bob received: {text:?}");
            assert_eq!(text, "hello bob (pq)");
        }
        other => panic!("expected application message, got {other:?}"),
    }

    // Bob self-updates (member-driven PCS: rekeys his own leaf).
    let (bob_commit, _welcome, _gi) = bob
        .self_update(&bob_p, &bob_signer, LeafNodeParameters::default())
        .expect("self_update")
        .into_contents();
    bob.merge_pending_commit(&bob_p).expect("bob merge update");
    // Alice applies Bob's update.
    let processed = alice
        .process_message(&alice_p, to_in(&bob_commit).try_into_protocol_message().unwrap())
        .expect("alice process bob update");
    if let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() {
        alice.merge_staged_commit(&alice_p, *staged).expect("alice merge bob update");
    } else {
        panic!("expected staged commit for bob's update");
    }
    println!("[ok] bob self-update applied; epochs a={} b={}", alice.epoch().as_u64(), bob.epoch().as_u64());
    assert_eq!(alice.epoch(), bob.epoch(), "epochs converge after self-update");

    // Bob -> Alice application message after the rekey.
    let msg = bob
        .create_message(&bob_p, &bob_signer, b"hi alice, rekeyed")
        .expect("bob create_message");
    let processed = alice
        .process_message(
            &alice_p,
            to_in(&msg).try_into_protocol_message().unwrap(),
        )
        .expect("alice process bob msg");
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => {
            let text = String::from_utf8(app.into_bytes()).unwrap();
            println!("[ok] alice received (post-rekey): {text:?}");
            assert_eq!(text, "hi alice, rekeyed");
        }
        other => panic!("expected application message, got {other:?}"),
    }

    // Alice removes Bob.
    let bob_leaf = alice
        .members()
        .find(|m| m.credential.serialized_content() == b"bob")
        .map(|m| m.index)
        .expect("find bob leaf");
    let (_commit, _welcome, _gi) = alice
        .remove_members(&alice_p, &alice_signer, &[bob_leaf])
        .expect("remove_members");
    alice.merge_pending_commit(&alice_p).expect("merge remove");
    println!("[ok] removed bob; alice group size = {}", alice.members().count());

    println!("\nSPIKE PASSED: full lifecycle under {CS:?}");
}
