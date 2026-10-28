//! Regression coverage for the independent-audit findings.
//! These are synthetic fixtures only; successful verification is never a holding or grant decision.

use ggbp1_v3_review as v3;
use tari_crypto::{
    compressed_key::CompressedKey,
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
};
use tari_script::push_pubkey_script;

fn key(value: u64) -> RistrettoSecretKey {
    RistrettoSecretKey::from(value)
}

fn v3_subject() -> v3::SyntheticSubjectWitness {
    v3::SyntheticSubjectWitness::new(key(31))
}

fn v3_challenge(nonce_byte: u8, threshold: u64) -> v3::Ggbp1Challenge {
    let subject = v3_subject();
    v3::Ggbp1Challenge {
        network: 42,
        genesis_hash: [1; 32],
        origin_hash: [2; 32],
        gate_id: [3; 16],
        gate_configuration_version: 7,
        subject_id: [4; 16],
        subject_authentication_public_key: subject.public_key(),
        threshold_micro_xtm: threshold,
        nonce: [nonce_byte; 32],
        expires_at_unix_seconds: 1_800_000_000,
        commitment_generator_fingerprint: v3::expected_commitment_generator_fingerprint(),
    }
}

fn v3_output(id: u8, value: u64) -> v3::SyntheticOutputWitness {
    v3::SyntheticOutputWitness::new([id; 32], value, key(11), key(21))
}

#[test]
fn v3_has_no_caller_rng_and_replayed_caller_state_cannot_control_nonces() {
    let _: fn(
        &v3::Ggbp1Challenge,
        &v3::SyntheticSubjectWitness,
        &[v3::SyntheticOutputWitness],
    ) -> Result<v3::Ggbp1Proof, v3::Ggbp1Error> = v3::prove_synthetic;

    let subject = v3_subject();
    let first = v3::prove_synthetic(&v3_challenge(5, 100), &subject, &[v3_output(1, 100)]).unwrap();
    let second =
        v3::prove_synthetic(&v3_challenge(6, 100), &subject, &[v3_output(1, 100)]).unwrap();

    assert_ne!(
        first.authority_signatures[0].get_public_nonce(),
        second.authority_signatures[0].get_public_nonce(),
        "v3 authority signatures use internally derived system-CSPRNG hedged nonce state"
    );
}

#[test]
fn v3_rejects_range_proof_transplant_between_sessions() {
    let subject = v3_subject();
    let first_challenge = v3_challenge(5, 100);
    let second_challenge = v3_challenge(6, 100);
    let first = v3::prove_synthetic(&first_challenge, &subject, &[v3_output(1, 100)]).unwrap();
    let second = v3::prove_synthetic(&second_challenge, &subject, &[v3_output(1, 100)]).unwrap();

    let transplanted = v3::Ggbp1Proof {
        aggregate_minimum_proof: first.aggregate_minimum_proof.clone(),
        ..second
    };
    let response = v3::Ggbp1WireProof {
        challenge: second_challenge.clone(),
        proof: transplanted,
    };
    let decoded = v3::Ggbp1WireProof::from_bytes(&response.to_bytes().unwrap()).unwrap();
    assert_eq!(
        v3::verify_synthetic(&decoded.challenge, &decoded.proof).unwrap_err(),
        v3::Ggbp1Error::InvalidAuthoritySignature
    );

    let valid = v3::Ggbp1WireProof {
        challenge: first_challenge,
        proof: first,
    }
    .to_bytes()
    .unwrap();
    assert_eq!(valid[6], 3, "v3 uses an explicit wire version");
}

#[test]
fn v3_crypto_verification_of_a_fabricated_fixture_is_not_chain_evidence() {
    let subject = v3_subject();
    let challenge = v3_challenge(9, 1_000_000_000_000_000);
    let proof =
        v3::prove_synthetic(&challenge, &subject, &[v3_output(1, 1_000_000_000_000_000)]).unwrap();
    v3::verify_synthetic(&challenge, &proof).unwrap();
    // This success is intentionally not a grant: no authenticated current-unspent chain evidence
    // exists in the v3 core, so any authorization layer must fail closed before consuming it.
}

#[test]
fn v3_rejects_identity_subject_and_output_keys_explicitly() {
    let subject = v3_subject();
    let mut identity_subject = v3_challenge(10, 100);
    identity_subject.subject_authentication_public_key = RistrettoPublicKey::default();
    assert_eq!(
        v3::prove_synthetic(&identity_subject, &subject, &[v3_output(1, 100)]).unwrap_err(),
        v3::Ggbp1Error::IdentityPublicKey
    );

    let challenge = v3_challenge(11, 100);
    let mut proof = v3::prove_synthetic(&challenge, &subject, &[v3_output(1, 100)]).unwrap();
    proof.outputs[0].script_public_key = RistrettoPublicKey::default();
    proof.outputs[0].script =
        push_pubkey_script(&CompressedKey::new_from_pk(RistrettoPublicKey::default()));
    assert_eq!(
        v3::verify_synthetic(&challenge, &proof).unwrap_err(),
        v3::Ggbp1Error::IdentityPublicKey
    );
}
