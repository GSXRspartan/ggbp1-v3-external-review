//! Generates fixed-input synthetic GGBP1R v3 review vectors.
//! This is not a wallet, chain or authorization tool.

use std::{error::Error, fs, path::Path};

use ggbp1_v3_review::{
    Ggbp1Challenge, Ggbp1WireProof, SyntheticOutputWitness, SyntheticSubjectWitness,
    expected_commitment_generator_fingerprint, prove_synthetic,
};
use tari_crypto::ristretto::RistrettoSecretKey;

fn key(value: u64) -> RistrettoSecretKey {
    RistrettoSecretKey::from(value)
}

fn subject() -> SyntheticSubjectWitness {
    SyntheticSubjectWitness::new(key(31))
}

fn challenge(threshold: u64) -> Ggbp1Challenge {
    let subject = subject();
    Ggbp1Challenge {
        network: 42,
        genesis_hash: [1; 32],
        origin_hash: [2; 32],
        gate_id: [3; 16],
        gate_configuration_version: 7,
        subject_id: [4; 16],
        subject_authentication_public_key: subject.public_key(),
        threshold_micro_xtm: threshold,
        nonce: [5; 32],
        expires_at_unix_seconds: 1_800_000_000,
        commitment_generator_fingerprint: expected_commitment_generator_fingerprint(),
    }
}

fn output(id: u8, value: u64, mask: u64, script_key: u64) -> SyntheticOutputWitness {
    SyntheticOutputWitness::new([id; 32], value, key(mask), key(script_key))
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn write_vector(
    name: &str,
    challenge: Ggbp1Challenge,
    outputs: &[SyntheticOutputWitness],
) -> Result<(), Box<dyn Error>> {
    let proof = prove_synthetic(&challenge, &subject(), outputs)?;
    let wire = Ggbp1WireProof { challenge, proof }.to_bytes()?;
    fs::write(
        Path::new("ggbp1-v3-review/vectors").join(format!("{name}.hex")),
        format!("{}\n", lower_hex(&wire)),
    )?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    write_vector("exact_threshold", challenge(100), &[output(1, 100, 11, 21)])?;
    write_vector("above_threshold", challenge(100), &[output(1, 101, 12, 22)])?;
    write_vector(
        "multiple_outputs",
        challenge(100),
        &[output(1, 45, 11, 21), output(2, 55, 12, 22)],
    )?;
    write_vector(
        "valid_output_authority",
        challenge(100),
        &[output(1, 100, 13, 23)],
    )?;
    Ok(())
}
