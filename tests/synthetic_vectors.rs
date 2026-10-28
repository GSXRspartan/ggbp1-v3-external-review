//! Review-only fixed vectors for the historical GGBP1R v2 archive.
//! These tests never invoke the unsafe v2 prover and are not wallet, node, or authorization tests.

use ggbp1_v2_historical::{Ggbp1WireProof, verify_synthetic};

fn expected_hex(name: &str) -> &'static str {
    match name {
        "exact_threshold" => include_str!("../vectors/exact_threshold.hex").trim(),
        "above_threshold" => include_str!("../vectors/above_threshold.hex").trim(),
        "multiple_outputs" => include_str!("../vectors/multiple_outputs.hex").trim(),
        "valid_output_authority" => include_str!("../vectors/valid_output_authority.hex").trim(),
        _ => panic!("unknown review vector: {name}"),
    }
}

fn decode_hex(input: &str) -> Vec<u8> {
    fn nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid hexadecimal review vector"),
        }
    }

    let input = input.as_bytes();
    assert_eq!(input.len() % 2, 0, "review vector has an odd hex length");
    input
        .chunks_exact(2)
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect()
}

fn assert_positive_vector(name: &str) {
    let golden_wire = decode_hex(expected_hex(name));
    let golden = Ggbp1WireProof::from_bytes(&golden_wire).unwrap();
    verify_synthetic(&golden.challenge, &golden.proof).unwrap();
    assert_eq!(
        golden.to_bytes().unwrap(),
        golden_wire,
        "{name} static corpus"
    );
}

#[test]
fn positive_exact_threshold_vector_is_valid_and_canonical() {
    assert_positive_vector("exact_threshold");
}

#[test]
fn positive_above_threshold_vector_is_valid_and_canonical() {
    assert_positive_vector("above_threshold");
}

#[test]
fn positive_multiple_outputs_vector_is_valid_and_canonical() {
    assert_positive_vector("multiple_outputs");
}

#[test]
fn positive_valid_output_authority_vector_is_valid_and_canonical() {
    assert_positive_vector("valid_output_authority");
}

#[test]
fn malformed_historical_vectors_are_rejected() {
    let valid_wire = decode_hex(expected_hex("exact_threshold"));
    assert_eq!(
        Ggbp1WireProof::from_bytes(&[0; 7]).unwrap_err(),
        ggbp1_v2_historical::Ggbp1Error::MalformedWire
    );
    assert_eq!(
        Ggbp1WireProof::from_bytes(&valid_wire[..valid_wire.len() - 1]).unwrap_err(),
        ggbp1_v2_historical::Ggbp1Error::MalformedWire
    );
    let mut trailing = valid_wire;
    trailing.push(0);
    assert_eq!(
        Ggbp1WireProof::from_bytes(&trailing).unwrap_err(),
        ggbp1_v2_historical::Ggbp1Error::MalformedWire
    );
}
