//! Fixed GGBP1R v3 corpus checks. These fixtures are not compatible with historical v2 parsing.

use ggbp1_v2_historical as v2;
use ggbp1_v3_review::{Ggbp1WireProof, verify_synthetic};

fn decode_hex(input: &str) -> Vec<u8> {
    fn nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid fixed review vector"),
        }
    }

    let input = input.trim().as_bytes();
    assert_eq!(input.len() % 2, 0);
    input
        .chunks_exact(2)
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect()
}

fn vector(name: &str) -> &'static str {
    match name {
        "exact_threshold" => include_str!("../vectors/exact_threshold.hex"),
        "above_threshold" => include_str!("../vectors/above_threshold.hex"),
        "multiple_outputs" => include_str!("../vectors/multiple_outputs.hex"),
        "valid_output_authority" => include_str!("../vectors/valid_output_authority.hex"),
        "bp_only_negative" => include_str!("../vectors/bp_only_negative.hex"),
        _ => unreachable!("fixed vector name"),
    }
}

#[test]
fn resigned_bp_only_negative_reaches_and_fails_the_range_proof_check() {
    let bytes = decode_hex(vector("bp_only_negative"));
    assert_eq!(bytes[6], 3);
    let response = Ggbp1WireProof::from_bytes(&bytes).unwrap();
    assert!(matches!(
        verify_synthetic(&response.challenge, &response.proof),
        Err(ggbp1_v3_review::Ggbp1Error::InvalidMinimumProof(_))
    ));
    assert_eq!(response.to_bytes().unwrap(), bytes);
}

#[test]
fn historical_v2_wire_vectors_are_rejected_by_the_v3_parser() {
    let bytes = decode_hex(include_str!("../../vectors/exact_threshold.hex"));
    assert_eq!(bytes[6], 2);
    assert_eq!(
        Ggbp1WireProof::from_bytes(&bytes).unwrap_err(),
        ggbp1_v3_review::Ggbp1Error::UnsupportedWireVersion
    );
}

#[test]
fn v3_fixed_vectors_verify_and_are_not_v2_compatible() {
    for name in [
        "exact_threshold",
        "above_threshold",
        "multiple_outputs",
        "valid_output_authority",
    ] {
        let bytes = decode_hex(vector(name));
        assert_eq!(bytes[6], 3, "{name}");
        let response = Ggbp1WireProof::from_bytes(&bytes).unwrap();
        verify_synthetic(&response.challenge, &response.proof).unwrap();
        assert_eq!(response.to_bytes().unwrap(), bytes, "{name}");
        assert_eq!(
            v2::Ggbp1WireProof::from_bytes(&bytes).unwrap_err(),
            v2::Ggbp1Error::UnsupportedWireVersion,
            "{name} must remain explicitly v3-only"
        );
    }
}
