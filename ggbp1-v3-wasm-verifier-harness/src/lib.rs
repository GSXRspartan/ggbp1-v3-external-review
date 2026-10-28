//! Verifier-only GGBP1R v3 WASM diagnostics.
//! No wallet, proof generation, chain view or authorization API is exposed here.

use ggbp1_v3_review::{Ggbp1WireProof, verify_synthetic};
use wasm_bindgen::prelude::wasm_bindgen;

const VECTOR_NAMES: [&str; 4] = [
    "exact_threshold",
    "above_threshold",
    "multiple_outputs",
    "valid_output_authority",
];

fn vector_hex(name: &str) -> &'static str {
    match name {
        "exact_threshold" => {
            include_str!("../../ggbp1-v3-review/vectors/exact_threshold.hex").trim()
        }
        "above_threshold" => {
            include_str!("../../ggbp1-v3-review/vectors/above_threshold.hex").trim()
        }
        "multiple_outputs" => {
            include_str!("../../ggbp1-v3-review/vectors/multiple_outputs.hex").trim()
        }
        "valid_output_authority" => {
            include_str!("../../ggbp1-v3-review/vectors/valid_output_authority.hex").trim()
        }
        "bp_only_negative" => {
            include_str!("../../ggbp1-v3-review/vectors/bp_only_negative.hex").trim()
        }
        _ => unreachable!("fixed vector name"),
    }
}

fn decode_hex(input: &str) -> Option<Vec<u8>> {
    fn nibble(value: u8) -> Option<u8> {
        match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            _ => None,
        }
    }

    let input = input.as_bytes();
    if input.len() % 2 != 0 {
        return None;
    }
    input
        .chunks_exact(2)
        .map(|pair| Some((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

fn response(name: &str) -> Option<Ggbp1WireProof> {
    Ggbp1WireProof::from_bytes(&decode_hex(vector_hex(name))?).ok()
}

fn verify_fixed_corpus() -> bool {
    VECTOR_NAMES.iter().all(|name| {
        let Some(response) = response(name) else {
            return false;
        };
        verify_synthetic(&response.challenge, &response.proof).is_ok()
            && response
                .to_bytes()
                .is_ok_and(|encoded| encoded == decode_hex(vector_hex(name)).unwrap())
    })
}

fn rejects_negative_vectors() -> bool {
    let mut threshold = response("exact_threshold").expect("fixed vector");
    threshold.challenge.threshold_micro_xtm += 1;

    let mut truncated_proof = response("exact_threshold").expect("fixed vector");
    truncated_proof.proof.aggregate_minimum_proof.pop();

    let mut swapped_signatures = response("multiple_outputs").expect("fixed vector");
    swapped_signatures.proof.authority_signatures.swap(0, 1);

    let mut swapped_records = response("multiple_outputs").expect("fixed vector");
    swapped_records.proof.outputs.swap(0, 1);
    swapped_records.proof.authority_signatures.swap(0, 1);

    let bp_only_negative = response("bp_only_negative").expect("fixed vector");
    let historical_v2 = decode_hex(include_str!("../../vectors/exact_threshold.hex").trim())
        .expect("historical vector");

    [
        threshold,
        truncated_proof,
        swapped_signatures,
        swapped_records,
    ]
    .iter()
    .all(|response| verify_synthetic(&response.challenge, &response.proof).is_err())
        && matches!(
            verify_synthetic(&bp_only_negative.challenge, &bp_only_negative.proof),
            Err(ggbp1_v3_review::Ggbp1Error::InvalidMinimumProof(_))
        )
        && matches!(
            Ggbp1WireProof::from_bytes(&historical_v2),
            Err(ggbp1_v3_review::Ggbp1Error::UnsupportedWireVersion)
        )
}

/// Returns 0 only when every fixed v3 fixture parses, verifies and canonically reserializes.
#[wasm_bindgen]
pub fn ggbp1_v3_verify_fixed_corpus() -> u32 {
    if verify_fixed_corpus() { 0 } else { 1 }
}

/// Returns 0 only when threshold/session tampering, truncated proof bytes, signature swapping,
/// record reordering, and a validly re-signed BP+-only negative are rejected by the v3 verifier.
#[wasm_bindgen]
pub fn ggbp1_v3_rejects_negative_corpus() -> u32 {
    if rejects_negative_vectors() { 0 } else { 1 }
}

/// Returns 0 only when the `getrandom` WASM backend obtains bytes through Web Crypto.
#[wasm_bindgen]
pub fn ggbp1_v3_browser_secure_randomness_probe() -> u32 {
    let mut bytes = [0u8; 32];
    if getrandom::fill(&mut bytes).is_ok() {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_and_negative_cases_are_checked_by_the_harness() {
        assert!(verify_fixed_corpus());
        assert!(rejects_negative_vectors());
    }
}
