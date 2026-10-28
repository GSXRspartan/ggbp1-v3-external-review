//! Historical Browser-Web-Crypto WASM verifier archive for GGBP1R v2.
//!
//! It exposes only two diagnostics: fixed-corpus verification and a secure-randomness probe.
//! It does not construct proofs, access a wallet, read chain data, or authorize anything.

use ggbp1_v2_historical::{Ggbp1WireProof, verify_synthetic};
use wasm_bindgen::prelude::wasm_bindgen;

const VECTOR_NAMES: [&str; 4] = [
    "exact_threshold",
    "above_threshold",
    "multiple_outputs",
    "valid_output_authority",
];

fn vector_hex(name: &str) -> &'static str {
    match name {
        "exact_threshold" => include_str!("../../vectors/exact_threshold.hex").trim(),
        "above_threshold" => include_str!("../../vectors/above_threshold.hex").trim(),
        "multiple_outputs" => include_str!("../../vectors/multiple_outputs.hex").trim(),
        "valid_output_authority" => include_str!("../../vectors/valid_output_authority.hex").trim(),
        _ => unreachable!("fixed corpus name"),
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

fn verify_fixed_corpus() -> bool {
    VECTOR_NAMES.iter().all(|name| {
        let Some(bytes) = decode_hex(vector_hex(name)) else {
            return false;
        };
        let Ok(response) = Ggbp1WireProof::from_bytes(&bytes) else {
            return false;
        };
        verify_synthetic(&response.challenge, &response.proof).is_ok()
            && response.to_bytes().is_ok_and(|encoded| encoded == bytes)
    })
}

/// Returns 0 only when every fixed GGBP1R v2 fixture parses, verifies, and reserializes exactly.
/// Nonzero means a corpus or verifier failure. This is not an authorization decision.
#[wasm_bindgen]
pub fn ggbp1_verify_fixed_corpus() -> u32 {
    if verify_fixed_corpus() { 0 } else { 1 }
}

/// Returns 0 only when `getrandom 0.4.3` obtains bytes from its WASM `wasm_js` backend.
/// That backend invokes `globalThis.crypto.getRandomValues`; no fixed seed is used here.
/// Nonzero means the browser/runtime did not make the Web Crypto API available.
#[wasm_bindgen]
pub fn ggbp1_browser_secure_randomness_probe() -> u32 {
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
    fn fixed_corpus_is_valid_in_the_harness() {
        assert!(verify_fixed_corpus());
    }
}
