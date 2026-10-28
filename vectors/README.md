# Historical GGBP1R v2 vector catalogue

This directory preserves the four fixed positive vectors for the unsafe historical v2 archive. They are public proof responses only: no masks, values, subject secrets, or script private keys are serialized. They are evidence for review compatibility, not wallet ownership evidence, real chain outputs, or authorization receipts.

| Fixture | Synthetic recipe | Default test result |
|---|---|---|
| `exact_threshold.hex` | one value 100; threshold 100 | parses, verifies, and reserializes canonically |
| `above_threshold.hex` | one value 101; threshold 100 | parses, verifies, and reserializes canonically |
| `multiple_outputs.hex` | values 45 + 55; threshold 100 | parses, verifies, and reserializes canonically |
| `valid_output_authority.hex` | one value 100 with matching fixture script key | parses, verifies, and reserializes canonically |

`tests/synthetic_vectors.rs` runs those five default v2 archive checks (the four vectors plus malformed-wire rejection). It does not invoke the unsafe prover. `tests/vulnerability_reproduction.rs` is deliberately empty by default; its one cloned-caller-RNG nonce-reuse reproduction exists only when `historical-v2-prover` is explicitly enabled.

The reviewed v3 corpus lives separately in `ggbp1-v3-review/vectors/`. Its tests verify four positive vectors, reject historical v2 wire data, and verify that `bp_only_negative.hex` has valid outer signatures but fails the BP+ minimum check. See that directory's test source and `V3_PROTOCOL.md` for the v3 fixture semantics.
