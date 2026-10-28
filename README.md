# GGBP-1 v3 — experimental external cryptographic review package

> **NO PRODUCTION AUTHORIZATION. A valid standalone GGBP1R response does not establish that the claimant holds spendable Tari outputs.**

This repository is a synthetic, standalone Rust package prepared for external cryptographic review. It is not a Tari wallet, transaction builder, chain verifier, chain-state service, or authorization service. It does not access wallet keys, a node, live outputs, or network funds. Live L1 authorization remains blocked.

## Start here

- `ggbp1-v3-review` is the reviewed experimental implementation and the workspace default.
- `ggbp1-v3-wasm-verifier-harness` is verifier-only WASM coverage for Node Web Crypto; it is not a browser certification or a wallet prover.
- `ggbp1-v2-historical` is an **unsafe archive**. Its caller-controlled-RNG prover is absent by default and can be enabled only with `historical-v2-prover` to reproduce the historic audit finding. Never enable or integrate it in wallet signing or authorization code.

The root workspace sets v3 crates as `default-members`. The historical v2 parser/verifier, source, and corpus remain available as evidence only. Ghost Gate, the native Tari wallet checkout, and Web Tari Universe are not part of this repository and were not modified.

## What a valid v3 proof does — and does not — establish

1. **Conditional aggregate-threshold statement.** Given the supplied synthetic records and the implementation's generator assumptions, signatures establish fixture-key knowledge and BP+ verifies the aggregate relation `v in [threshold, threshold + 2^64)`.
2. **Genuine real-chain output ownership.** Not established. The response can contain fabricated identifiers, commitments, scripts, and keys.
3. **Authenticated inclusion and current-unspent state.** Not established. There is no authenticated tip, inclusion proof, current-unspent evidence, maturity/lock/covenant checking, or reorg policy.
4. **Wallet-owned authorization and safe signing.** Not established. Fixture keys are synthetic; no wallet key-manager boundary or authorization operation exists here.
5. **Expiration and replay prevention.** Not established by the core verifier, which is clock-free. A relying service must compare an issued challenge, enforce server time, and persist single use.
6. **Output reuse policy.** Not implemented. `OUTPUT_USE_POLICY.md` is policy guidance only; no output lease/registry is present.
7. **Output identifier linkability.** Not prevented. Output hashes, commitments, scripts, keys, challenge fields, and signatures are public and linkable across uses.

See `CHAIN_BOUNDARY.md`, `AUTHORIZATION_BOUNDARY.md`, and `OUTPUT_USE_POLICY.md`. A missing integration check must be an error, never a grant.

## v3 remediation status

V3 has undergone an independent remediation review. That review found the v3 internal hedged nonce construction and proof-byte binding to address the identified v2 H-1 and M-1 defects in this crate. This is evidence for external review, **not** a formal proof, production security certification, or approval for wallet integration.

- H-1: v3 does not accept caller RNG. It obtains OS randomness internally and hedges it with the signing key, role, and signing message. The construction is normative in `V3_PROTOCOL.md` and pinned by a private test-only known-answer test.
- M-1: v3 signs a domain-separated SHA-256 hash of the BP+ proof bytes. The corpus includes a validly re-signed statement where signatures pass and BP+ itself rejects the changed threshold.
- The current package has no L1 inclusion, unspent-state, wallet authority, replay, or output-use implementation. These are release blockers for any authorization design.

## Provenance and dependencies

`historical-v2/lib.rs` preserves the original Ghost Gate extraction with SHA-256 `70899BCD5D9871073F2C68059C408C5056E42F3329029BA356130BD392F104F2`.

`Cargo.lock` is checked in for reproducible builds. Direct cryptographic pins are `tari_crypto 0.23.4`, `tari_script 6.0.1-pre.2`, `rand 0.10.3`, `sha2 0.10.9`, and `getrandom 0.4.3` (WASM harness). The reviewed lock resolution includes `tari_bulletproofs_plus 0.5.3`, `curve25519-dalek 5.0.0`, and `tari_merlin 4.0.0`. The repository is MIT licensed; upstream Tari dependencies retain their own licenses.

## Build and test

```powershell
cargo test --workspace --locked --offline
cargo build -p ggbp1-v3-wasm-verifier-harness --target wasm32-unknown-unknown --release --locked --offline
```

See `VALIDATION.md` for the recorded results and Node invocation. Node Web Crypto is not equivalent to real browser execution. `V3_PROTOCOL.md` specifies the reviewed format and nonce construction; `REVIEW_NOTES.md` lists scope and unresolved requirements.

## Relationship to Web TU PR #2

This package is a standalone review artifact for the experimental GGBP-1 v3 core. It does not modify, approve, or authorize Web Tari Universe PR #2. Any later Web TU integration must implement wallet-owned signing inside its privileged boundary, reproduce the normative nonce construction, pass a real-browser matrix, and satisfy every chain and authorization prerequisite above.
