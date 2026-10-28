# GGBP1R v3 remediation protocol

## Status and compatibility

GGBP1R v3 uses magic `GGBP1R` followed by version byte `0x03`. It is deliberately incompatible with v2: v2 parsers reject v3 and v3 parsers reject v2. Historical v2 source and fixtures remain in `historical-v2/` for audit evidence only; v2 is unsafe for wallet signing and must never be integrated.

V3 vectors are synthetic fixed corpus files under `ggbp1-v3-review/vectors/`. They are not holdings, chain receipts, wallet proofs, or authorization grants.

## Conditional statement

For canonical synthetic records, v3 verifies authority and subject signatures over the complete record/challenge transcript and a hash of the serialized aggregate proof. It then asks Tari Extended Bulletproofs+ to verify the aggregate relation `v in [threshold, threshold + 2^64)` against the public aggregate commitment.

This is a conditional cryptographic statement only. It does not establish genuine Tari output ownership, authenticated inclusion, current-unspent state, wallet authorization, expiration/replay protection, an output reuse policy, or unlinkability. In particular, **a valid standalone GGBP1R response does not establish that the claimant holds spendable Tari outputs.**

## H-1 remediation: normative v3 hedged Schnorr nonce derivation

This section specifies the construction exactly as implemented by `ggbp1-v3-review::prove_synthetic`. It is prover-internal and cannot be verified from proof wire bytes. Any future wallet-owned prover must reproduce it inside its key boundary and pass the known-answer test before use.

For each authority signature and the one subject signature:

1. **Entropy source and length.** Obtain exactly 32 fresh bytes from `rand::rngs::SysRng::try_fill_bytes`. In this pinned build, `SysRng` is backed by `getrandom`; on native targets this means the OS CSPRNG. The public proving API accepts no RNG, seed, callback, or entropy argument.
2. **Domain separation bytes.** Append the exact 28 ASCII bytes `GGBP1V3/hedged-schnorr-nonce`.
3. **Role encoding.** Append the raw ASCII role bytes with no terminator or length field: authority is the nine bytes `authority`; subject is the seven bytes `subject`. These are closed, internal constants and are never caller supplied.
4. **Secret-key encoding.** Append `RistrettoSecretKey::as_bytes()`: its canonical 32-byte scalar encoding.
5. **Message encoding.** Append the exact already-domain-separated signing message bytes, with no length prefix. Authority message bytes are `GGBP1/output-authority || index_u8 || T3`; subject message bytes are `GGBP1/subject-binding || T3`. `T3` is defined below. The current messages are unambiguous because the role set and all preceding field widths are fixed by the protocol.
6. **Hash and expansion.** Compute `seed = SHA-256(domain || role || secret_key || signing_message || entropy)`, producing 32 bytes. Initialize pinned `rand 0.10.3` `StdRng` with `StdRng::from_seed(seed)`; this is ChaCha12 expansion.
7. **Scalar conversion and reduction.** Pass that `StdRng` directly to Tari `RistrettoSchnorrWithDomain::sign`. In the pinned `tari_crypto 0.23.4`, the nonce scalar is sampled through `RistrettoSecretKey::random`, which reads 64 bytes and performs wide reduction modulo the Ristretto scalar order. No caller-controlled scalar conversion occurs in this package.
8. **Error behavior.** Before BP+ construction, v3 probes `SysRng` with 32 bytes; failure returns `SecureRandomnessUnavailable` before BP+ is entered. Each per-signature entropy failure also returns that error. BP+ internally uses system randomness too; an entropy failure after the preflight can trap/panic inside the upstream BP+ construction, but cannot produce a proof or signature. This remains fail-closed and is not a typed BP+ error path.

The test-only entropy injection seam is private to unit tests. It fixes secret key `21`, role `authority`, message `GGBP1V3 KAT authority message`, and entropy `0xa5` repeated 32 times. The expected seed is `f724062355be618d70203792abb9a20f16ed601c454c3b87821a701b9f57ac46`; the expected Schnorr public nonce is `be5c1a1f87d9548afa979104e7b848423d6149566a2afbc6a012b7f7466e2f69`. This seam is not compiled into release builds and does not restore caller-controlled RNG.

Repeated messages with a repeated role and shared key are safe only to the degree that fresh entropy differs; if entropy is repeated or weak, the derivation degrades to deterministic nonce generation keyed by the secret and message, rather than caller-selected nonce reuse. Different roles and different authority indices/messages produce distinct KDF inputs. Randomness failure is fail-closed. Future wallet implementations must treat cloned VM entropy, unsafe Web Crypto polyfills, and custom `getrandom` backends as deployment risks.

### Browser assumptions

The current WASM artifact is a **verifier-only** harness. It enables `getrandom/wasm_js` and checks Node's Web Crypto availability, but the v3 prover has not been built or tested in a real browser. A browser wallet prover must use a trusted `globalThis.crypto.getRandomValues` path via the pinned backend, fail closed when unavailable, preserve the 32-byte entropy requirement, and pass a real-browser matrix. Node Web Crypto is not evidence of that.

## M-1 remediation: bind BP+ proof bytes

V3 first constructs the aggregate proof `rho`, then computes:

`proof_hash = SHA-256("GGBP1V3/aggregate-minimum-proof" || rho)`

and:

`T3 = "GGBP1V3/proof-binding" || canonical_v3_record_transcript || proof_hash`.

The authority message is `GGBP1/output-authority || index_u8 || T3`; the subject message is `GGBP1/subject-binding || T3`. Any proof-byte transplantation therefore invalidates those signatures unless all fixture authorities re-sign. The `bp_only_negative.hex` corpus deliberately does exactly that with synthetic test keys: all outer signatures and structural fields are valid, but the proof generated for threshold 100 is re-signed under threshold 101 and BP+ rejects it as `InvalidMinimumProof`. Unit instrumentation counts the actual `verify_batch` invocation.

The checked-in vector is reproducible without production proof construction. The private unit-test recipe parses the fixed valid `exact_threshold.hex` base (whose `rho` proves threshold 100), changes only the threshold to 101, reconstructs `T3`, and deterministically re-signs with synthetic authority key `21`, synthetic subject key `31`, and test RNG seed `[45; 32]`. The result must byte-match `bp_only_negative.hex` and then fail only at BP+ verification. This test-only fixture recipe exposes no runtime API and accepts no caller key or RNG.

## Non-goals and integration blockers

V3 does not implement authenticated L1 state, current-unspent checks, real wallet script-key derivation, authorization, output leasing/reuse prevention, expiry enforcement, replay prevention, privacy, or browser wallet proving. `CHAIN_BOUNDARY.md`, `AUTHORIZATION_BOUNDARY.md`, and `OUTPUT_USE_POLICY.md` are normative integration requirements, not implemented capabilities.

The independent remediation review is an external assessment, not a formal proof or production security certification. It should not be used to authorize real-chain activity.
