# External review notes — GGBP1R v3

## Scope

This repository presents the reviewed experimental v3 synthetic core first. `historical-v2/` preserves the earlier extraction and corpus as archival evidence only. The default workspace does not build or expose the v2 caller-RNG prover; it is explicit opt-in audit material because it is unsafe for real wallet signing.

The second independent remediation review found no new fundamental v3 protocol weakness, and found the v3 H-1 nonce remediation and M-1 proof-byte binding effective within this crate. That review is not a formal proof, a production security certification, or approval for live chain authorization.

## Questions for an external reviewer

- Does `RistrettoExtendedWitness::new` plus `construct_extended_proof` establish the specified aggregate-minimum statement for the pinned `RistrettoAggregatedPublicStatement`?
- Are generator assumptions/fingerprint, transcript fields, domains, parser bounds, canonical ordering, and the v3 proof-byte binding adequate against substitution and malleability?
- Does the normative hedged-nonce byte layout in `V3_PROTOCOL.md` faithfully match pinned Tari Schnorr behavior, including the KAT and all entropy-failure paths?
- Does the validly re-signed `bp_only_negative.hex` reach `verify_batch` and reject strictly because the BP+ statement is false?
- Are the pinned lockfile versions portable to a real browser environment with sound randomness behavior? The supplied WASM evidence is Node Web Crypto only.
- Can a future wallet implement a single privileged operation that selects genuine outputs, creates `rho`, computes `T3`, and signs only the internally constructed message without exposing raw keys or a generic GGBP signing oracle?

## Explicitly unresolved, and release-blocking for authorization

- Authentic chain inclusion and current-unspent state, maturity, lock/covenant, confirmation, and reorg policy.
- Genuine wallet-owned output authority and Tari-compatible script-key derivation.
- Issued-challenge equality, expiry, atomic replay prevention, and a durable output-use policy.
- Output-identifier linkability and threshold-probing/privacy controls.
- Real browser WASM prover testing and key-boundary integration.

Core verification deliberately has no authorization result type. A valid response alone proves no spendable Tari output ownership and must never create a grant.
