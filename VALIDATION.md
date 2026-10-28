# Validation record

This record applies to the checked-in standalone review package after the v3-readiness changes.

## Reproducible native validation

```powershell
cargo test --workspace --locked --offline
```

Expected native count: **27 tests**, all passing:

- historical v2 archive: 5 fixed-vector tests; 0 default unit tests;
- historical v2 WASM harness (host): 1;
- v3 core: 13, including the reproducible BP+-only vector recipe;
- v3 audit regressions: 4;
- v3 vectors: 3, including v2 rejection and the validly re-signed BP+-only negative;
- v3 WASM harness (host): 1.

The deliberately unsafe historical nonce reproduction is separate and requires explicit opt-in:

```powershell
cargo test -p ggbp1-v2-historical --features historical-v2-prover --test vulnerability_reproduction --locked --offline
```

It passes by reproducing the vulnerability: cloned caller RNG state yields the same authority nonce. It is audit evidence, not a successful security property.

## v3 WASM verifier / Node Web Crypto

```powershell
cargo build -p ggbp1-v3-wasm-verifier-harness --target wasm32-unknown-unknown --release --locked --offline
wasm-bindgen --target nodejs --out-dir target/wasm-bindgen-v3-node-current --out-name ggbp1_v3_wasm_review target/wasm32-unknown-unknown/release/ggbp1_v3_wasm_verifier_harness.wasm
node -e "const m=require('./target/wasm-bindgen-v3-node-current/ggbp1_v3_wasm_review.js'); const r={positive:m.ggbp1_v3_verify_fixed_corpus(),negative:m.ggbp1_v3_rejects_negative_corpus(),randomness:m.ggbp1_v3_browser_secure_randomness_probe()}; console.log(JSON.stringify(r)); process.exit(Object.values(r).some(x=>x!==0)?1:0)"
```

Recorded Node result: `{"positive":0,"negative":0,"randomness":0}`.

`negative: 0` includes the re-signed BP+-only invalid vector; it has valid outer signatures and fails as `InvalidMinimumProof`. Native unit instrumentation additionally records exactly one entry into the range-proof verifier for that case. `randomness: 0` checks the `getrandom/wasm_js` Web Crypto backend. This is Node Web Crypto validation only, **not real browser execution**.

## Source identity and package hygiene

- v3 source SHA-256 (`ggbp1-v3-review/src/lib.rs`): `01F4CCAD3885E5984D7AFF68646AA54C2282A84CB86817650903BBDA6BBFEB69`
- `Cargo.lock` is present and direct crypto dependencies are exact-pinned in manifests.
- Secret/local-path scan found no credentials or private key material. The only matches are explanatory text stating that proof responses contain no private keys.
- Build outputs are ignored by `.gitignore` (`/target/`).
