# WASM portability status

## Target and toolchain

- Target: `wasm32-unknown-unknown` (already installed)
- Rust: `rustc 1.97.1 (8bab26f4f 2026-07-14)`
- Cargo: `1.97.1`
- Existing wasm-bindgen CLI: `0.2.108`
- Node runtime used for execution: `v24.14.0`

## Initial blocker and isolated fix

The original review crate failed because `getrandom 0.4.3` does not support
`wasm32-unknown-unknown` by default. Feature inspection showed that it arrives through both
`rand 0.10.3` and the default `tari_bulletproofs_plus 0.5.3` closure.

The core proof manifest and `src/lib.rs` were not changed. A separate
`wasm-verifier-harness` package activates the already locked `getrandom 0.4.3` package with
`features = ["wasm_js"]` and pins `wasm-bindgen 0.2.108`. Cargo added only the matching browser
binding support packages; every pre-existing locked version remained unchanged.

`getrandom`'s `wasm_js` implementation invokes `globalThis.crypto.getRandomValues`. The harness
calls `getrandom::fill` directly for its diagnostic; it neither uses a constant seed nor exposes
proof generation.

## Successful build and runtime check

```powershell
cargo build -p ggbp1-wasm-verifier-harness --target wasm32-unknown-unknown --release --locked
wasm-bindgen --target nodejs --out-dir target/wasm-bindgen-node --out-name ggbp1_wasm_review target/wasm32-unknown-unknown/release/ggbp1_wasm_verifier_harness.wasm
node -e "..."
```

The raw verifier `cdylib` is `426,647` bytes. The wasm-bindgen Node output contains a `575,204`
byte WASM file and a `2,726` byte JavaScript wrapper.

Node reported `globalThis.crypto.getRandomValues` available, and both exported diagnostics returned
zero: the four fixed GGBP1R v2 vectors parsed, verified, and canonically reserialized in WASM; the
`getrandom` Web-Crypto probe succeeded.

This is a Node Web-Crypto execution, not a browser UI integration test. No fresh proof encoding is
compared byte-for-byte, and no browser wallet API was created.

## Remaining WASM limitations

No incompatible Rust crate remains for this verifier build. The core package built by itself still
does not select a browser randomness backend and will retain the original `getrandom` failure; that
is intentional so this review extraction does not silently alter its dependency behavior. A future
browser integration must explicitly make and review the same feature-selection decision.

It also needs its own reviewed API boundary, bundle policy, browser matrix, and actual browser
test. It must not turn this harness into an authorization or wallet-signing interface.

## V3 remediation harness

The separate `ggbp1-v3-wasm-verifier-harness` was built after the v3 wire change with the same
locked `getrandom 0.4.3` `wasm_js` configuration. Its currently measured raw WASM artifact is
`440,311` bytes. The wasm-bindgen WASM artifact is `589,428` bytes; the accompanying JavaScript
wrapper is a Node harness artifact.

Node 24.14 reported Web Crypto available and returned zero from all three v3 diagnostics:

- fixed v3 corpus parses, verifies and reserializes;
- threshold/session tampering, truncated proof bytes, signature swapping, record reordering, and
  a validly re-signed BP+-only threshold negative are rejected; historical v2 wire data is rejected
  by the v3 parser; and
- the `getrandom` secure-randomness probe succeeds.

The randomness probe does **not** mean verification itself needs randomness; it only validates the
browser backend required by the separate v3 proof-construction dependency path. This remains a
Node Web-Crypto test, not a browser wallet or real-browser matrix. These are Node WASM verifier
artifacts, not final Web TU bundle sizes.
