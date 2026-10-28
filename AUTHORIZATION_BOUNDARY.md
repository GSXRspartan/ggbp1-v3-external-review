# Authorization and expiry boundary

`verify_synthetic` is a public **cryptographic fixture verifier**, not an authorization function.
It serializes and verifies the `expires_at_unix_seconds` field as part of the challenge transcript,
but it deliberately does not compare that field to a clock. The fixed negative review vector proves
that an expired, correctly signed fixture response still verifies at this layer.

There is no public authorization, entitlement, wallet, network, or chain-verification API in this
package. Therefore there is no package authorization API that can bypass expiry; treating a
successful `verify_synthetic` call as a grant would be an integration defect.

Any future authorization layer must, before granting anything:

1. bounded-size parse, then load its persisted issued challenge by nonce; reject unknown nonces;
2. compare every response challenge field byte-for-byte with that stored challenge;
3. reject expiry using authoritative server time, never caller-supplied time, and re-check it at
   final grant commit;
4. atomically transition the challenge to a single-use redeeming state before expensive work;
5. run the cryptographic verifier, then bind every record to authenticated current-unspent chain
   evidence before granting anything;
6. commit output-use state, grant state, and expiry atomically; continue reorg and spend monitoring
   according to a separately reviewed policy.

None of those requirements is implemented by this extracted proof package.
