# Mandatory fail-closed chain boundary

## C-1 status: unresolved integration blocker

A GGBP1R v2 or v3 core response is synthetic cryptographic material. It can contain fabricated
output hashes, commitments, scripts and script keys chosen by its prover. Core verification alone
must never be consumed as evidence of holdings, a current balance, ownership of a live output, or
authorization.

The v3 regression suite deliberately proves a fabricated high-value fixture and verifies it at the
core layer. That test records the boundary; it does not resolve it.

Any relying component must fail closed unless each record is checked against authenticated chain
state at an authenticated tip. The minimum required evidence is:

1. a configured network/genesis and authenticated canonical-header/finality policy;
2. locally recomputed output hash from the full output, plus membership/inclusion proof bound to the
   authenticated tip;
3. current-unspent evidence, maturity, lock-height, covenant, output type and range-proof checks;
4. confirmation and reorg policy, including revalidation after a grant; and
5. persistent issued-challenge and output-use state committed with the grant decision.

The current package implements none of this evidence. It provides no simulated trusted adapter and
no public authorization result type. A missing or incomplete chain check must be an error, never a
positive outcome.
