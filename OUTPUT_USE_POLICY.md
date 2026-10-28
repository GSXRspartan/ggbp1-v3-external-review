# Gate-scoped output use and threshold-probing policy

This is a design requirement, not an implemented registry or authorization service.

## Output use

Do not globally ban a holder from making all future balance proofs. Legitimate repeated proofs can
exist for a renewed session or a different relying gate. Instead, each gate configuration needs a
persistent, auditable registry scoped at least by network, genesis, origin, gate ID, configuration
version, subject and output hash.

For a single gate scope, a policy should:

1. permit at most one active/redeeming proof request for an output at a time;
2. make challenge redemption and output-use recording atomic;
3. bind any grant to a short policy-defined TTL and revalidate chain state before every privileged
   action or at a policy-defined cadence;
4. revoke a grant if its recorded output is spent, reorged out, or no longer meets the gate policy;
5. define whether same-subject renewal reuses a prior grant, requires fresh evidence, or permits a
   fresh proof only after the old grant expires.

This reduces replay inside a gate but cannot stop voluntary lending across unrelated gates. A proof
is a point-in-time statement, not a perpetual balance lock.

## Threshold probing and disclosure

Thresholds must come from the gate configuration and server-issued challenge, never from arbitrary
dapp input. A wallet integration should rate-limit requests, return uniform dapp-visible failures,
require foreground approval showing the exact disclosed outputs, and avoid exposing selection or
`InsufficientEligibleValue` details. These controls are not implemented here.
