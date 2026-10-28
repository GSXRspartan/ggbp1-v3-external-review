# Historical GGBP1R v2 archive

This archive was captured before v3 remediation work. `lib.rs` SHA-256 is
`70899BCD5D9871073F2C68059C408C5056E42F3329029BA356130BD392F104F2`.

The archived vectors are byte-for-byte copies of the prior v2 review corpus. They remain historical
compatibility fixtures only; v3 parsers deliberately reject them. No source in this archive is used
by the v3 implementation. V2 is unsafe for real wallet signing because its historical prover
accepts caller-controlled randomness; it must never be integrated.
